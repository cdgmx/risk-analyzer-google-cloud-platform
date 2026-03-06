"""
@purpose: Unit tests for GCPRiskAnalyzer — credential setup, project validation,
          and per-service check methods.
@note: All GCP API calls are mocked; no live credentials required.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import google.auth.exceptions
import pytest
from google.api_core import exceptions as gcp_exceptions

from gcp_risk_analyzer.analyzer import GCPRiskAnalyzer
from gcp_risk_analyzer.models.finding import Finding, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_analyzer(project_id: str = "test-project-01") -> GCPRiskAnalyzer:
    """
    @purpose: Construct a GCPRiskAnalyzer with mocked google.auth.default credentials.
    @returns: Analyzer instance ready for check method calls.
    """
    with patch("google.auth.default", return_value=(MagicMock(), "test-project-01")):
        return GCPRiskAnalyzer(project_id)


# ---------------------------------------------------------------------------
# project_id validation
# ---------------------------------------------------------------------------

class TestProjectIdValidation:
    def test_empty_project_id_raises(self):
        """@purpose: Empty string must be rejected before any API call."""
        with pytest.raises(ValueError, match="must not be empty"):
            GCPRiskAnalyzer("")

    def test_whitespace_project_id_raises(self):
        """@purpose: Whitespace-only project ID must be rejected."""
        with pytest.raises(ValueError, match="must not be empty"):
            GCPRiskAnalyzer("   ")

    def test_invalid_format_raises(self):
        """@purpose: Project IDs that violate GCP naming rules must be rejected."""
        with pytest.raises(ValueError, match="does not match GCP naming rules"):
            GCPRiskAnalyzer("UPPERCASE-ID")

    def test_valid_project_id_accepted(self):
        """@purpose: A well-formed project ID must not raise."""
        analyzer = _make_analyzer("test-project-01")
        assert analyzer.project_id == "test-project-01"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class TestAuth:
    def test_auth_failure_adds_critical_finding(self):
        """@purpose: DefaultCredentialsError must produce a CRITICAL auth finding."""
        with patch("google.auth.default", side_effect=google.auth.exceptions.DefaultCredentialsError("no creds")):
            analyzer = GCPRiskAnalyzer("test-project-01")

        assert analyzer.credentials is None
        assert any(f.check == "auth" and f.severity is Severity.CRITICAL for f in analyzer.findings)

    def test_auth_success_sets_credentials(self):
        """@purpose: Successful auth must store credentials and leave findings empty."""
        mock_creds = MagicMock()
        with patch("google.auth.default", return_value=(mock_creds, "test-project-01")):
            analyzer = GCPRiskAnalyzer("test-project-01")

        assert analyzer.credentials is mock_creds
        assert not any(f.check == "auth" for f in analyzer.findings)


# ---------------------------------------------------------------------------
# Vertex AI checks
# ---------------------------------------------------------------------------

class TestCheckVertexAiSecurity:
    def test_public_ip_instance_adds_critical_finding(self):
        """@purpose: Notebook with public IP must produce a CRITICAL ai-security finding."""
        mock_instance = MagicMock()
        mock_instance.name = "projects/p/locations/us/instances/risky-nb"
        mock_instance.no_public_ip = False
        mock_instance.no_proxy_access = True

        analyzer = _make_analyzer()
        with patch("google.cloud.notebooks_v1.NotebookServiceClient") as mock_client:
            mock_client.return_value.list_instances.return_value = [mock_instance]
            analyzer.check_vertex_ai_security()

        critical = [f for f in analyzer.findings if f.severity is Severity.CRITICAL and f.check == "ai-security"]
        assert len(critical) == 1
        assert "public IP" in critical[0].message

    def test_proxy_access_instance_adds_high_finding(self):
        """@purpose: Notebook with proxy access must produce a HIGH ai-security finding."""
        mock_instance = MagicMock()
        mock_instance.name = "projects/p/locations/us/instances/proxy-nb"
        mock_instance.no_public_ip = True
        mock_instance.no_proxy_access = False

        analyzer = _make_analyzer()
        with patch("google.cloud.notebooks_v1.NotebookServiceClient") as mock_client:
            mock_client.return_value.list_instances.return_value = [mock_instance]
            analyzer.check_vertex_ai_security()

        high = [f for f in analyzer.findings if f.severity is Severity.HIGH and f.check == "ai-security"]
        assert len(high) == 1
        assert "proxy access" in high[0].message

    def test_permission_denied_adds_high_finding(self):
        """@purpose: PermissionDenied from Notebooks API must produce a HIGH ai-security finding."""
        analyzer = _make_analyzer()
        with patch("google.cloud.notebooks_v1.NotebookServiceClient") as mock_client:
            mock_client.return_value.list_instances.side_effect = gcp_exceptions.PermissionDenied("denied")
            analyzer.check_vertex_ai_security()

        high = [f for f in analyzer.findings if f.severity is Severity.HIGH and f.check == "ai-security"]
        assert len(high) == 1
        assert "permission denied" in high[0].message.lower()

    def test_unexpected_error_adds_high_finding(self):
        """@purpose: Any unexpected exception must produce a HIGH ai-security finding, not crash."""
        analyzer = _make_analyzer()
        with patch("google.cloud.notebooks_v1.NotebookServiceClient") as mock_client:
            mock_client.return_value.list_instances.side_effect = RuntimeError("boom")
            analyzer.check_vertex_ai_security()

        high = [f for f in analyzer.findings if f.severity is Severity.HIGH and f.check == "ai-security"]
        assert len(high) == 1

    def test_no_instances_produces_no_findings(self):
        """@purpose: Empty instance list must produce zero ai-security findings."""
        analyzer = _make_analyzer()
        with patch("google.cloud.notebooks_v1.NotebookServiceClient") as mock_client:
            mock_client.return_value.list_instances.return_value = []
            analyzer.check_vertex_ai_security()

        assert not any(f.check == "ai-security" for f in analyzer.findings)


# ---------------------------------------------------------------------------
# Storage checks
# ---------------------------------------------------------------------------

class TestCheckStorageSecurity:
    def test_public_access_prevention_inherited_adds_high_finding(self):
        """@purpose: Bucket with inherited public access prevention must produce HIGH finding."""
        mock_bucket = MagicMock()
        mock_bucket.name = "risky-bucket"
        mock_bucket.public_access_prevention = "inherited"
        mock_bucket.default_kms_key_name = "projects/p/locations/global/keyRings/r/cryptoKeys/k"

        analyzer = _make_analyzer()
        with patch("google.cloud.storage.Client") as mock_client:
            mock_client.return_value.list_buckets.return_value = [mock_bucket]
            analyzer.check_storage_security()

        high = [f for f in analyzer.findings if f.severity is Severity.HIGH and f.check == "storage-security"]
        assert len(high) == 1
        assert "risky-bucket" in high[0].message

    def test_missing_kms_key_adds_medium_finding(self):
        """@purpose: Bucket without KMS key must produce MEDIUM finding."""
        mock_bucket = MagicMock()
        mock_bucket.name = "no-kms-bucket"
        mock_bucket.public_access_prevention = "enforced"
        mock_bucket.default_kms_key_name = None

        analyzer = _make_analyzer()
        with patch("google.cloud.storage.Client") as mock_client:
            mock_client.return_value.list_buckets.return_value = [mock_bucket]
            analyzer.check_storage_security()

        medium = [f for f in analyzer.findings if f.severity is Severity.MEDIUM and f.check == "storage-security"]
        assert len(medium) == 1
        assert "no-kms-bucket" in medium[0].message

    def test_permission_denied_adds_high_finding(self):
        """@purpose: PermissionDenied from Storage API must produce HIGH storage-security finding."""
        analyzer = _make_analyzer()
        with patch("google.cloud.storage.Client") as mock_client:
            mock_client.return_value.list_buckets.side_effect = gcp_exceptions.PermissionDenied("denied")
            analyzer.check_storage_security()

        high = [f for f in analyzer.findings if f.severity is Severity.HIGH and f.check == "storage-security"]
        assert len(high) == 1

    def test_unexpected_error_adds_high_finding(self):
        """@purpose: Any unexpected exception must produce HIGH finding, not crash."""
        analyzer = _make_analyzer()
        with patch("google.cloud.storage.Client") as mock_client:
            mock_client.return_value.list_buckets.side_effect = RuntimeError("boom")
            analyzer.check_storage_security()

        high = [f for f in analyzer.findings if f.severity is Severity.HIGH and f.check == "storage-security"]
        assert len(high) == 1

    def test_no_buckets_produces_no_findings(self):
        """@purpose: Empty bucket list must produce zero storage-security findings."""
        analyzer = _make_analyzer()
        with patch("google.cloud.storage.Client") as mock_client:
            mock_client.return_value.list_buckets.return_value = []
            analyzer.check_storage_security()

        assert not any(f.check == "storage-security" for f in analyzer.findings)


# ---------------------------------------------------------------------------
# IAM checks
# ---------------------------------------------------------------------------

class TestCheckIamSecurity:
    def test_all_users_binding_adds_critical_finding(self):
        """@purpose: allUsers member must produce CRITICAL iam-security finding."""
        mock_policy = MagicMock()
        mock_policy.bindings = [
            MagicMock(role="roles/viewer", members=["allUsers"]),
        ]

        analyzer = _make_analyzer()
        with patch("google.cloud.resourcemanager_v3.ProjectsClient") as mock_client:
            mock_client.return_value.get_iam_policy.return_value = mock_policy
            analyzer.check_iam_security()

        critical = [f for f in analyzer.findings if f.severity is Severity.CRITICAL and f.check == "iam-security"]
        assert len(critical) == 1
        assert "Public IAM binding" in critical[0].message

    def test_primitive_role_adds_high_finding(self):
        """@purpose: roles/owner binding must produce HIGH iam-security finding."""
        mock_policy = MagicMock()
        mock_policy.bindings = [
            MagicMock(role="roles/owner", members=["user:admin@example.com"]),
        ]

        analyzer = _make_analyzer()
        with patch("google.cloud.resourcemanager_v3.ProjectsClient") as mock_client:
            mock_client.return_value.get_iam_policy.return_value = mock_policy
            analyzer.check_iam_security()

        high = [f for f in analyzer.findings if f.severity is Severity.HIGH and f.check == "iam-security"]
        assert len(high) == 1

    def test_service_account_with_owner_adds_critical_finding(self):
        """@purpose: Service account with roles/owner must produce CRITICAL iam-security finding."""
        mock_policy = MagicMock()
        mock_policy.bindings = [
            MagicMock(role="roles/owner", members=["serviceAccount:sa@project.iam.gserviceaccount.com"]),
        ]

        analyzer = _make_analyzer()
        with patch("google.cloud.resourcemanager_v3.ProjectsClient") as mock_client:
            mock_client.return_value.get_iam_policy.return_value = mock_policy
            analyzer.check_iam_security()

        critical = [f for f in analyzer.findings if f.severity is Severity.CRITICAL and f.check == "iam-security"]
        assert any("service account" in f.message.lower() for f in critical)

    def test_permission_denied_adds_high_finding(self):
        """@purpose: PermissionDenied from IAM API must produce HIGH iam-security finding."""
        analyzer = _make_analyzer()
        with patch("google.cloud.resourcemanager_v3.ProjectsClient") as mock_client:
            mock_client.return_value.get_iam_policy.side_effect = gcp_exceptions.PermissionDenied("denied")
            analyzer.check_iam_security()

        high = [f for f in analyzer.findings if f.severity is Severity.HIGH and f.check == "iam-security"]
        assert len(high) == 1

    def test_unexpected_error_adds_high_finding(self):
        """@purpose: Any unexpected exception must produce HIGH finding, not crash."""
        analyzer = _make_analyzer()
        with patch("google.cloud.resourcemanager_v3.ProjectsClient") as mock_client:
            mock_client.return_value.get_iam_policy.side_effect = RuntimeError("boom")
            analyzer.check_iam_security()

        high = [f for f in analyzer.findings if f.severity is Severity.HIGH and f.check == "iam-security"]
        assert len(high) == 1

    def test_no_bindings_produces_no_findings(self):
        """@purpose: Empty bindings list must produce zero iam-security findings."""
        mock_policy = MagicMock()
        mock_policy.bindings = []

        analyzer = _make_analyzer()
        with patch("google.cloud.resourcemanager_v3.ProjectsClient") as mock_client:
            mock_client.return_value.get_iam_policy.return_value = mock_policy
            analyzer.check_iam_security()

        assert not any(f.check == "iam-security" for f in analyzer.findings)


# ---------------------------------------------------------------------------
# run_all_checks orchestration
# ---------------------------------------------------------------------------

class TestRunAllChecks:
    def test_run_all_checks_calls_each_method_once(self):
        """
        @purpose: run_all_checks() must invoke all three check methods and the reporter exactly once.
        @note: Mocks the four delegates so no real GCP calls are made.
        @note: Reporter is asserted with exact args — project_id and the findings list — to lock
               down the orchestration contract between analyzer and reporter.
        """
        analyzer = _make_analyzer()
        analyzer.check_vertex_ai_security = MagicMock()
        analyzer.check_storage_security = MagicMock()
        analyzer.check_iam_security = MagicMock()

        with patch("gcp_risk_analyzer.reporter.generate_report") as mock_report:
            analyzer.run_all_checks()

        analyzer.check_vertex_ai_security.assert_called_once()
        analyzer.check_storage_security.assert_called_once()
        analyzer.check_iam_security.assert_called_once()
        mock_report.assert_called_once_with(analyzer.project_id, analyzer.findings)
