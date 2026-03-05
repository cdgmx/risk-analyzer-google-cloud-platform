"""
@purpose: Core GCP risk analysis orchestration — credential setup, project validation,
          and per-service security checks that populate a typed Finding list.
@note: Report rendering is intentionally kept out of this module; see reporter.py.
"""
from __future__ import annotations

import logging
import os
import re
import sys
from typing import List

import google.auth
import google.auth.exceptions
from google.api_core import exceptions as gcp_exceptions
from google.cloud import notebooks_v1
from google.cloud import resourcemanager_v3
from google.cloud import storage

from gcp_risk_analyzer.models.finding import Finding, Severity

logger = logging.getLogger(__name__)

# GCP project IDs must be 6-30 chars, lowercase letters/digits/hyphens, start with a letter.
_PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9\-]{4,28}[a-z0-9]$")


def _validate_project_id(project_id: str) -> None:
    """
    @purpose: Reject obviously invalid project IDs before any GCP API call is attempted.
    @params: project_id — raw string from caller or environment.
    @raises: ValueError if the project_id is empty or does not match GCP naming rules.
    """
    if not project_id or not project_id.strip():
        raise ValueError("project_id must not be empty.")
    if not _PROJECT_ID_RE.match(project_id):
        raise ValueError(
            f"project_id '{project_id}' does not match GCP naming rules "
            "(6-30 chars, lowercase letters/digits/hyphens, must start with a letter)."
        )


class GCPRiskAnalyzer:
    """
    @purpose: Orchestrates GCP security checks across Vertex AI, Cloud Storage, and IAM.
              Produces a list of typed Finding objects; delegates rendering to reporter.py.
    @params:
        project_id: GCP project ID to audit. Must satisfy GCP naming constraints.
    @example:
        analyzer = GCPRiskAnalyzer("my-gcp-project")
        analyzer.run_all_checks()
        from gcp_risk_analyzer.reporter import generate_report
        generate_report(analyzer.project_id, analyzer.findings)
    """

    def __init__(self, project_id: str) -> None:
        _validate_project_id(project_id)
        self.project_id: str = project_id
        self.findings: List[Finding] = []

        try:
            self.credentials, self.detected_project = google.auth.default()
            logger.info("Authenticated successfully (detected project: %s).", self.detected_project)
        except google.auth.exceptions.DefaultCredentialsError as exc:
            self.credentials = None
            self.findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    check="auth",
                    message=str(exc),
                )
            )
            logger.error("[AUTH ERROR] %s", exc)

    # ------------------------------------------------------------------
    # Individual check methods
    # ------------------------------------------------------------------

    def check_vertex_ai_security(self) -> None:
        """
        @purpose: Audit Vertex AI Notebook instances for public IP and proxy access exposure.
        @note: Appends CRITICAL finding for public IP, HIGH for unrestricted proxy access.
               Appends HIGH finding and logs on PermissionDenied or any other GCP API error.
        """
        logger.info("Running Vertex AI security check for project '%s'.", self.project_id)
        try:
            client = notebooks_v1.NotebookServiceClient(credentials=self.credentials)
            request = notebooks_v1.ListInstancesRequest(
                parent=f"projects/{self.project_id}/locations/-",
            )
            page_result = client.list_instances(request=request)

            for response in page_result:
                if response.no_public_ip is False:
                    self.findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            check="ai-security",
                            message=f"Instance with public IP: {response.name}",
                        )
                    )
                    logger.warning("CRITICAL — public IP on notebook instance: %s", response.name)
                if response.no_proxy_access is False:
                    self.findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            check="ai-security",
                            message=f"Instance with proxy access: {response.name}",
                        )
                    )
                    logger.warning("HIGH — proxy access on notebook instance: %s", response.name)

        except gcp_exceptions.PermissionDenied as exc:
            self.findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check="ai-security",
                    message=f"Notebooks API disabled or permission denied: {exc}",
                )
            )
            logger.error("Vertex AI check failed (PermissionDenied): %s", exc)
        except Exception as exc:  # noqa: BLE001
            self.findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check="ai-security",
                    message=f"Vertex AI check encountered an unexpected error: {exc}",
                )
            )
            logger.exception("Vertex AI check failed with unexpected error.")

    def check_storage_security(self) -> None:
        """
        @purpose: Audit Cloud Storage buckets for public access prevention and missing KMS keys.
        @note: Appends HIGH for inherited public access, MEDIUM for missing KMS key.
               Appends HIGH finding and logs on any GCP API error.
        """
        logger.info("Running Cloud Storage security check for project '%s'.", self.project_id)
        try:
            storage_client = storage.Client(project=self.project_id, credentials=self.credentials)
            buckets_iterator = storage_client.list_buckets()

            for bucket in buckets_iterator:
                if bucket.public_access_prevention == "inherited":
                    self.findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            check="storage-security",
                            message=f"Bucket with public access prevention inherited: {bucket.name}",
                        )
                    )
                    logger.warning("HIGH — public access prevention inherited: %s", bucket.name)
                if bucket.default_kms_key_name is None:
                    self.findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            check="storage-security",
                            message=f"Bucket without default KMS key: {bucket.name}",
                        )
                    )
                    logger.warning("MEDIUM — no KMS key on bucket: %s", bucket.name)

        except gcp_exceptions.PermissionDenied as exc:
            self.findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check="storage-security",
                    message=f"Storage API disabled or permission denied: {exc}",
                )
            )
            logger.error("Storage check failed (PermissionDenied): %s", exc)
        except Exception as exc:  # noqa: BLE001
            self.findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check="storage-security",
                    message=f"Storage check encountered an unexpected error: {exc}",
                )
            )
            logger.exception("Storage check failed with unexpected error.")

    def check_iam_security(self) -> None:
        """
        @purpose: Audit IAM policy bindings for public members and over-privileged roles.
        @note: Appends CRITICAL for allUsers/allAuthenticatedUsers, HIGH for primitive roles,
               CRITICAL for service accounts with owner/editor.
               Appends HIGH finding and logs on any GCP API error.
        """
        logger.info("Running IAM security check for project '%s'.", self.project_id)
        try:
            client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
            policy = client.get_iam_policy(resource=f"projects/{self.project_id}")

            for binding in policy.bindings:
                if "allUsers" in binding.members or "allAuthenticatedUsers" in binding.members:
                    self.findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            check="iam-security",
                            message=f"Public IAM binding on role: {binding.role}",
                        )
                    )
                    logger.warning("CRITICAL — public IAM binding on role: %s", binding.role)

                if binding.role in ("roles/owner", "roles/editor"):
                    self.findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            check="iam-security",
                            message=f"{', '.join(binding.members)} IAM binding on role: {binding.role}",
                        )
                    )
                    logger.warning("HIGH — primitive role binding: %s", binding.role)

                for member in binding.members:
                    if member.startswith("serviceAccount:") and binding.role in (
                        "roles/owner",
                        "roles/editor",
                    ):
                        self.findings.append(
                            Finding(
                                severity=Severity.CRITICAL,
                                check="iam-security",
                                message=f"Service account with owner/editor role: {member}",
                            )
                        )
                        logger.warning("CRITICAL — service account with primitive role: %s", member)

        except gcp_exceptions.PermissionDenied as exc:
            self.findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check="iam-security",
                    message=f"IAM API disabled or permission denied: {exc}",
                )
            )
            logger.error("IAM check failed (PermissionDenied): %s", exc)
        except Exception as exc:  # noqa: BLE001
            self.findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check="iam-security",
                    message=f"IAM check encountered an unexpected error: {exc}",
                )
            )
            logger.exception("IAM check failed with unexpected error.")

    def run_all_checks(self) -> None:
        """
        @purpose: Execute all security checks in order, then delegate to reporter for output.
        @note: Imports reporter inline to avoid circular imports; reporter has no back-reference to analyzer.
        """
        self.check_vertex_ai_security()
        self.check_storage_security()
        self.check_iam_security()

        from gcp_risk_analyzer.reporter import generate_report  # noqa: PLC0415
        generate_report(self.project_id, self.findings)
