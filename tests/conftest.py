"""
@purpose: Shared pytest fixtures for unit and integration tests.
@note: Fixtures here are available to all test files without explicit import.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import google.auth.exceptions
import pytest

from gcp_risk_analyzer.models.finding import Finding, Severity

# ---------------------------------------------------------------------------
# Project ID fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_project_id() -> str:
    """
    @purpose: Provide a syntactically valid GCP project ID for tests.
    @returns: A string that satisfies GCP naming rules.
    """
    return "test-project-01"


@pytest.fixture
def mock_credentials():
    """
    @purpose: Patch google.auth.default to return dummy credentials and project.
    @note: Yields (credentials_mock, project_string) so tests can inspect the mock if needed.
    """
    mock_creds = MagicMock()
    with patch("google.auth.default", return_value=(mock_creds, "test-project-01")) as patched:
        yield patched, mock_creds


# ---------------------------------------------------------------------------
# Pre-built Finding fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def critical_iam_finding() -> Finding:
    """@purpose: A CRITICAL IAM finding for use in reporter/model tests."""
    return Finding(severity=Severity.CRITICAL, check="iam-security", message="Public IAM binding on role: roles/owner")


@pytest.fixture
def high_storage_finding() -> Finding:
    """@purpose: A HIGH storage finding for use in reporter/model tests."""
    return Finding(severity=Severity.HIGH, check="storage-security", message="Bucket with public access prevention inherited: my-bucket")


@pytest.fixture
def medium_storage_finding() -> Finding:
    """@purpose: A MEDIUM storage finding for use in reporter/model tests."""
    return Finding(severity=Severity.MEDIUM, check="storage-security", message="Bucket without default KMS key: my-bucket")
