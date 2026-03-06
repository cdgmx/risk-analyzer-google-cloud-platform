"""
@purpose: Integration smoke test — verifies `python -m gcp_risk_analyzer` exits cleanly
          when GCP_PROJECT_ID is unset, and that the package import path is correct.
@note: Does not make live GCP API calls; tests the CLI entry point and import surface only.
"""
from __future__ import annotations

import subprocess
import sys

import pytest


class TestCliSmoke:
    def test_module_exits_with_code_1_when_project_id_unset(self):
        """
        @purpose: Running the module without GCP_PROJECT_ID must exit with code 1.
        @note: Uses subprocess to isolate the real module execution path.
        """
        result = subprocess.run(
            [sys.executable, "-m", "gcp_risk_analyzer"],
            capture_output=True,
            text=True,
            env={},  # empty env — no GCP_PROJECT_ID
        )
        assert result.returncode == 1

    def test_module_exits_with_code_1_when_project_id_invalid(self):
        """
        @purpose: Running the module with an invalid project ID must exit with code 1.
        @note: 'INVALID_ID' violates GCP naming rules (uppercase letters).
        """
        result = subprocess.run(
            [sys.executable, "-m", "gcp_risk_analyzer"],
            capture_output=True,
            text=True,
            env={"GCP_PROJECT_ID": "INVALID_ID"},
        )
        assert result.returncode == 1

    def test_package_import_succeeds(self):
        """
        @purpose: `from gcp_risk_analyzer.analyzer import GCPRiskAnalyzer` must not raise.
        @note: Verifies the src-layout package is importable after editable install.
        """
        result = subprocess.run(
            [sys.executable, "-c", "from gcp_risk_analyzer.analyzer import GCPRiskAnalyzer; print('ok')"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "ok" in result.stdout

    def test_finding_model_import_succeeds(self):
        """@purpose: Finding and Severity must be importable from the package root."""
        result = subprocess.run(
            [sys.executable, "-c", "from gcp_risk_analyzer import Finding, Severity; print('ok')"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "ok" in result.stdout
