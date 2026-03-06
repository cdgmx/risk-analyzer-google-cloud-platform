"""
@purpose: Unit tests for the Finding dataclass and Severity enum.
@note: No GCP API calls; pure model validation.
"""
from __future__ import annotations

import pytest

from gcp_risk_analyzer.models.finding import Finding, Severity


class TestSeverity:
    def test_severity_values_are_strings(self):
        """@purpose: Severity enum values must be plain strings for backward-compatible output."""
        assert str(Severity.CRITICAL) == "CRITICAL"
        assert str(Severity.HIGH) == "HIGH"
        assert str(Severity.MEDIUM) == "MEDIUM"

    def test_severity_enum_members(self):
        """@purpose: All three severity levels must exist."""
        assert Severity("CRITICAL") is Severity.CRITICAL
        assert Severity("HIGH") is Severity.HIGH
        assert Severity("MEDIUM") is Severity.MEDIUM

    def test_invalid_severity_raises(self):
        """@purpose: Unknown severity strings must raise ValueError."""
        with pytest.raises(ValueError):
            Severity("LOW")


class TestFinding:
    def test_finding_stores_fields(self):
        """@purpose: Finding must expose severity, check, and message attributes."""
        f = Finding(severity=Severity.HIGH, check="storage-security", message="Bucket exposed")
        assert f.severity is Severity.HIGH
        assert f.check == "storage-security"
        assert f.message == "Bucket exposed"

    def test_finding_coerces_string_severity(self):
        """@purpose: Passing a plain string severity must be coerced to the Severity enum."""
        f = Finding(severity="CRITICAL", check="iam-security", message="Public binding")  # type: ignore[arg-type]
        assert f.severity is Severity.CRITICAL

    def test_finding_invalid_severity_raises(self):
        """@purpose: An unrecognised severity string must raise ValueError during coercion."""
        with pytest.raises(ValueError):
            Finding(severity="UNKNOWN", check="test", message="bad")  # type: ignore[arg-type]

    def test_finding_equality(self):
        """@purpose: Two Findings with identical fields must be equal (dataclass default)."""
        f1 = Finding(severity=Severity.MEDIUM, check="storage-security", message="No KMS key: bucket-a")
        f2 = Finding(severity=Severity.MEDIUM, check="storage-security", message="No KMS key: bucket-a")
        assert f1 == f2

    def test_finding_inequality_on_message(self):
        """@purpose: Findings differing only in message must not be equal."""
        f1 = Finding(severity=Severity.HIGH, check="ai-security", message="Instance A")
        f2 = Finding(severity=Severity.HIGH, check="ai-security", message="Instance B")
        assert f1 != f2
