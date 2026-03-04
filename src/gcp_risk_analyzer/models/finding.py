"""
@purpose: Typed Finding model for GCP Risk Analyzer.
@note: Replaces loose dicts used in the original auditor; all check paths produce Finding instances.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """
    @purpose: Ordered severity levels for risk findings.
    @note: Inherits from str so instances compare/print as plain strings for backward-compatible output.
    """
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:
        return self.value


@dataclass
class Finding:
    """
    @purpose: Represents a single security finding produced by a GCP check.
    @params:
        severity: Severity level (MEDIUM | HIGH | CRITICAL).
        check: Short identifier for the check that produced this finding (e.g. 'iam-security').
        message: Human-readable description of the specific issue found.
    @example:
        Finding(severity=Severity.CRITICAL, check="iam-security", message="Public IAM binding on role: roles/owner")
    """
    severity: Severity
    check: str
    message: str

    def __post_init__(self) -> None:
        # Coerce plain strings to Severity enum so callers can pass either form.
        if not isinstance(self.severity, Severity):
            self.severity = Severity(self.severity)
