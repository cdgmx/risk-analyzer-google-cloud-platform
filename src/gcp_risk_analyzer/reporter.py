"""
@purpose: Report rendering for GCP Risk Analyzer findings.
@note: Intentionally stateless — accepts project_id and findings list, prints to stdout.
       Severity counting uses collections.Counter; formatting bug from original (line 110) is fixed.
"""
from __future__ import annotations

import logging
from collections import Counter
from typing import List

from gcp_risk_analyzer.models.finding import Finding, Severity

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]


def generate_report(project_id: str, findings: List[Finding]) -> None:
    """
    @purpose: Print a formatted risk report to stdout, grouped by severity, with a summary footer.
    @params:
        project_id: GCP project ID that was audited (used in the report header).
        findings: List of Finding objects produced by GCPRiskAnalyzer checks.
    @note: Empty findings list produces a clean 'No findings' report rather than an empty block.
    @example:
        generate_report("my-project", analyzer.findings)
    """
    separator = "=" * 50

    print(f"\n{separator}")
    print(f"Google Cloud Platform Risk Analysis Report - Project: {project_id}")
    print(separator)

    if not findings:
        print("\nNo findings — project passed all checks.")
        print(f"\n{separator}")
        logger.info("Report complete: 0 findings for project '%s'.", project_id)
        return

    # Print each finding in the order they were collected.
    for finding in findings:
        print(f"\n{finding.severity}: {finding.check} - {finding.message}")

    # Count by severity using Counter for clarity.
    counts: Counter[Severity] = Counter(f.severity for f in findings)
    total = sum(counts.values())

    print(f"\n{separator}")
    print(f"Total findings: {total}")
    for severity in _SEVERITY_ORDER:
        count = counts.get(severity, 0)
        if count:
            print(f"  {count} {severity}")
    print(separator)

    logger.info(
        "Report complete: %d findings (%s) for project '%s'.",
        total,
        ", ".join(f"{counts.get(s, 0)} {s}" for s in _SEVERITY_ORDER if counts.get(s, 0)),
        project_id,
    )
