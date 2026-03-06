"""
@purpose: Unit tests for the generate_report() function in reporter.py.
@note: Validates stdout output, severity counting, and empty-findings handling.
"""
from __future__ import annotations

from gcp_risk_analyzer.models.finding import Finding, Severity
from gcp_risk_analyzer.reporter import generate_report


class TestGenerateReport:
    def test_report_header_contains_project_id(self, capsys):
        """@purpose: Report header must include the project ID."""
        generate_report("my-project-01", [])
        captured = capsys.readouterr()
        assert "my-project-01" in captured.out

    def test_empty_findings_prints_no_findings_message(self, capsys):
        """@purpose: Empty findings list must print a clean 'No findings' message."""
        generate_report("my-project-01", [])
        captured = capsys.readouterr()
        assert "No findings" in captured.out

    def test_finding_severity_and_check_appear_in_output(self, capsys):
        """@purpose: Each finding's severity and check identifier must appear in the report."""
        findings = [
            Finding(severity=Severity.CRITICAL, check="iam-security", message="Public binding"),
        ]
        generate_report("my-project-01", findings)
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out
        assert "iam-security" in captured.out
        assert "Public binding" in captured.out

    def test_summary_counts_are_correct(self, capsys):
        """@purpose: Summary footer must show correct counts per severity level."""
        findings = [
            Finding(severity=Severity.CRITICAL, check="iam-security", message="Critical finding"),
            Finding(severity=Severity.HIGH, check="storage-security", message="High finding"),
            Finding(severity=Severity.HIGH, check="ai-security", message="Another high"),
            Finding(severity=Severity.MEDIUM, check="storage-security", message="Medium finding"),
        ]
        generate_report("my-project-01", findings)
        captured = capsys.readouterr()
        assert "Total findings: 4" in captured.out
        assert "1 CRITICAL" in captured.out
        assert "2 HIGH" in captured.out
        assert "1 MEDIUM" in captured.out

    def test_only_present_severities_appear_in_summary(self, capsys):
        """@purpose: Severity levels with zero findings must not appear in the summary footer."""
        findings = [
            Finding(severity=Severity.HIGH, check="ai-security", message="High only"),
        ]
        generate_report("my-project-01", findings)
        captured = capsys.readouterr()
        assert "HIGH" in captured.out
        assert "MEDIUM" not in captured.out
        assert "CRITICAL" not in captured.out

    def test_total_findings_count_in_summary(self, capsys):
        """@purpose: Total count in summary must match the number of findings passed in."""
        findings = [
            Finding(severity=Severity.CRITICAL, check="iam-security", message="c1"),
            Finding(severity=Severity.CRITICAL, check="iam-security", message="c2"),
            Finding(severity=Severity.MEDIUM, check="storage-security", message="m1"),
        ]
        generate_report("proj-abc-01", findings)
        captured = capsys.readouterr()
        assert "Total findings: 3" in captured.out
