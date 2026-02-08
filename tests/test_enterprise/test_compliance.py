"""Tests for ComplianceReporter: OWASP mapping, SOC2 mapping, report generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from devnog.core.models import Category, Finding, ScanReport, Severity
from devnog.enterprise.compliance import (
    OWASP_MAPPING,
    SOC2_MAPPING,
    ComplianceReporter,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    check_id: str,
    category: Category = Category.SECURITY,
    severity: Severity = Severity.WARNING,
    message: str = "test issue",
    file: str = "app.py",
    line: int = 1,
) -> Finding:
    return Finding(
        check_id=check_id,
        category=category,
        severity=severity,
        message=message,
        file=Path(file),
        line=line,
    )


def _report(
    score: int = 80,
    findings: list[Finding] | None = None,
) -> ScanReport:
    return ScanReport(
        overall_score=score,
        findings=findings or [],
    )


# ---------------------------------------------------------------------------
# _get_mapping()
# ---------------------------------------------------------------------------

class TestComplianceReporterGetMapping:
    """Tests for ComplianceReporter._get_mapping()."""

    def test_owasp_mapping(self, tmp_path: Path):
        """'owasp' framework should return OWASP_MAPPING."""
        reporter = ComplianceReporter(tmp_path)
        mapping = reporter._get_mapping("owasp")
        assert mapping is OWASP_MAPPING
        assert "A01:Broken Access Control" in mapping

    def test_soc2_mapping(self, tmp_path: Path):
        """'soc2' framework should return SOC2_MAPPING."""
        reporter = ComplianceReporter(tmp_path)
        mapping = reporter._get_mapping("soc2")
        assert mapping is SOC2_MAPPING
        assert "CC6.1 - Logical Access" in mapping

    def test_unknown_framework_returns_empty(self, tmp_path: Path):
        """Unknown framework should return an empty dict."""
        reporter = ComplianceReporter(tmp_path)
        mapping = reporter._get_mapping("iso27001")
        assert mapping == {}


# ---------------------------------------------------------------------------
# _map_findings() — OWASP
# ---------------------------------------------------------------------------

class TestComplianceReporterMapFindingsOWASP:
    """Tests for _map_findings() with OWASP framework."""

    def test_all_pass_no_findings(self, tmp_path: Path):
        """No findings should produce PASS for all OWASP controls."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=100, findings=[])

        result = reporter._map_findings("owasp", report)

        assert len(result) == len(OWASP_MAPPING)
        for control, data in result.items():
            assert data["status"] == "PASS", f"{control} should be PASS"
            assert data["matched_ids"] == []
            assert data["findings"] == []

    def test_finding_maps_to_correct_control(self, tmp_path: Path):
        """SEC-001 should map to A02:Cryptographic Failures."""
        reporter = ComplianceReporter(tmp_path)
        f = _finding(check_id="SEC-001", severity=Severity.WARNING)
        report = _report(findings=[f])

        result = reporter._map_findings("owasp", report)

        a02 = result["A02:Cryptographic Failures"]
        assert a02["status"] in ("FAIL", "WARNING")
        assert "SEC-001" in a02["matched_ids"]

    def test_critical_finding_produces_fail(self, tmp_path: Path):
        """A CRITICAL finding should set the control status to FAIL."""
        reporter = ComplianceReporter(tmp_path)
        f = _finding(check_id="SEC-002", severity=Severity.CRITICAL)
        report = _report(findings=[f])

        result = reporter._map_findings("owasp", report)

        a03 = result["A03:Injection"]
        assert a03["status"] == "FAIL"

    def test_warning_finding_produces_warning_status(self, tmp_path: Path):
        """A WARNING finding (no criticals) should set status to WARNING."""
        reporter = ComplianceReporter(tmp_path)
        f = _finding(check_id="SEC-002", severity=Severity.WARNING)
        report = _report(findings=[f])

        result = reporter._map_findings("owasp", report)

        a03 = result["A03:Injection"]
        assert a03["status"] == "WARNING"

    def test_unrelated_finding_does_not_affect_control(self, tmp_path: Path):
        """A finding not in any OWASP mapping should not affect control statuses."""
        reporter = ComplianceReporter(tmp_path)
        f = _finding(check_id="CUSTOM-999", severity=Severity.CRITICAL)
        report = _report(findings=[f])

        result = reporter._map_findings("owasp", report)

        for control, data in result.items():
            assert data["status"] == "PASS", f"{control} should still be PASS"

    def test_multiple_findings_in_same_control(self, tmp_path: Path):
        """Multiple findings in the same control should all be reported."""
        reporter = ComplianceReporter(tmp_path)
        f1 = _finding(check_id="SEC-002", severity=Severity.WARNING, message="injection risk A")
        f2 = _finding(check_id="SEC-004", severity=Severity.WARNING, message="injection risk B")
        report = _report(findings=[f1, f2])

        result = reporter._map_findings("owasp", report)

        a03 = result["A03:Injection"]
        assert "SEC-002" in a03["matched_ids"]
        assert "SEC-004" in a03["matched_ids"]
        assert len(a03["findings"]) == 2

    def test_finding_maps_to_multiple_controls(self, tmp_path: Path):
        """SEC-010 appears in both A03:Injection and A10:SSRF."""
        reporter = ComplianceReporter(tmp_path)
        f = _finding(check_id="SEC-010", severity=Severity.WARNING)
        report = _report(findings=[f])

        result = reporter._map_findings("owasp", report)

        assert "SEC-010" in result["A03:Injection"]["matched_ids"]
        assert "SEC-010" in result["A10:SSRF"]["matched_ids"]


# ---------------------------------------------------------------------------
# _map_findings() — SOC2
# ---------------------------------------------------------------------------

class TestComplianceReporterMapFindingsSOC2:
    """Tests for _map_findings() with SOC2 framework."""

    def test_all_pass_no_findings(self, tmp_path: Path):
        """No findings should produce PASS for all SOC2 controls."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=100, findings=[])

        result = reporter._map_findings("soc2", report)

        assert len(result) == len(SOC2_MAPPING)
        for control, data in result.items():
            assert data["status"] == "PASS"

    def test_soc2_logical_access_fail(self, tmp_path: Path):
        """SEC-001 in SOC2 should affect CC6.1 - Logical Access."""
        reporter = ComplianceReporter(tmp_path)
        f = _finding(check_id="SEC-001", severity=Severity.CRITICAL)
        report = _report(findings=[f])

        result = reporter._map_findings("soc2", report)

        cc61 = result["CC6.1 - Logical Access"]
        assert cc61["status"] == "FAIL"
        assert "SEC-001" in cc61["matched_ids"]

    def test_soc2_change_management(self, tmp_path: Path):
        """DEP-001 should affect CC8.1 - Change Management."""
        reporter = ComplianceReporter(tmp_path)
        f = _finding(check_id="DEP-001", severity=Severity.WARNING, category=Category.DEPENDENCIES)
        report = _report(findings=[f])

        result = reporter._map_findings("soc2", report)

        cc81 = result["CC8.1 - Change Management"]
        assert cc81["status"] == "WARNING"
        assert "DEP-001" in cc81["matched_ids"]


# ---------------------------------------------------------------------------
# generate_json()
# ---------------------------------------------------------------------------

class TestComplianceReporterGenerateJSON:
    """Tests for ComplianceReporter.generate_json()."""

    def test_generates_json_file(self, tmp_path: Path):
        """generate_json() should create a JSON file and return its path."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=85, findings=[])

        out_path = reporter.generate_json("owasp", report)

        assert out_path.exists()
        assert out_path.suffix == ".json"
        assert "compliance-owasp" in out_path.name

    def test_json_structure(self, tmp_path: Path):
        """JSON output should have expected top-level keys."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=85, findings=[])

        out_path = reporter.generate_json("owasp", report)
        data = json.loads(out_path.read_text())

        assert data["framework"] == "owasp"
        assert data["overall_score"] == 85
        assert "controls" in data
        assert "generated_at" in data
        assert "project" in data

    def test_json_controls_all_present(self, tmp_path: Path):
        """All OWASP controls should appear in the JSON output."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=100, findings=[])

        out_path = reporter.generate_json("owasp", report)
        data = json.loads(out_path.read_text())

        for control in OWASP_MAPPING:
            assert control in data["controls"]

    def test_json_includes_issues(self, tmp_path: Path):
        """Findings should be serialized in the JSON control entries."""
        reporter = ComplianceReporter(tmp_path)
        f = _finding(
            check_id="SEC-002",
            severity=Severity.CRITICAL,
            message="SQL injection detected",
            file="db.py",
            line=42,
        )
        report = _report(score=60, findings=[f])

        out_path = reporter.generate_json("owasp", report)
        data = json.loads(out_path.read_text())

        a03 = data["controls"]["A03:Injection"]
        assert a03["status"] == "FAIL"
        assert len(a03["issues"]) >= 1
        issue = a03["issues"][0]
        assert issue["check_id"] == "SEC-002"
        assert issue["severity"] == "critical"
        assert issue["message"] == "SQL injection detected"

    def test_json_soc2_framework(self, tmp_path: Path):
        """generate_json() should work for SOC2 framework as well."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=90, findings=[])

        out_path = reporter.generate_json("soc2", report)
        data = json.loads(out_path.read_text())

        assert data["framework"] == "soc2"
        for control in SOC2_MAPPING:
            assert control in data["controls"]

    def test_json_passing_controls_have_no_issues(self, tmp_path: Path):
        """PASS controls should have an empty issues list."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=100, findings=[])

        out_path = reporter.generate_json("owasp", report)
        data = json.loads(out_path.read_text())

        for control, cdata in data["controls"].items():
            assert cdata["status"] == "PASS"
            assert cdata["issues"] == []

    def test_json_file_in_reports_dir(self, tmp_path: Path):
        """JSON file should be created inside .devnog/reports/."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=85, findings=[])

        out_path = reporter.generate_json("owasp", report)

        assert out_path.parent == tmp_path / ".devnog" / "reports"


# ---------------------------------------------------------------------------
# generate_html()
# ---------------------------------------------------------------------------

class TestComplianceReporterGenerateHTML:
    """Tests for ComplianceReporter.generate_html()."""

    def test_generates_html_file(self, tmp_path: Path):
        """generate_html() should create an HTML file and return its path."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=85, findings=[])

        out_path = reporter.generate_html("owasp", report)

        assert out_path.exists()
        assert out_path.suffix == ".html"
        assert "compliance-owasp" in out_path.name

    def test_html_contains_framework_name(self, tmp_path: Path):
        """HTML output should contain the framework name (OWASP)."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=85, findings=[])

        out_path = reporter.generate_html("owasp", report)
        html = out_path.read_text()

        assert "OWASP" in html

    def test_html_contains_score(self, tmp_path: Path):
        """HTML output should contain the overall score."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=77, findings=[])

        out_path = reporter.generate_html("owasp", report)
        html = out_path.read_text()

        assert "77/100" in html

    def test_html_contains_control_names(self, tmp_path: Path):
        """HTML should contain all OWASP control names."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=85, findings=[])

        out_path = reporter.generate_html("owasp", report)
        html = out_path.read_text()

        for control in OWASP_MAPPING:
            assert control in html

    def test_html_shows_pass_status(self, tmp_path: Path):
        """Controls with no issues should show PASS in the HTML."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=100, findings=[])

        out_path = reporter.generate_html("owasp", report)
        html = out_path.read_text()

        assert "PASS" in html

    def test_html_shows_fail_status(self, tmp_path: Path):
        """Controls with critical findings should show FAIL in the HTML."""
        reporter = ComplianceReporter(tmp_path)
        f = _finding(check_id="SEC-002", severity=Severity.CRITICAL)
        report = _report(score=50, findings=[f])

        out_path = reporter.generate_html("owasp", report)
        html = out_path.read_text()

        assert "FAIL" in html

    def test_html_shows_matched_issue_ids(self, tmp_path: Path):
        """HTML should display matched check IDs for failing controls."""
        reporter = ComplianceReporter(tmp_path)
        f = _finding(check_id="SEC-001", severity=Severity.WARNING)
        report = _report(score=70, findings=[f])

        out_path = reporter.generate_html("owasp", report)
        html = out_path.read_text()

        assert "SEC-001" in html

    def test_html_is_valid_structure(self, tmp_path: Path):
        """HTML should have basic valid structure."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=85, findings=[])

        out_path = reporter.generate_html("owasp", report)
        html = out_path.read_text()

        assert "<!DOCTYPE html>" in html
        assert "<html>" in html
        assert "</html>" in html
        assert "<table>" in html

    def test_html_pass_count(self, tmp_path: Path):
        """HTML should display the count of passing controls."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=100, findings=[])

        out_path = reporter.generate_html("owasp", report)
        html = out_path.read_text()

        total = len(OWASP_MAPPING)
        assert f"{total}/{total} passing" in html

    def test_html_soc2_framework(self, tmp_path: Path):
        """generate_html() should work for SOC2 framework."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=85, findings=[])

        out_path = reporter.generate_html("soc2", report)
        html = out_path.read_text()

        assert "SOC2" in html
        for control in SOC2_MAPPING:
            assert control in html

    def test_html_file_in_reports_dir(self, tmp_path: Path):
        """HTML file should be created inside .devnog/reports/."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=85, findings=[])

        out_path = reporter.generate_html("owasp", report)

        assert out_path.parent == tmp_path / ".devnog" / "reports"


# ---------------------------------------------------------------------------
# generate_pdf() — skip if reportlab not installed
# ---------------------------------------------------------------------------

class TestComplianceReporterGeneratePDF:
    """Tests for ComplianceReporter.generate_pdf()."""

    def test_pdf_raises_without_reportlab(self, tmp_path: Path):
        """generate_pdf() should raise ImportError when reportlab is absent."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=85, findings=[])

        # We test the error path; if reportlab IS installed, we skip this.
        try:
            import reportlab  # noqa: F401
            pytest.skip("reportlab is installed; cannot test import error path")
        except ImportError:
            with pytest.raises(ImportError, match="reportlab"):
                reporter.generate_pdf("owasp", report)


# ---------------------------------------------------------------------------
# Edge cases / integration
# ---------------------------------------------------------------------------

class TestComplianceReporterEdgeCases:
    """Edge cases and integration scenarios."""

    def test_reports_dir_created_automatically(self, tmp_path: Path):
        """ComplianceReporter should create .devnog/reports/ on init."""
        reporter = ComplianceReporter(tmp_path)
        assert (tmp_path / ".devnog" / "reports").is_dir()

    def test_unknown_framework_produces_empty_report(self, tmp_path: Path):
        """Unknown framework should produce JSON with empty controls."""
        reporter = ComplianceReporter(tmp_path)
        report = _report(score=80, findings=[])

        out_path = reporter.generate_json("unknown", report)
        data = json.loads(out_path.read_text())

        assert data["framework"] == "unknown"
        assert data["controls"] == {}

    def test_many_findings_across_controls(self, tmp_path: Path):
        """Multiple findings spanning multiple OWASP controls."""
        reporter = ComplianceReporter(tmp_path)
        findings = [
            _finding(check_id="SEC-001", severity=Severity.CRITICAL, message="weak crypto"),
            _finding(check_id="SEC-002", severity=Severity.CRITICAL, message="sql injection"),
            _finding(check_id="SEC-003", severity=Severity.WARNING, message="broken access"),
            _finding(check_id="SEC-005", severity=Severity.WARNING, message="misconfig"),
            _finding(check_id="DEP-001", severity=Severity.INFO, message="outdated dep", category=Category.DEPENDENCIES),
            _finding(check_id="QA-010", severity=Severity.INFO, message="logging gap", category=Category.CODE_QUALITY),
        ]
        report = _report(score=45, findings=findings)

        result = reporter._map_findings("owasp", report)

        # A01 gets SEC-003 (WARNING) -> WARNING
        assert result["A01:Broken Access Control"]["status"] == "WARNING"
        assert "SEC-003" in result["A01:Broken Access Control"]["matched_ids"]

        # A02 gets SEC-001 (CRITICAL) -> FAIL
        assert result["A02:Cryptographic Failures"]["status"] == "FAIL"

        # A03 gets SEC-002 (CRITICAL) -> FAIL
        assert result["A03:Injection"]["status"] == "FAIL"

        # A06 gets DEP-001 (INFO, no critical) -> WARNING
        assert result["A06:Vulnerable Components"]["status"] == "WARNING"

    def test_json_and_html_produce_consistent_results(self, tmp_path: Path):
        """JSON and HTML reports for the same data should have consistent statuses."""
        reporter = ComplianceReporter(tmp_path)
        f = _finding(check_id="SEC-002", severity=Severity.CRITICAL)
        report = _report(score=60, findings=[f])

        json_path = reporter.generate_json("owasp", report)
        html_path = reporter.generate_html("owasp", report)

        json_data = json.loads(json_path.read_text())
        html_content = html_path.read_text()

        # A03 should be FAIL in both
        assert json_data["controls"]["A03:Injection"]["status"] == "FAIL"
        assert "FAIL" in html_content

    def test_owasp_mapping_has_expected_controls(self, tmp_path: Path):
        """OWASP mapping should contain all 10 OWASP Top 10 categories."""
        assert len(OWASP_MAPPING) == 10
        for i in range(1, 11):
            prefix = f"A{i:02d}:"
            assert any(k.startswith(prefix) for k in OWASP_MAPPING), (
                f"Missing OWASP control starting with {prefix}"
            )

    def test_soc2_mapping_has_expected_controls(self, tmp_path: Path):
        """SOC2 mapping should contain the expected CC controls."""
        assert len(SOC2_MAPPING) == 6
        expected_prefixes = ["CC6.1", "CC6.6", "CC6.7", "CC7.1", "CC7.2", "CC8.1"]
        for prefix in expected_prefixes:
            assert any(k.startswith(prefix) for k in SOC2_MAPPING), (
                f"Missing SOC2 control starting with {prefix}"
            )
