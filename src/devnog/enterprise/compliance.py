"""Compliance report generation (Enterprise)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from devnog.core.config import get_devnog_dir
from devnog.core.models import ScanReport, Severity

# OWASP Top 10 mapping
OWASP_MAPPING = {
    "A01:Broken Access Control": ["SEC-003", "SEC-011", "QA-009"],
    "A02:Cryptographic Failures": ["SEC-001", "SEC-009"],
    "A03:Injection": ["SEC-002", "SEC-004", "SEC-010", "SEC-012"],
    "A04:Insecure Design": ["QA-018", "QA-019"],
    "A05:Security Misconfiguration": ["SEC-005", "SEC-006", "QA-015", "QA-016"],
    "A06:Vulnerable Components": ["DEP-001", "DEP-002", "DEP-006"],
    "A07:Auth Failures": ["SEC-007", "SEC-008"],
    "A08:Data Integrity Failures": ["QA-012", "QA-013"],
    "A09:Logging Failures": ["QA-010", "QA-022", "QA-023"],
    "A10:SSRF": ["SEC-010"],
}

SOC2_MAPPING = {
    "CC6.1 - Logical Access": ["SEC-001", "SEC-003", "SEC-007", "SEC-008"],
    "CC6.6 - System Boundaries": ["SEC-005", "QA-009"],
    "CC6.7 - Data Classification": ["SEC-001", "QA-016"],
    "CC7.1 - Detection": ["QA-010", "QA-022", "QA-023"],
    "CC7.2 - Monitoring": ["ERR-005", "QA-022"],
    "CC8.1 - Change Management": ["DEP-003", "DEP-001"],
}


class ComplianceReporter:
    """Generates audit-ready compliance reports."""

    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.devnog_dir = get_devnog_dir(project_path)
        self.reports_dir = self.devnog_dir / "reports"
        self.reports_dir.mkdir(exist_ok=True)

    def _get_mapping(self, framework: str) -> dict[str, list[str]]:
        """Get the check-to-framework mapping."""
        if framework == "owasp":
            return OWASP_MAPPING
        elif framework == "soc2":
            return SOC2_MAPPING
        return {}

    def _map_findings(self, framework: str, report: ScanReport) -> dict[str, dict]:
        """Map findings to compliance controls."""
        mapping = self._get_mapping(framework)
        finding_ids = {f.check_id for f in report.findings}

        result = {}
        for control, check_ids in mapping.items():
            matched = [cid for cid in check_ids if cid in finding_ids]
            findings = [f for f in report.findings if f.check_id in check_ids]

            if matched:
                status = "FAIL"
                has_critical = any(f.severity == Severity.CRITICAL for f in findings)
                if not has_critical:
                    status = "WARNING"
            else:
                status = "PASS"
                findings = []

            result[control] = {
                "status": status,
                "check_ids": check_ids,
                "matched_ids": matched,
                "findings": findings,
            }

        return result

    def generate_json(self, framework: str, report: ScanReport) -> Path:
        """Generate JSON compliance report."""
        mapped = self._map_findings(framework, report)
        timestamp = datetime.now().strftime("%Y-%m-%d")

        output = {
            "framework": framework,
            "generated_at": datetime.now().isoformat(),
            "project": self.project_path.name,
            "overall_score": report.overall_score,
            "controls": {
                control: {
                    "status": data["status"],
                    "checks": data["check_ids"],
                    "issues": [
                        {
                            "check_id": f.check_id,
                            "severity": f.severity.value,
                            "message": f.message,
                            "file": str(f.file),
                            "line": f.line,
                        }
                        for f in data["findings"]
                    ],
                }
                for control, data in mapped.items()
            },
        }

        out_file = self.reports_dir / f"compliance-{framework}-{timestamp}.json"
        out_file.write_text(json.dumps(output, indent=2, default=str))
        return out_file

    def generate_html(self, framework: str, report: ScanReport) -> Path:
        """Generate HTML compliance report."""
        mapped = self._map_findings(framework, report)
        timestamp = datetime.now().strftime("%Y-%m-%d")

        rows = ""
        for control, data in mapped.items():
            color = "#2ecc71" if data["status"] == "PASS" else "#e74c3c" if data["status"] == "FAIL" else "#f39c12"
            issues = ", ".join(data["matched_ids"]) if data["matched_ids"] else "None"
            rows += f"""
            <tr>
                <td>{control}</td>
                <td style="color:{color};font-weight:bold">{data["status"]}</td>
                <td>{issues}</td>
            </tr>"""

        pass_count = sum(1 for d in mapped.values() if d["status"] == "PASS")
        total = len(mapped)

        html = f"""<!DOCTYPE html>
<html><head><title>DevNog Compliance Report - {framework.upper()}</title>
<style>
body {{ font-family: -apple-system, sans-serif; margin: 40px; background: #fff; color: #333; }}
h1 {{ color: #2c3e50; }}
.summary {{ font-size: 24px; margin: 20px 0; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
th, td {{ padding: 12px; text-align: left; border: 1px solid #ddd; }}
th {{ background: #f8f9fa; }}
.footer {{ margin-top: 30px; color: #999; font-size: 12px; }}
</style></head>
<body>
<h1>DevNog Compliance Report</h1>
<h2>Framework: {framework.upper()}</h2>
<p class="summary">Score: {report.overall_score}/100 | Controls: {pass_count}/{total} passing</p>
<p>Project: {self.project_path.name} | Generated: {timestamp}</p>
<table>
<tr><th>Control</th><th>Status</th><th>Issues</th></tr>
{rows}
</table>
<div class="footer">Generated by DevNog v0.1.0</div>
</body></html>"""

        out_file = self.reports_dir / f"compliance-{framework}-{timestamp}.html"
        out_file.write_text(html)
        return out_file

    def generate_pdf(self, framework: str, report: ScanReport) -> Path:
        """Generate PDF compliance report."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib import colors
        except ImportError:
            raise ImportError(
                "PDF generation requires reportlab. "
                "Install with: pip install devnog[enterprise]"
            )

        mapped = self._map_findings(framework, report)
        timestamp = datetime.now().strftime("%Y-%m-%d")
        out_file = self.reports_dir / f"compliance-{framework}-{timestamp}.pdf"

        doc = SimpleDocTemplate(str(out_file), pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Title
        elements.append(Paragraph("DevNog Compliance Report", styles["Title"]))
        elements.append(Paragraph(f"Framework: {framework.upper()}", styles["Heading2"]))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(
            f"Project: {self.project_path.name} | Score: {report.overall_score}/100 | Date: {timestamp}",
            styles["Normal"],
        ))
        elements.append(Spacer(1, 24))

        # Controls table
        table_data = [["Control", "Status", "Issues"]]
        for control, data in mapped.items():
            issues = ", ".join(data["matched_ids"]) if data["matched_ids"] else "None"
            table_data.append([control, data["status"], issues])

        table = Table(table_data, colWidths=[250, 80, 200])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.white),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(table)

        doc.build(elements)
        return out_file
