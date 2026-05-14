from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from html import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def scan_to_json(scan: dict) -> bytes:
    return json.dumps(scan, indent=2, default=str).encode("utf-8")


def scan_to_csv(scan: dict) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=["title", "category", "severity", "score", "confidence", "evidence", "recommendation", "source"],
    )
    writer.writeheader()
    for finding in scan.get("findings", []):
        writer.writerow({key: finding.get(key, "") for key in writer.fieldnames})
    return buffer.getvalue().encode("utf-8")


def scan_to_html(scan: dict) -> bytes:
    target = scan.get("target") or scan.get("target", {}).get("value", "")
    findings = scan.get("findings", [])
    rows = "\n".join(
        "<tr>"
        f"<td>{escape(item.get('title', ''))}</td>"
        f"<td>{escape(item.get('severity', ''))}</td>"
        f"<td>{escape(str(item.get('score', '')))}</td>"
        f"<td>{escape(item.get('confidence', ''))}</td>"
        f"<td>{escape(item.get('recommendation', ''))}</td>"
        "</tr>"
        for item in findings
    )
    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Digital Footprint Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #1f2937; }}
    h1 {{ color: #0f766e; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d1d5db; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
  </style>
</head>
<body>
  <h1>The Digital Footprint Report</h1>
  <p><strong>Target:</strong> {escape(str(target))}</p>
  <p><strong>Risk:</strong> {escape(str(scan.get('risk_level', 'Info')))} ({escape(str(scan.get('risk_score', 0)))}/10)</p>
  <p>{escape(scan.get('summary', ''))}</p>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Finding</th><th>Severity</th><th>Score</th><th>Confidence</th><th>Suggested Fix</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>
"""
    return html.encode("utf-8")


def scan_to_pdf(scan: dict) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = []

    target = scan.get("target") or scan.get("target", {}).get("value", "")
    story.append(Paragraph("The Digital Footprint Report", styles["Title"]))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(f"Target: {target}", styles["Normal"]))
    story.append(Paragraph(f"Overall Risk: {scan.get('risk_level', 'Info')} ({scan.get('risk_score', 0)}/10)", styles["Normal"]))
    story.append(Paragraph(scan.get("summary", "No summary available."), styles["Normal"]))
    story.append(Spacer(1, 12))

    table_data = [["Finding", "Severity", "Score", "Confidence", "Suggested Fix"]]
    for item in scan.get("findings", []):
        table_data.append(
            [
                Paragraph(item.get("title", ""), styles["BodyText"]),
                item.get("severity", ""),
                str(item.get("score", "")),
                item.get("confidence", ""),
                Paragraph(item.get("recommendation", ""), styles["BodyText"]),
            ]
        )
    if len(table_data) == 1:
        table_data.append(["No findings", "Info", "0", "High", "Continue periodic monitoring."])

    table = Table(table_data, colWidths=[105, 55, 42, 70, 210])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    )
    story.append(Paragraph("Vulnerability / Exposure List", styles["Heading2"]))
    story.append(table)
    doc.build(story)
    return buffer.getvalue()


def generate_report(scan: dict, report_format: str) -> tuple[bytes, str, str]:
    fmt = report_format.lower()
    if fmt == "pdf":
        return scan_to_pdf(scan), "application/pdf", "digital-footprint-report.pdf"
    if fmt == "csv":
        return scan_to_csv(scan), "text/csv", "digital-footprint-findings.csv"
    if fmt == "html":
        return scan_to_html(scan), "text/html", "digital-footprint-report.html"
    return scan_to_json(scan), "application/json", "digital-footprint-result.json"

