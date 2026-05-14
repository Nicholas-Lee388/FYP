from __future__ import annotations


def explain_scan_for_audience(scan_result: dict, audience: str = "beginner", language: str = "English") -> str:
    """Safe AI-like explanation layer.

    The function is intentionally deterministic for FYP demos. It can be replaced by
    Gemini or OpenAI API calls later, but the scanner itself should remain rule-based.
    """

    findings = scan_result.get("findings", [])
    risk_level = scan_result.get("risk_level", "Info")
    risk_score = scan_result.get("risk_score", 0)
    target = scan_result.get("target", "the target")

    if not findings:
        base = f"No major issues were detected for {target}. Continue monitoring and repeat scans after configuration changes."
    else:
        top = sorted(findings, key=lambda item: item.get("score", 0), reverse=True)[:3]
        top_items = "; ".join(f"{item['title']} ({item['severity']})" for item in top)
        base = f"{target} currently has {risk_level} risk ({risk_score}/10). The main items to review are: {top_items}."

    if audience == "manager":
        return f"Management summary: {base} Prioritize high-risk findings first and track remediation through retesting."
    if audience == "developer":
        return f"Developer guidance: {base} Review the evidence, update server/DNS configuration, and verify the change with a follow-up scan."
    if language.lower().startswith("chinese"):
        return f"简明说明：{base} 建议先处理高风险项目，然后重新扫描确认是否已经修复。"
    if language.lower().startswith("malay"):
        return f"Ringkasan mudah: {base} Utamakan isu berisiko tinggi dahulu, kemudian jalankan imbasan semula."
    return f"Beginner explanation: {base} Start with the highest risk item and follow the suggested fix checklist."

