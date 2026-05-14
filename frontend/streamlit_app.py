from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import graphviz
import pandas as pd
import plotly.express as px
import requests
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.reports import generate_report
from backend.services.ai_assistant import explain_scan_for_audience
from backend.services.input_detection import detect_input_type, normalize_target
from backend.services.scanner import run_scan


API_URL = os.getenv("STREAMLIT_API_URL", "http://localhost:5000")


st.set_page_config(page_title="fyp2 - Digital Footprint", page_icon="DF", layout="wide")

st.markdown(
    """
<style>
    .block-container { padding-top: 1.2rem; padding-bottom: 4rem; }
    [data-testid="stMetricValue"] { font-size: 1.7rem; }
    .risk-chip {
        display: inline-block;
        padding: 0.25rem 0.55rem;
        border-radius: 7px;
        color: white;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .risk-Critical { background: #7f1d1d; }
    .risk-High { background: #b91c1c; }
    .risk-Medium { background: #b45309; }
    .risk-Low { background: #047857; }
    .risk-Info { background: #475569; }
    .small-muted { color: #64748b; font-size: 0.88rem; }
</style>
""",
    unsafe_allow_html=True,
)


def api_available() -> bool:
    try:
        response = requests.get(f"{API_URL}/api/health", timeout=2)
        return response.ok
    except requests.RequestException:
        return False


def create_api_scan(target: str, mode: str, target_type: str) -> dict | None:
    try:
        response = requests.post(
            f"{API_URL}/api/scans",
            json={
                "target": target,
                "mode": mode,
                "target_type": target_type,
                "authorization_confirmed": True,
            },
            timeout=120,
        )
        response.raise_for_status()
        payload = response.json()
        scan_id = payload["scan"]["id"]
        for _ in range(60):
            detail = requests.get(f"{API_URL}/api/scans/{scan_id}", timeout=20)
            detail.raise_for_status()
            scan = detail.json()
            if scan.get("status") in {"completed", "failed"}:
                return scan
            time.sleep(2)
        return scan
    except requests.RequestException:
        return None


def local_scan(target: str, mode: str) -> dict:
    result = run_scan(target, mode)
    result["id"] = f"local-{len(st.session_state.history) + 1}"
    result["target"] = normalize_target(target)
    return result


def risk_color(level: str) -> str:
    return {
        "Critical": "#7f1d1d",
        "High": "#b91c1c",
        "Medium": "#b45309",
        "Low": "#047857",
        "Info": "#475569",
    }.get(level, "#475569")


def render_graph(correlation: dict) -> None:
    dot = graphviz.Digraph()
    dot.attr(rankdir="LR")
    for node in correlation.get("nodes", []):
        dot.node(node["id"], f"{node['label']}\n{node.get('type', '')}", shape="box", style="rounded,filled", fillcolor="#e0f2fe")
    for edge in correlation.get("edges", []):
        dot.edge(edge["from"], edge["to"], label=edge.get("label", ""))
    st.graphviz_chart(dot)


def render_findings(findings: list[dict], mode: str) -> None:
    if not findings:
        st.success("No major findings detected.")
        return
    for finding in sorted(findings, key=lambda item: item.get("score", 0), reverse=True):
        title = finding["title"]
        level = finding["severity"]
        with st.expander(f"{title} - {level} ({finding['score']}/10)", expanded=level in {"Critical", "High"}):
            st.markdown(
                f"<span class='risk-chip risk-{level}'>{level}</span>",
                unsafe_allow_html=True,
            )
            if mode == "Beginner":
                st.write(finding.get("beginner_explanation", "No explanation available."))
                st.write("Suggested fix:")
                st.info(finding.get("recommendation", "Review this item and apply the relevant security control."))
            else:
                st.write("Technical evidence:")
                st.code(finding.get("evidence", "No evidence available."))
                st.write(finding.get("expert_explanation", "No technical explanation available."))
                st.write(f"Source: {finding.get('source', 'Scanner')} | Confidence: {finding.get('confidence', 'Medium')}")


def render_report_downloads(scan: dict) -> None:
    cols = st.columns(4)
    for col, fmt in zip(cols, ["pdf", "csv", "html", "json"]):
        with col:
            data, mime, filename = generate_report(scan, fmt)
            st.download_button(
                label=f"Download {fmt.upper()}",
                data=data,
                file_name=filename,
                mime=mime,
                use_container_width=True,
            )


def get_scan_for_report(scan: dict) -> dict:
    payload = dict(scan)
    if isinstance(payload.get("target"), dict):
        payload["target"] = payload["target"].get("value", "")
    return payload


if "history" not in st.session_state:
    st.session_state.history = []
if "last_scan" not in st.session_state:
    st.session_state.last_scan = None
if "user_mode" not in st.session_state:
    st.session_state.user_mode = "Beginner"
if "language" not in st.session_state:
    st.session_state.language = "English"


st.title("The Digital Footprint")
st.caption("fyp2 | Beginner-Friendly OSINT and General Security Scan Platform")

backend_state = "Connected" if api_available() else "Local demo mode"
st.markdown(f"<p class='small-muted'>Backend status: {backend_state}</p>", unsafe_allow_html=True)

scan_tab, learn_tab, history_tab, info_tab, me_tab = st.tabs(["Scan", "Learn", "History", "Info", "Me"])

with scan_tab:
    left, right = st.columns([0.35, 0.65], gap="large")
    with left:
        st.subheader("Target")
        target_value = st.text_input("Website URL, domain, IP address, API endpoint, email, or username", placeholder="example.com")
        detected = detect_input_type(target_value) if target_value else "unknown"
        st.write(f"Detected input: **{detected}**")
        target_type = st.selectbox("Target type", ["Web App", "API", "Server", "Internal System", "Personal Footprint"])
        scan_mode = st.radio("Scan mode", ["quick", "passive", "full"], horizontal=True)
        st.session_state.user_mode = st.radio(
            "View mode",
            ["Beginner", "Expert"],
            horizontal=True,
            index=0 if st.session_state.user_mode == "Beginner" else 1,
        )
        authorized = st.checkbox("I own this target or have permission to scan it.")

        start = st.button("Start Scan", type="primary", use_container_width=True, disabled=not target_value or not authorized)
        if start:
            with st.spinner("Scanning safely and preparing the dashboard..."):
                scan = create_api_scan(target_value, scan_mode, target_type) if backend_state == "Connected" else None
                if scan is None:
                    scan = local_scan(target_value, scan_mode)
                scan["target"] = scan.get("target") or normalize_target(target_value)
                st.session_state.last_scan = scan
                st.session_state.history.insert(0, scan)
            st.success("Scan completed.")

    with right:
        scan = st.session_state.last_scan
        if not scan:
            st.info("Add a target, confirm authorization, and start a scan to view results.")
        else:
            target_label = scan.get("target", "")
            if isinstance(target_label, dict):
                target_label = target_label.get("value", "")
            st.subheader(target_label)
            metric_cols = st.columns(4)
            metric_cols[0].metric("Overall Risk", f"{scan.get('risk_score', 0)}/10")
            metric_cols[1].metric("Risk Level", scan.get("risk_level", "Info"))
            metric_cols[2].metric("Findings", len(scan.get("findings", [])))
            metric_cols[3].metric("Mode", scan.get("mode", scan_mode).title())

            findings = scan.get("findings", [])
            if findings:
                severity_df = pd.DataFrame(findings)
                chart = px.histogram(
                    severity_df,
                    x="severity",
                    color="severity",
                    color_discrete_map={
                        "Critical": "#7f1d1d",
                        "High": "#b91c1c",
                        "Medium": "#b45309",
                        "Low": "#047857",
                        "Info": "#475569",
                    },
                    category_orders={"severity": ["Critical", "High", "Medium", "Low", "Info"]},
                    title="Findings by Severity",
                )
                st.plotly_chart(chart, use_container_width=True)

            ai_text = explain_scan_for_audience(
                get_scan_for_report(scan),
                audience="beginner" if st.session_state.user_mode == "Beginner" else "developer",
                language=st.session_state.language,
            )
            st.write(ai_text)

            render_findings(findings, st.session_state.user_mode)

            telemetry = scan.get("telemetry", {})
            if telemetry.get("source_reliability"):
                st.subheader("Source Reliability")
                st.dataframe(pd.DataFrame(telemetry["source_reliability"]), use_container_width=True, hide_index=True)
            if telemetry.get("correlation"):
                st.subheader("Relationship Graph")
                render_graph(telemetry["correlation"])

            st.subheader("Report")
            render_report_downloads(get_scan_for_report(scan))

with learn_tab:
    st.subheader("Learn")
    topics = [
        ("WHOIS", "Public registration information about a domain. Some data may be hidden for privacy."),
        ("DNS", "The internet address book that maps domains to IP addresses, mail servers, and text records."),
        ("Subdomain", "A smaller section of a domain, such as admin.example.com or api.example.com."),
        ("DMARC", "An email security record that helps reduce domain impersonation and phishing."),
        ("Security Header", "A browser instruction that adds protection against common web attacks."),
        ("Risk Score", "A simple score based on impact, exposure, exploitability, and confidence."),
        ("Passive Scan", "A safer scan mode that focuses on public information and low-impact checks."),
        ("Full Scan", "A broader scan mode for authorized technical users, including limited port checks."),
    ]
    cols = st.columns(2)
    for index, (title, body) in enumerate(topics):
        with cols[index % 2]:
            with st.container(border=True):
                st.markdown(f"**{title}**")
                st.write(body)

with history_tab:
    st.subheader("History")
    if not st.session_state.history:
        st.info("No scans in this dashboard session yet.")
    else:
        rows = []
        for scan in st.session_state.history:
            target = scan.get("target", "")
            if isinstance(target, dict):
                target = target.get("value", "")
            rows.append(
                {
                    "Target": target,
                    "Mode": scan.get("mode", ""),
                    "Risk Score": scan.get("risk_score", 0),
                    "Risk Level": scan.get("risk_level", "Info"),
                    "Findings": len(scan.get("findings", [])),
                }
            )
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        selected = st.selectbox("Open previous result", list(range(len(st.session_state.history))), format_func=lambda i: rows[i]["Target"])
        if st.button("Load Selected Scan", use_container_width=True):
            st.session_state.last_scan = st.session_state.history[selected]
            st.success("Loaded selected scan in the Scan tab.")

with info_tab:
    st.subheader("Info")
    st.markdown(
        """
This platform uses public and low-impact technical sources such as HTTP responses, DNS records, TLS certificate metadata, and WHOIS-style domain information.

It is designed for awareness and authorized assessment. Results may contain false positives or outdated third-party information, so important findings should be manually verified before action.
"""
    )
    st.write("Example academic SaaS concept:")
    st.dataframe(
        pd.DataFrame(
            [
                {"Plan": "Free", "Use": "Student demo and small personal checks", "Scans": "Limited"},
                {"Plan": "Student", "Use": "Coursework, FYP demo, learning dashboard", "Scans": "Moderate"},
                {"Plan": "Pro", "Use": "Small team awareness and reporting", "Scans": "Higher"},
            ]
        ),
        use_container_width=True,
        hide_index=True,
    )

with me_tab:
    st.subheader("Me")
    st.session_state.user_mode = st.radio("Default view mode", ["Beginner", "Expert"], horizontal=True, index=0 if st.session_state.user_mode == "Beginner" else 1)
    st.session_state.language = st.selectbox("Explanation language", ["English", "Chinese", "Malay"], index=["English", "Chinese", "Malay"].index(st.session_state.language))
    if st.button("Delete dashboard session history", use_container_width=True):
        st.session_state.history = []
        st.session_state.last_scan = None
        st.success("Session history cleared.")
    st.caption("Use this system only on targets you own or are authorized to assess.")
