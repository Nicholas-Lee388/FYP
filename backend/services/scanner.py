from __future__ import annotations

import json
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import requests

from backend.services.explanations import explain
from backend.services.input_detection import detect_input_type, ensure_url, extract_hostname, normalize_target
from backend.services.scoring import RiskFactors, overall_risk, score_from_factors, severity_from_score

try:
    import dns.resolver
except Exception:  # pragma: no cover
    dns = None

try:
    import whois
except Exception:  # pragma: no cover
    whois = None


SECURITY_HEADERS = {
    "Content-Security-Policy": "Missing Security Header",
    "Strict-Transport-Security": "Missing Security Header",
    "X-Frame-Options": "Missing Security Header",
    "X-Content-Type-Options": "Missing Security Header",
    "Referrer-Policy": "Missing Security Header",
}

SENSITIVE_PATHS = [".env", ".git/config", "backup.zip", "config.php.bak", "db.sql", "admin/"]
COMMON_PORTS = [21, 22, 25, 80, 110, 143, 443, 445, 3306, 5432, 6379, 8080, 8443]


def make_finding(
    title: str,
    category: str,
    factors: RiskFactors,
    evidence: str,
    source: str,
) -> dict:
    score = score_from_factors(factors)
    details = explain(title)
    return {
        "title": title,
        "category": category,
        "severity": severity_from_score(score),
        "score": score,
        "confidence": factors.confidence,
        "evidence": evidence,
        "beginner_explanation": details["beginner"],
        "expert_explanation": details["expert"],
        "recommendation": details["recommendation"],
        "source": source,
    }


def request_target(url: str, timeout: int = 8) -> requests.Response | None:
    headers = {"User-Agent": "fyp2-digital-footprint-scanner/1.0"}
    try:
        return requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None


def check_http(target: str, mode: str) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    telemetry: dict[str, Any] = {"http": {}, "cookies": [], "headers": {}, "probed_paths": []}
    url = ensure_url(target)
    response = request_target(url)
    if response is None and url.startswith("https://"):
        url = ensure_url(target, prefer_https=False)
        response = request_target(url)

    if response is None:
        findings.append(
            make_finding(
                "HTTPS Not Available",
                "Website Basic Check",
                RiskFactors(impact=5.5, exposure=7.0, exploitability=4.0, confidence="Medium"),
                "Could not connect to HTTPS or HTTP endpoint.",
                "HTTP Response",
            )
        )
        telemetry["http"]["reachable"] = False
        return findings, telemetry

    telemetry["http"] = {
        "reachable": True,
        "final_url": response.url,
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type", ""),
        "server": response.headers.get("server", ""),
    }
    telemetry["headers"] = dict(response.headers)

    if not response.url.startswith("https://"):
        findings.append(
            make_finding(
                "HTTPS Not Available",
                "Website Basic Check",
                RiskFactors(impact=6.5, exposure=7.5, exploitability=5.5, confidence="High"),
                f"Final URL used non-HTTPS scheme: {response.url}",
                "HTTP Response",
            )
        )

    for header, title in SECURITY_HEADERS.items():
        if header not in response.headers:
            findings.append(
                make_finding(
                    title,
                    "Security Headers",
                    RiskFactors(impact=4.5, exposure=6.0, exploitability=4.5, confidence="High"),
                    f"Missing header: {header}",
                    "HTTP Response Header",
                )
            )

    if response.headers.get("server") or response.headers.get("x-powered-by"):
        evidence = "; ".join(
            item
            for item in [
                f"Server={response.headers.get('server', '')}",
                f"X-Powered-By={response.headers.get('x-powered-by', '')}",
            ]
            if item.split("=", 1)[1]
        )
        findings.append(
            make_finding(
                "Outdated Server Fingerprint",
                "Web Security",
                RiskFactors(impact=3.5, exposure=5.5, exploitability=3.0, confidence="Medium"),
                evidence,
                "HTTP Response Header",
            )
        )

    for cookie in response.cookies:
        flags = str(cookie)
        telemetry["cookies"].append({"name": cookie.name, "secure": cookie.secure, "domain": cookie.domain})
        raw_cookie_header = response.headers.get("set-cookie", "")
        missing = []
        if not cookie.secure:
            missing.append("Secure")
        if "httponly" not in raw_cookie_header.lower():
            missing.append("HttpOnly")
        if "samesite" not in raw_cookie_header.lower():
            missing.append("SameSite")
        if missing:
            findings.append(
                make_finding(
                    "Insecure Cookie",
                    "Session",
                    RiskFactors(impact=5.5, exposure=5.0, exploitability=5.0, confidence="Medium"),
                    f"Cookie {cookie.name} may be missing: {', '.join(missing)}. Raw: {flags}",
                    "HTTP Cookie",
                )
            )

    if mode in {"quick", "full"}:
        base_url = response.url if response.url.endswith("/") else response.url + "/"
        paths = SENSITIVE_PATHS if mode == "full" else SENSITIVE_PATHS[:3]
        for path in paths:
            probe_url = urljoin(base_url, path)
            try:
                probe = requests.get(probe_url, timeout=6, allow_redirects=False, headers={"User-Agent": "fyp2-safe-check/1.0"})
                telemetry["probed_paths"].append({"path": path, "status_code": probe.status_code})
            except requests.RequestException:
                continue
            if path.endswith("/") and probe.status_code == 200 and any(marker in probe.text.lower() for marker in ["index of /", "parent directory", "directory listing"]):
                findings.append(
                    make_finding(
                        "Directory Listing",
                        "Exposure Check",
                        RiskFactors(impact=6.0, exposure=8.0, exploitability=6.0, confidence="High"),
                        f"Possible directory listing at {probe_url}",
                        "HTTP Public Path Check",
                    )
                )
            elif not path.endswith("/") and probe.status_code == 200 and len(probe.text.strip()) > 10:
                findings.append(
                    make_finding(
                        "Sensitive File Exposure",
                        "Exposure Check",
                        RiskFactors(impact=8.0, exposure=8.0, exploitability=7.0, confidence="Medium"),
                        f"Potentially sensitive file reachable at {probe_url}",
                        "HTTP Public Path Check",
                    )
                )

    return findings, telemetry


def check_tls(hostname: str) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    telemetry: dict[str, Any] = {"tls": {}}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                telemetry["tls"] = {
                    "issuer": cert.get("issuer", []),
                    "subject": cert.get("subject", []),
                    "not_after": cert.get("notAfter", ""),
                    "version": ssock.version(),
                }
    except Exception as exc:
        findings.append(
            make_finding(
                "Certificate Issue",
                "SSL/TLS",
                RiskFactors(impact=5.0, exposure=6.0, exploitability=4.0, confidence="Medium"),
                f"TLS check failed for {hostname}: {exc}",
                "TLS Certificate Check",
            )
        )
        telemetry["tls"] = {"error": str(exc)}
    return findings, telemetry


def lookup_dns(hostname: str) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    telemetry: dict[str, Any] = {"dns": {"A": [], "AAAA": [], "MX": [], "TXT": [], "DMARC": []}}
    if dns is None:
        try:
            telemetry["dns"]["A"] = [socket.gethostbyname(hostname)]
        except socket.gaierror:
            telemetry["dns"]["error"] = "DNS resolver package unavailable and socket lookup failed."
        return findings, telemetry

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 5
    for record_type in ["A", "AAAA", "MX", "TXT"]:
        try:
            answers = resolver.resolve(hostname, record_type)
            telemetry["dns"][record_type] = [answer.to_text() for answer in answers]
        except Exception:
            telemetry["dns"][record_type] = []

    txt_values = " ".join(telemetry["dns"]["TXT"]).lower()
    if "v=spf1" not in txt_values:
        findings.append(
            make_finding(
                "Missing SPF Record",
                "OSINT",
                RiskFactors(impact=4.0, exposure=7.0, exploitability=5.0, confidence="High"),
                f"No SPF record found for {hostname}.",
                "DNS TXT Lookup",
            )
        )

    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{hostname}", "TXT")
        telemetry["dns"]["DMARC"] = [answer.to_text() for answer in dmarc_answers]
    except Exception:
        telemetry["dns"]["DMARC"] = []
        findings.append(
            make_finding(
                "Missing DMARC Record",
                "OSINT",
                RiskFactors(impact=4.5, exposure=7.0, exploitability=5.5, confidence="High"),
                f"No DMARC record found for _dmarc.{hostname}.",
                "DNS TXT Lookup",
            )
        )

    return findings, telemetry


def lookup_whois(hostname: str) -> dict:
    if whois is None:
        return {"available": False, "message": "python-whois is not installed."}
    try:
        data = whois.whois(hostname)
        return {
            "available": True,
            "registrar": str(data.get("registrar", "")),
            "creation_date": str(data.get("creation_date", "")),
            "expiration_date": str(data.get("expiration_date", "")),
            "name_servers": [str(item) for item in data.get("name_servers", [])] if data.get("name_servers") else [],
        }
    except Exception as exc:
        return {"available": False, "message": str(exc)}


def check_ports(hostname: str) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    telemetry: dict[str, Any] = {"open_ports": []}
    for port in COMMON_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.8)
            try:
                result = sock.connect_ex((hostname, port))
            except socket.gaierror:
                break
            except Exception:
                continue
            if result == 0:
                telemetry["open_ports"].append(port)
                if port not in {80, 443}:
                    findings.append(
                        make_finding(
                            "Open Port",
                            "Basic Security Check",
                            RiskFactors(impact=4.5, exposure=8.0, exploitability=4.5, confidence="Medium"),
                            f"Port {port} is reachable on {hostname}.",
                            "TCP Port Check",
                        )
                    )
    return findings, telemetry


def build_correlation(target: str, hostname: str, telemetry: dict) -> dict:
    nodes = [{"id": target, "label": target, "type": "target"}]
    edges = []
    dns_data = telemetry.get("dns", {})
    for ip in dns_data.get("A", []):
        nodes.append({"id": ip, "label": ip, "type": "ip"})
        edges.append({"from": hostname, "to": ip, "label": "A record"})
    for mx in dns_data.get("MX", []):
        mx_host = mx.split()[-1].rstrip(".") if mx else mx
        nodes.append({"id": mx_host, "label": mx_host, "type": "mail"})
        edges.append({"from": hostname, "to": mx_host, "label": "MX"})
    if hostname != target:
        nodes.append({"id": hostname, "label": hostname, "type": "domain"})
        edges.append({"from": target, "to": hostname, "label": "resolves to"})
    return {"nodes": nodes, "edges": edges}


def source_reliability(telemetry: dict) -> list[dict]:
    rows = []
    if telemetry.get("http"):
        rows.append({"result": "HTTP response collected", "source": "Live HTTP response", "confidence": "High"})
    if telemetry.get("dns"):
        rows.append({"result": "DNS records collected", "source": "Live DNS lookup", "confidence": "High"})
    if telemetry.get("whois", {}).get("available"):
        rows.append({"result": "WHOIS metadata collected", "source": "WHOIS lookup", "confidence": "Medium"})
    if telemetry.get("tls"):
        rows.append({"result": "TLS certificate checked", "source": "Live TLS socket", "confidence": "High"})
    if telemetry.get("open_ports"):
        rows.append({"result": "Port reachability checked", "source": "Limited TCP connection check", "confidence": "Medium"})
    return rows


def run_scan(target: str, mode: str = "quick") -> dict:
    normalized = normalize_target(target)
    input_type = detect_input_type(normalized)
    hostname = extract_hostname(normalized)
    scan_mode = mode.lower().replace(" ", "_")
    if scan_mode == "safe":
        scan_mode = "passive"

    findings: list[dict] = []
    telemetry: dict[str, Any] = {
        "target": normalized,
        "input_type": input_type,
        "hostname": hostname,
        "mode": scan_mode,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }

    dns_findings, dns_telemetry = lookup_dns(hostname)
    findings.extend(dns_findings)
    telemetry.update(dns_telemetry)
    telemetry["whois"] = lookup_whois(hostname)

    if input_type in {"url", "domain", "api_endpoint"}:
        http_findings, http_telemetry = check_http(normalized, scan_mode)
        findings.extend(http_findings)
        telemetry.update(http_telemetry)

        tls_findings, tls_telemetry = check_tls(hostname)
        findings.extend(tls_findings)
        telemetry.update(tls_telemetry)

    if scan_mode == "full" and input_type in {"url", "domain", "ip", "api_endpoint"}:
        port_findings, port_telemetry = check_ports(hostname)
        findings.extend(port_findings)
        telemetry.update(port_telemetry)

    risk_score, risk_level = overall_risk(findings)
    telemetry["completed_at"] = datetime.now(timezone.utc).isoformat()
    telemetry["source_reliability"] = source_reliability(telemetry)
    telemetry["correlation"] = build_correlation(normalized, hostname, telemetry)

    summary = (
        f"{len(findings)} finding(s) detected for {normalized}. "
        f"Overall risk is {risk_level} ({risk_score}/10)."
    )
    return {
        "target": normalized,
        "input_type": input_type,
        "mode": scan_mode,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "summary": summary,
        "findings": findings,
        "telemetry": telemetry,
        "raw_json": json.dumps({"findings": findings, "telemetry": telemetry}, default=str),
    }

