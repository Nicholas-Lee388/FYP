from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


DOMAIN_RE = re.compile(r"^(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_target(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        return value
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        host = parsed.netloc.lower()
        path = parsed.path.rstrip("/")
        return f"{parsed.scheme}://{host}{path}"
    return value.lower().rstrip("/")


def detect_input_type(value: str) -> str:
    normalized = normalize_target(value)
    if not normalized:
        return "unknown"
    if EMAIL_RE.match(normalized):
        return "email"
    try:
        ipaddress.ip_address(normalized)
        return "ip"
    except ValueError:
        pass
    if normalized.startswith(("http://", "https://")):
        parsed = urlparse(normalized)
        if "/api" in parsed.path.lower() or parsed.path.lower().endswith((".json", ".xml")):
            return "api_endpoint"
        return "url"
    if DOMAIN_RE.match(normalized):
        return "domain"
    if re.match(r"^[A-Za-z0-9_.-]{3,40}$", normalized):
        return "username"
    return "unknown"


def extract_hostname(value: str) -> str:
    normalized = normalize_target(value)
    if normalized.startswith(("http://", "https://")):
        return urlparse(normalized).netloc.split("@")[-1].split(":")[0]
    if detect_input_type(normalized) == "email":
        return normalized.split("@", 1)[1]
    return normalized


def ensure_url(value: str, prefer_https: bool = True) -> str:
    normalized = normalize_target(value)
    if normalized.startswith(("http://", "https://")):
        return normalized
    scheme = "https" if prefer_https else "http"
    return f"{scheme}://{normalized}"

