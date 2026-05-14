from __future__ import annotations


EXPLANATION_LIBRARY = {
    "Missing Security Header": {
        "beginner": "This website is missing a browser protection setting. Without it, visitors may have less protection against common web attacks.",
        "expert": "The HTTP response does not include one or more recommended security headers such as Content-Security-Policy, X-Frame-Options, or Strict-Transport-Security.",
        "recommendation": "Add the missing security header in the web server or application framework configuration.",
    },
    "HTTPS Not Available": {
        "beginner": "The website may not be protecting traffic with encryption. Attackers on the same network could read or modify data.",
        "expert": "The scanner could not establish a successful HTTPS connection to the target.",
        "recommendation": "Enable a valid TLS certificate and redirect HTTP traffic to HTTPS.",
    },
    "Certificate Issue": {
        "beginner": "The website certificate may be expired, invalid, or difficult for browsers to trust.",
        "expert": "TLS certificate validation returned an error or the certificate has an expiry issue.",
        "recommendation": "Renew the certificate, verify the certificate chain, and monitor certificate expiry dates.",
    },
    "Directory Listing": {
        "beginner": "A public folder may be showing its file list. This can reveal files that were not meant to be discovered.",
        "expert": "The response body contains common autoindex markers, indicating directory indexing may be enabled.",
        "recommendation": "Disable directory indexing in the web server configuration.",
    },
    "Sensitive File Exposure": {
        "beginner": "A file that often contains private configuration or backup data may be publicly reachable.",
        "expert": "A common sensitive path returned a successful HTTP status and non-empty response.",
        "recommendation": "Remove sensitive files from the public web root and block access using server rules.",
    },
    "Insecure Cookie": {
        "beginner": "A browser cookie is missing a safety flag. This can make account sessions easier to steal or misuse.",
        "expert": "The Set-Cookie header is missing Secure, HttpOnly, or SameSite attributes.",
        "recommendation": "Set Secure, HttpOnly, and SameSite attributes for session cookies.",
    },
    "Missing DMARC Record": {
        "beginner": "Your domain may be easier to impersonate in phishing emails.",
        "expert": "No DMARC TXT record was found at _dmarc.<domain>.",
        "recommendation": "Add a DMARC record to DNS, starting with a monitoring policy such as p=none before enforcing stricter policy.",
    },
    "Missing SPF Record": {
        "beginner": "Email receivers may have less information to confirm which servers are allowed to send email for this domain.",
        "expert": "No SPF TXT record was found in the domain DNS records.",
        "recommendation": "Add an SPF TXT record that lists authorized mail senders.",
    },
    "Open Port": {
        "beginner": "A network service is reachable from the internet. This is not always bad, but unused services should be closed.",
        "expert": "A TCP connection was established to a commonly checked service port.",
        "recommendation": "Confirm the service is required, patched, and protected by firewall rules if possible.",
    },
    "Outdated Server Fingerprint": {
        "beginner": "The website reveals software version information. This can help attackers choose targeted attacks.",
        "expert": "The Server or X-Powered-By header exposes framework or platform fingerprinting details.",
        "recommendation": "Hide detailed version headers and keep the underlying server software updated.",
    },
}


def explain(title: str) -> dict:
    details = EXPLANATION_LIBRARY.get(title)
    if details:
        return details
    return {
        "beginner": "This item may affect the target's digital footprint or security posture.",
        "expert": "The scanner identified a notable condition based on public or low-impact technical evidence.",
        "recommendation": "Review the evidence, confirm whether the issue applies, and apply the recommended security control.",
    }

