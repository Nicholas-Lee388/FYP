# fyp2 Technical Architecture

## System Positioning

The Digital Footprint is a beginner-friendly security awareness and OSINT aggregation platform. It is not designed as an advanced penetration testing tool. Its purpose is to help students, beginners, and junior security users understand digital footprint risk through guided scanning, risk scoring, visualization, and downloadable reporting.

## Main Modules

```text
User
  -> Streamlit Dashboard
  -> Target and Asset Management
  -> Scan Mode Selection
  -> Flask API
  -> Celery Background Worker
  -> OSINT + Basic Security Scan Engine
  -> Risk Scoring and Correlation Engine
  -> Dashboard Visualization
  -> Explanation Assistant
  -> Report Generation
```

## Scan Modes

### Passive Scan

Passive Scan focuses on public information and low-impact checks:

- DNS lookup
- WHOIS-style metadata
- TLS metadata
- HTTP header observation
- Email security records such as SPF and DMARC

### Quick Scan

Quick Scan adds beginner-friendly checks:

- HTTP and HTTPS availability
- Missing security headers
- Basic cookie flags
- A small set of common sensitive file checks
- Risk summary

### Full Scan

Full Scan is for authorized technical users:

- All Quick Scan modules
- Broader sensitive file checks
- Limited common port reachability checks
- More technical evidence for Expert Mode

## Risk Scoring

The scoring model is inspired by CVSS but intentionally simplified for an FYP awareness system.

```text
Finding Score = Impact + Exposure + Exploitability, adjusted by Confidence
Overall Score = Weighted finding score + volume boost for multiple notable issues
```

Severity bands:

| Level | Score |
| --- | ---: |
| Critical | 9.0 - 10.0 |
| High | 7.0 - 8.9 |
| Medium | 4.0 - 6.9 |
| Low | 1.0 - 3.9 |
| Info | 0.0 |

## AI Explanation Layer

The explanation assistant is intentionally separated from the detection engine. The scanner uses deterministic rules and evidence. The assistant converts scan results into beginner, developer, manager, or multilingual summaries.

This avoids using AI as the vulnerability decision-maker while still giving the system a strong educational feature.

## Database Design

Main relational entities:

- `Target`: target value, type, detected input type, latest risk state
- `Scan`: scan mode, status, score, summary, raw JSON telemetry
- `Finding`: category, severity, score, confidence, evidence, explanations, recommendations

PostgreSQL is recommended for final deployment through Google Cloud SQL. SQLite is used as a local fallback for development and demo convenience.

## Cloud Deployment Plan

Recommended GCP deployment:

- Compute Engine VM hosts Docker containers
- Cloud SQL hosts PostgreSQL
- Redis container or managed Memorystore acts as Celery broker/cache
- Secret Manager stores Shodan, Gemini, OpenAI, and database credentials
- Docker Compose is used for reproducible local and VM deployment

## Ethical Controls

The system requires authorization confirmation before scanning. It avoids destructive exploitation, authentication bypass, SQL injection exploitation, XSS payload testing, dark web scraping, and enterprise compliance claims.

