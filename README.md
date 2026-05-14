# fyp2 - The Digital Footprint

Beginner-Friendly OSINT and General Security Scan Platform.

This project is an FYP-ready web system that combines safe OSINT collection, basic security checks, risk scoring, visual dashboarding, beginner explanations, scan history, and downloadable reports.

## Main Features

- Target and asset management with authorization confirmation
- Quick Scan, Passive/Safe Scan, and Full Scan modes
- OSINT checks for DNS, WHOIS-style metadata, IP, email security records, and subdomain hints
- Basic security checks for HTTPS, security headers, cookies, sensitive file exposure, directory listing, and limited open ports
- CVSS-inspired risk scoring with impact, exposure, exploitability, and confidence factors
- Beginner Mode and Expert Mode explanations
- Source reliability indicator
- Lightweight relationship graph data for domain, IP, mail, and hosting relationships
- Report export in PDF, CSV, HTML, and JSON
- Streamlit dashboard with Scan, Learn, History, Info, and Me sections
- Flask API, Celery worker, Redis broker/cache, and PostgreSQL-ready persistence
- Docker Compose setup for a professional demo environment

## Recommended Demo Path

### With Docker

1. Copy `.env.example` to `.env`.
2. Start the system:

```powershell
docker compose up --build
```

3. Open the dashboard:

```text
http://localhost:8501
```

4. Open the API health check:

```text
http://localhost:5000/api/health
```

## Local Development Without Docker

For local development, you can skip `.env` and the app will use a local SQLite database automatically.

Install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run the API:

```powershell
python -m backend.app
```

Run the dashboard in another terminal:

```powershell
streamlit run frontend/streamlit_app.py
```

The dashboard has a local fallback scan mode, so it can still demonstrate core scanning even if Redis, Celery, or PostgreSQL are not running.

## Ethical Scope

This system is designed for beginner-friendly security awareness and authorized scanning only. It does not perform destructive exploitation, authentication bypass, SQL injection exploitation, or aggressive vulnerability testing. Users must confirm that they own or have permission to scan each target.

## Architecture

```text
User
  -> Streamlit Dashboard
  -> Flask API
  -> Celery Worker
  -> OSINT + Basic Security Scan Engine
  -> Risk Scoring + Correlation Engine
  -> PostgreSQL / SQLite fallback
  -> Report Generator
```

See `docs/architecture.md` for the full FYP technical write-up.

## Deployment

For Google Cloud Platform deployment, see `docs/gcp_deployment.md`.
