from __future__ import annotations

import json
from datetime import datetime

from celery import Celery

from backend.config import settings
from backend.database import init_db, session_scope
from backend.models import Finding, Scan, Target
from backend.services.scanner import run_scan

celery = Celery("fyp2", broker=settings.celery_broker_url, backend=settings.celery_result_backend)


def persist_scan_result(scan_id: str, result: dict) -> dict:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")
        scan.status = "completed"
        scan.risk_score = result["risk_score"]
        scan.risk_level = result["risk_level"]
        scan.summary = result["summary"]
        scan.raw_json = result["raw_json"]
        scan.completed_at = datetime.utcnow()
        scan.target.status = "online" if result.get("telemetry", {}).get("http", {}).get("reachable") else "unknown"
        scan.target.last_risk_level = result["risk_level"]

        scan.findings.clear()
        for item in result["findings"]:
            scan.findings.append(
                Finding(
                    title=item["title"],
                    category=item["category"],
                    severity=item["severity"],
                    score=item["score"],
                    confidence=item["confidence"],
                    evidence=item["evidence"],
                    beginner_explanation=item["beginner_explanation"],
                    expert_explanation=item["expert_explanation"],
                    recommendation=item["recommendation"],
                    source=item["source"],
                )
            )
        session.add(scan)
    return result


@celery.task(name="backend.tasks.scan_target")
def scan_target(scan_id: str, target_value: str, mode: str) -> dict:
    init_db()
    try:
        result = run_scan(target_value, mode)
        return persist_scan_result(scan_id, result)
    except Exception as exc:
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.summary = str(exc)
                scan.raw_json = json.dumps({"error": str(exc)})
                scan.completed_at = datetime.utcnow()
                session.add(scan)
        raise


def run_scan_synchronously(scan_id: str, target_value: str, mode: str) -> dict:
    result = run_scan(target_value, mode)
    return persist_scan_result(scan_id, result)


def queue_or_run_scan(scan: Scan, target: Target) -> str:
    if not settings.use_celery:
        run_scan_synchronously(scan.id, target.value, scan.mode)
        return "synchronous-local"
    try:
        task = scan_target.delay(scan.id, target.value, scan.mode)
        return str(task.id)
    except Exception:
        run_scan_synchronously(scan.id, target.value, scan.mode)
        return "synchronous-fallback"
