from __future__ import annotations

import json
from datetime import datetime

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from sqlalchemy import desc

from backend.database import init_db, session_scope
from backend.models import Scan, Target
from backend.reports import generate_report
from backend.services.ai_assistant import explain_scan_for_audience
from backend.services.input_detection import detect_input_type, normalize_target
from backend.tasks import queue_or_run_scan


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)
    init_db()

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "service": "fyp2-api", "time": datetime.utcnow().isoformat()})

    @app.get("/api/targets")
    def list_targets():
        with session_scope() as session:
            targets = session.query(Target).order_by(desc(Target.updated_at)).all()
            return jsonify([target.to_dict() for target in targets])

    @app.post("/api/targets")
    def create_target():
        payload = request.get_json(force=True)
        value = normalize_target(payload.get("value", ""))
        if not value:
            return jsonify({"error": "Target value is required."}), 400
        with session_scope() as session:
            target = session.query(Target).filter(Target.value == value).one_or_none()
            if target is None:
                target = Target(
                    label=payload.get("label") or value,
                    value=value,
                    input_type=detect_input_type(value),
                    target_type=payload.get("target_type") or "Web App",
                )
                session.add(target)
                session.flush()
            return jsonify(target.to_dict()), 201

    @app.get("/api/scans")
    def list_scans():
        with session_scope() as session:
            scans = session.query(Scan).order_by(desc(Scan.created_at)).limit(50).all()
            return jsonify([scan.to_dict(include_findings=False) for scan in scans])

    @app.post("/api/scans")
    def create_scan():
        payload = request.get_json(force=True)
        target_value = normalize_target(payload.get("target") or payload.get("value", ""))
        target_id = payload.get("target_id")
        mode = (payload.get("mode") or "quick").lower()
        authorized = bool(payload.get("authorization_confirmed"))
        if not authorized:
            return jsonify({"error": "Authorization confirmation is required before scanning."}), 403
        if mode not in {"quick", "full", "passive", "safe"}:
            return jsonify({"error": "Mode must be quick, full, or passive."}), 400

        with session_scope() as session:
            target = session.get(Target, target_id) if target_id else None
            if target is None:
                if not target_value:
                    return jsonify({"error": "Target value is required."}), 400
                target = session.query(Target).filter(Target.value == target_value).one_or_none()
                if target is None:
                    target = Target(
                        label=payload.get("label") or target_value,
                        value=target_value,
                        input_type=detect_input_type(target_value),
                        target_type=payload.get("target_type") or "Web App",
                    )
                    session.add(target)
                    session.flush()
            scan = Scan(target_id=target.id, mode="passive" if mode == "safe" else mode, authorization_confirmed=1)
            session.add(scan)
            session.flush()
            scan_id = scan.id
            target_payload = target.to_dict()

        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            target = session.get(Target, target_payload["id"])
            task_id = queue_or_run_scan(scan, target)

        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            return jsonify({"scan": scan.to_dict(), "task_id": task_id}), 202

    @app.get("/api/scans/<scan_id>")
    def get_scan(scan_id: str):
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return jsonify({"error": "Scan not found."}), 404
            payload = scan.to_dict()
            try:
                raw = json.loads(scan.raw_json or "{}")
            except json.JSONDecodeError:
                raw = {}
            payload["telemetry"] = raw.get("telemetry", {})
            return jsonify(payload)

    @app.get("/api/scans/<scan_id>/report")
    def download_report(scan_id: str):
        report_format = request.args.get("format", "pdf")
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return jsonify({"error": "Scan not found."}), 404
            payload = scan.to_dict()
            try:
                raw = json.loads(scan.raw_json or "{}")
            except json.JSONDecodeError:
                raw = {}
            payload["telemetry"] = raw.get("telemetry", {})
            payload["target"] = scan.target.value
            report_bytes, mimetype, filename = generate_report(payload, report_format)
        return send_file(
            __import__("io").BytesIO(report_bytes),
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename,
        )

    @app.post("/api/ai/explain")
    def ai_explain():
        payload = request.get_json(force=True)
        scan_result = payload.get("scan_result") or {}
        if payload.get("scan_id"):
            with session_scope() as session:
                scan = session.get(Scan, payload["scan_id"])
                if scan:
                    scan_result = scan.to_dict()
        text = explain_scan_for_audience(
            scan_result,
            audience=payload.get("audience", "beginner"),
            language=payload.get("language", "English"),
        )
        return jsonify({"explanation": text, "mode": "deterministic-explanation-layer"})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

