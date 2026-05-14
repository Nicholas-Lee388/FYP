from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base


def new_id() -> str:
    return str(uuid.uuid4())


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    label: Mapped[str] = mapped_column(String(160))
    value: Mapped[str] = mapped_column(String(500), unique=True, index=True)
    input_type: Mapped[str] = mapped_column(String(40), default="unknown")
    target_type: Mapped[str] = mapped_column(String(80), default="Web App")
    status: Mapped[str] = mapped_column(String(40), default="unknown")
    last_risk_level: Mapped[str] = mapped_column(String(40), default="Info")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scans: Mapped[list["Scan"]] = relationship(back_populates="target", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "value": self.value,
            "input_type": self.input_type,
            "target_type": self.target_type,
            "status": self.status,
            "last_risk_level": self.last_risk_level,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"))
    mode: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(40), default="queued")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(40), default="Info")
    summary: Mapped[str] = mapped_column(Text, default="")
    raw_json: Mapped[str] = mapped_column(Text, default="{}")
    authorization_confirmed: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    target: Mapped[Target] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self, include_findings: bool = True) -> dict:
        payload = {
            "id": self.id,
            "target_id": self.target_id,
            "target": self.target.to_dict() if self.target else None,
            "mode": self.mode,
            "status": self.status,
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level,
            "summary": self.summary,
            "authorization_confirmed": bool(self.authorization_confirmed),
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
        if include_findings:
            payload["findings"] = [finding.to_dict() for finding in self.findings]
        return payload


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    title: Mapped[str] = mapped_column(String(180))
    category: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(40))
    score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[str] = mapped_column(String(40), default="Medium")
    evidence: Mapped[str] = mapped_column(Text, default="")
    beginner_explanation: Mapped[str] = mapped_column(Text, default="")
    expert_explanation: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(120), default="Scanner")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan: Mapped[Scan] = relationship(back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "score": round(self.score, 2),
            "confidence": self.confidence,
            "evidence": self.evidence,
            "beginner_explanation": self.beginner_explanation,
            "expert_explanation": self.expert_explanation,
            "recommendation": self.recommendation,
            "source": self.source,
            "created_at": self.created_at.isoformat(),
        }

