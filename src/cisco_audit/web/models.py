"""SQLAlchemy models for audit history."""

from __future__ import annotations

from datetime import datetime, timezone

from cisco_audit.web import db


class AuditRecord(db.Model):  # type: ignore[name-defined]
    __tablename__ = "audit_records"

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False, default="unknown")
    source = db.Column(db.String(10), nullable=False)  # "file" or "ssh"
    source_detail = db.Column(db.String(512), nullable=False)
    timestamp = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    count_low = db.Column(db.Integer, nullable=False, default=0)
    count_medium = db.Column(db.Integer, nullable=False, default=0)
    count_high = db.Column(db.Integer, nullable=False, default=0)
    count_critical = db.Column(db.Integer, nullable=False, default=0)
    count_total = db.Column(db.Integer, nullable=False, default=0)

    findings = db.relationship(
        "FindingRecord", backref="audit", cascade="all, delete-orphan"
    )


class FindingRecord(db.Model):  # type: ignore[name-defined]
    __tablename__ = "finding_records"

    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(
        db.Integer, db.ForeignKey("audit_records.id"), nullable=False
    )
    rule_id = db.Column(db.String(20), nullable=False)
    severity = db.Column(db.String(10), nullable=False)
    description = db.Column(db.Text, nullable=False)
    remediation = db.Column(db.Text, nullable=False)
    config_line = db.Column(db.Text, nullable=True)
