"""Pydantic models for audit findings and reports."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    description: str
    remediation: str
    config_line: str | None = None


class AuditReport(BaseModel):
    hostname: str = "unknown"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding] = Field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        counts["TOTAL"] = len(self.findings)
        return counts
