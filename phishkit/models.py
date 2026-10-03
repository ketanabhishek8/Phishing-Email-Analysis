"""Shared data types used by every analysis module."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Severity of a finding. The value is its weight in the risk score."""

    INFO = 0
    LOW = 5
    MEDIUM = 15
    HIGH = 30
    CRITICAL = 50

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    """A single observation about the email, with an analyst-facing explanation."""

    category: str
    severity: Severity
    title: str
    detail: str = ""
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity.label,
            "weight": int(self.severity),
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class Report:
    """The full result of analysing one email."""

    summary: dict = field(default_factory=dict)
    auth: dict = field(default_factory=dict)
    senders: dict = field(default_factory=dict)
    urls: list[dict] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)
    received: list[dict] = field(default_factory=list)
    body_preview: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "Clean"

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "verdict": self.verdict,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "auth": self.auth,
            "senders": self.senders,
            "urls": self.urls,
            "attachments": self.attachments,
            "received": self.received,
            "body_preview": self.body_preview,
        }
