"""Finding data model — represents a detected vulnerability."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        weights = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return weights[self.value]


class Confidence(Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNVERIFIED = "unverified"


class Status(Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NOT_REPRODUCED = "not_reproduced"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str
    confidence: Confidence = Confidence.UNVERIFIED
    status: Status = Status.OPEN
    evidence_static: Optional[str] = None
    evidence_dynamic: Optional[str] = None
    masvs_category: Optional[str] = None
    mastg_test: Optional[str] = None
    business_impact: Optional[str] = None
    poc: Optional[str] = None
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confirmed_at: Optional[datetime] = None

    def confirm(self, evidence: str) -> None:
        self.confidence = Confidence.CONFIRMED
        self.status = Status.CONFIRMED
        self.evidence_dynamic = evidence
        self.confirmed_at = datetime.now(timezone.utc)

    def mark_false_positive(self, reason: str) -> None:
        self.status = Status.FALSE_POSITIVE
        self.evidence_dynamic = f"FP: {reason}"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "status": self.status.value,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "evidence_static": self.evidence_static,
            "evidence_dynamic": self.evidence_dynamic,
            "masvs_category": self.masvs_category,
            "mastg_test": self.mastg_test,
            "business_impact": self.business_impact,
            "poc": self.poc,
            "detected_at": self.detected_at.isoformat(),
            "confirmed_at": self.confirmed_at.isoformat() if self.confirmed_at else None,
        }
