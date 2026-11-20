"""Typed, memory-efficient data models for PS06 Cybersecurity Triage."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class AlertInput:
    """Normalized cybersecurity alert payload."""

    alert_id: str
    title: str
    description: str
    source_ip: str = ""
    dest_host: str = ""
    user: str = ""
    domain: str = ""
    file_hash: str = ""
    category: str = "general"
    raw_severity: str = "medium"
    timestamp: str = ""


@dataclass(slots=True, frozen=True)
class MitreMapping:
    """MITRE ATT&CK tactic and technique mapping."""

    tactic: str
    technique_id: str
    technique_name: str


@dataclass(slots=True, frozen=True)
class AIAnalysis:
    """AI-generated triage summary and containment guidance."""

    provider: str
    summary: str
    root_cause_hypothesis: str
    false_positive_likelihood: str
    recommended_actions: tuple[str, ...]


@dataclass(slots=True, frozen=True)
class ResponseStep:
    """Proposed incident response action (never auto-executed)."""

    action: str
    requires_human_approval: bool
    category: str


@dataclass(slots=True, frozen=True)
class AgentTraceStep:
    """Auditable step in the 6-stage triage agent reasoning trace."""

    stage: str
    detail: str


@dataclass(slots=True, frozen=True)
class TriageIncident:
    """Triaged, deduplicated, and agent-evaluated security incident."""

    incident_id: str
    fingerprint: str
    title: str
    severity: str
    risk_score: int
    confidence: float
    occurrence_count: int
    alert_ids: tuple[str, ...]
    source_ip: str
    dest_host: str
    user: str
    matched_iocs: tuple[str, ...]
    mitre: tuple[MitreMapping, ...]
    score_factors: tuple[str, ...]
    ai_analysis: AIAnalysis
    decision: str
    response_plan: tuple[ResponseStep, ...]
    agent_trace: tuple[AgentTraceStep, ...]
    first_seen: str
    last_seen: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize incident to a JSON-safe dictionary."""
        return asdict(self)


@dataclass(slots=True, frozen=True)
class BatchTriageSummary:
    """Aggregate summary metrics for a batch triage run."""

    total_alerts_ingested: int
    unique_incidents: int
    duplicates_suppressed: int
    noise_reduction_pct: float
    severity_counts: dict[str, int]
    processing_time_ms: float
    incidents: tuple[TriageIncident, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Serialize batch triage response to a JSON-safe dictionary."""
        return {
            "total_alerts_ingested": self.total_alerts_ingested,
            "unique_incidents": self.unique_incidents,
            "duplicates_suppressed": self.duplicates_suppressed,
            "noise_reduction_pct": self.noise_reduction_pct,
            "severity_counts": self.severity_counts,
            "processing_time_ms": self.processing_time_ms,
            "incidents": [inc.to_dict() for inc in self.incidents],
        }
