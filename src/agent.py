"""Six-step auditable SOC triage agent: Observe -> Enrich -> Reason -> Plan -> Decide -> Propose.

No response action is ever executed automatically; containment steps are explicitly
flagged with requires_human_approval=True.
"""

from __future__ import annotations

from src.models import AIAnalysis, AgentTraceStep, MitreMapping, ResponseStep

# Actions that change infrastructure, network, or identity state require human sign-off.
_CONTAINMENT_KEYWORDS = (
    "block",
    "isolate",
    "quarantine",
    "revoke",
    "disable",
    "sinkhole",
    "purge",
    "force",
    "rotate",
    "patch",
    "containment",
    "re-image",
    "terminate",
)


def _needs_approval(action: str) -> tuple[bool, str]:
    lower = action.lower()
    if any(kw in lower for kw in _CONTAINMENT_KEYWORDS):
        return True, "containment"
    return False, "investigation"


def decide_action(
    severity: str,
    risk_score: int,
    matched_iocs: tuple[str, ...],
    false_positive_likelihood: str,
    mitre: tuple[MitreMapping, ...],
) -> str:
    """Select one deterministic SOC triage decision from verified signals."""
    if severity == "CRITICAL" or (severity == "HIGH" and matched_iocs):
        return "CONTAIN_PENDING_APPROVAL"
    if severity == "HIGH":
        return "ESCALATE_TIER2"
    if severity == "MEDIUM":
        return "INVESTIGATE"
    if risk_score <= 15 and not matched_iocs and not mitre and false_positive_likelihood == "High":
        return "AUTO_CLOSE_BENIGN"
    return "MONITOR"


def run_triage_agent(
    title: str,
    severity: str,
    risk_score: int,
    occurrence_count: int,
    matched_iocs: tuple[str, ...],
    mitre: tuple[MitreMapping, ...],
    ai_analysis: AIAnalysis,
    dest_host: str,
    source_ip: str,
) -> tuple[str, tuple[ResponseStep, ...], tuple[AgentTraceStep, ...]]:
    """Run the 6-stage triage agent and return (decision, response_plan, agent_trace)."""
    decision = decide_action(
        severity=severity,
        risk_score=risk_score,
        matched_iocs=matched_iocs,
        false_positive_likelihood=ai_analysis.false_positive_likelihood,
        mitre=mitre,
    )

    response_plan = tuple(
        ResponseStep(
            action=step,
            requires_human_approval=needs_approval,
            category=category,
        )
        for step in ai_analysis.recommended_actions
        for needs_approval, category in (_needs_approval(step),)
    )

    approval_count = sum(1 for step in response_plan if step.requires_human_approval)
    mitre_ids = ", ".join(m.technique_id for m in mitre) if mitre else "none"
    ioc_summary = ", ".join(matched_iocs) if matched_iocs else "none"

    trace = (
        AgentTraceStep(
            stage="Observe",
            detail=(
                f"Consolidated {occurrence_count} alert(s) for '{title}' "
                f"(source={source_ip or 'N/A'}, host={dest_host or 'N/A'})."
            ),
        ),
        AgentTraceStep(
            stage="Enrich",
            detail=f"IOC hits: {ioc_summary}; MITRE ATT&CK: {mitre_ids}.",
        ),
        AgentTraceStep(
            stage="Reason",
            detail=(
                f"Provider={ai_analysis.provider}; risk={risk_score}/100 ({severity}); "
                f"FP likelihood={ai_analysis.false_positive_likelihood}."
            ),
        ),
        AgentTraceStep(
            stage="Plan",
            detail=(
                f"Assembled {len(response_plan)} response step(s) "
                f"({approval_count} requiring human approval)."
            ),
        ),
        AgentTraceStep(
            stage="Decide",
            detail=f"Selected disposition: {decision}.",
        ),
        AgentTraceStep(
            stage="Propose",
            detail=(
                "Proposal queued for SOC analyst review; no automated containment executed."
            ),
        ),
    )

    return decision, response_plan, trace
