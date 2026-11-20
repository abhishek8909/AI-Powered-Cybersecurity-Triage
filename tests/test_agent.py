"""Unit tests for the 6-step SOC triage agent decision table, approval flags, and trace."""

from __future__ import annotations

import unittest

from src.agent import decide_action, run_triage_agent
from src.models import AIAnalysis, MitreMapping


class TestTriageAgent(unittest.TestCase):
    def test_decision_table_covers_all_five_dispositions(self) -> None:
        mitre = (MitreMapping("Initial Access", "T1190", "Exploit Public-Facing Application"),)
        self.assertEqual(decide_action("CRITICAL", 90, (), "Low", mitre), "CONTAIN_PENDING_APPROVAL")
        self.assertEqual(decide_action("HIGH", 70, ("malicious_ip:1.2.3.4",), "Low", mitre), "CONTAIN_PENDING_APPROVAL")
        self.assertEqual(decide_action("HIGH", 68, (), "Medium", mitre), "ESCALATE_TIER2")
        self.assertEqual(decide_action("MEDIUM", 45, (), "Medium", ()), "INVESTIGATE")
        self.assertEqual(decide_action("LOW", 10, (), "High", ()), "AUTO_CLOSE_BENIGN")
        self.assertEqual(decide_action("LOW", 25, (), "Medium", ()), "MONITOR")

    def test_containment_steps_always_flagged_for_human_approval(self) -> None:
        analysis = AIAnalysis(
            provider="deterministic-soc-engine",
            summary="Critical incident",
            root_cause_hypothesis="SQLi exploit",
            false_positive_likelihood="Low",
            recommended_actions=(
                "Isolate affected host via EDR immediately.",
                "Inspect web access logs for payload execution.",
                "Block source IP at perimeter firewall.",
            ),
        )
        decision, plan, _ = run_triage_agent(
            title="SQLi",
            severity="CRITICAL",
            risk_score=95,
            occurrence_count=3,
            matched_iocs=("malicious_ip:185.220.101.42",),
            mitre=(),
            ai_analysis=analysis,
            dest_host="payments-api-01",
            source_ip="185.220.101.42",
        )
        self.assertEqual(decision, "CONTAIN_PENDING_APPROVAL")
        self.assertTrue(plan[0].requires_human_approval)
        self.assertEqual(plan[0].category, "containment")
        self.assertFalse(plan[1].requires_human_approval)
        self.assertEqual(plan[1].category, "investigation")
        self.assertTrue(plan[2].requires_human_approval)

    def test_six_stage_auditable_trace_order(self) -> None:
        analysis = AIAnalysis(
            provider="deterministic-soc-engine",
            summary="Summary",
            root_cause_hypothesis="Hypothesis",
            false_positive_likelihood="Medium",
            recommended_actions=("Inspect telemetry.",),
        )
        _, _, trace = run_triage_agent(
            title="Suspicious Login",
            severity="MEDIUM",
            risk_score=45,
            occurrence_count=1,
            matched_iocs=(),
            mitre=(),
            ai_analysis=analysis,
            dest_host="auth-gw",
            source_ip="198.51.100.12",
        )
        stages = [step.stage for step in trace]
        self.assertEqual(stages, ["Observe", "Enrich", "Reason", "Plan", "Decide", "Propose"])
        self.assertIn("no automated containment executed", trace[-1].detail)


if __name__ == "__main__":
    unittest.main()
