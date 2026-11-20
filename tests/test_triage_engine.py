"""Unit tests for the O(n) triage engine, 18 MITRE rules, evasion resistance, and bounded LLM use."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from src.models import AIAnalysis, AlertInput
from src.sample_data import SAMPLE_ALERTS
from src.security import parse_alert_input
from src.triage_engine import MAX_LLM_INCIDENTS, _DETECTION_RULES, triage_batch


class TestTriageEngine(unittest.TestCase):
    def test_eighteen_mitre_rules_registered(self) -> None:
        self.assertEqual(len(_DETECTION_RULES), 18)
        technique_ids = {mapping.technique_id for _, _, _, mapping in _DETECTION_RULES}
        expected = {
            "T1110", "T1190", "T1505.003", "T1059", "T1105", "T1071",
            "T1041", "T1074", "T1003", "T1558", "T1068", "T1548.003",
            "T1098", "T1566", "T1078", "T1621", "T1486", "T1490",
        }
        self.assertEqual(technique_ids, expected)

    def test_sample_stream_deduplication_and_prioritization(self) -> None:
        parsed = [parse_alert_input(item, idx) for idx, item in enumerate(SAMPLE_ALERTS)]
        result = triage_batch(parsed)

        self.assertEqual(result.total_alerts_ingested, 8)
        self.assertEqual(result.unique_incidents, 6)
        self.assertEqual(result.duplicates_suppressed, 2)
        self.assertGreater(result.noise_reduction_pct, 0.0)

        scores = [inc.risk_score for inc in result.incidents]
        self.assertEqual(scores, sorted(scores, reverse=True))

        top = result.incidents[0]
        self.assertEqual(top.severity, "CRITICAL")
        self.assertEqual(top.decision, "CONTAIN_PENDING_APPROVAL")
        self.assertEqual(len(top.agent_trace), 6)
        self.assertTrue(any(step.requires_human_approval for step in top.response_plan))

    def test_benign_maintenance_noise_is_deprioritized_and_auto_closed(self) -> None:
        benign = AlertInput(
            alert_id="NOISE-1",
            title="Scheduled Backup Health Check",
            description="Routine maintenance window health check completed.",
            source_ip="10.0.0.5",
            dest_host="backup-srv-01",
            raw_severity="low",
        )
        result = triage_batch([benign])
        inc = result.incidents[0]
        self.assertEqual(inc.severity, "LOW")
        self.assertLessEqual(inc.risk_score, 15)
        self.assertEqual(inc.decision, "AUTO_CLOSE_BENIGN")

    def test_evasion_resistance_blocks_benign_keyword_stuffing(self) -> None:
        evasive = AlertInput(
            alert_id="EVADE-1",
            title="SQL Injection during scheduled backup maintenance window",
            description="UNION SELECT payload disguised as health check",
            source_ip="198.51.100.99",
            dest_host="app-srv-01",
            raw_severity="high",
        )
        result = triage_batch([evasive])
        inc = result.incidents[0]
        self.assertFalse(any("-25" in f for f in inc.score_factors))
        self.assertGreaterEqual(inc.risk_score, 60)
        self.assertIn(inc.severity, {"HIGH", "CRITICAL"})

    def test_mitre_mapping_for_credential_dumping_and_kerberos(self) -> None:
        alert = AlertInput(
            alert_id="CRED-1",
            title="Mimikatz LSASS Dump and Golden Ticket Forgery",
            description="Detected lsass access and golden ticket creation on domain controller.",
            dest_host="dc-primary-01",
            raw_severity="critical",
        )
        inc = triage_batch([alert]).incidents[0]
        ids = {m.technique_id for m in inc.mitre}
        self.assertIn("T1003", ids)
        self.assertIn("T1558", ids)

    def test_mitre_mapping_for_sudo_and_account_manipulation(self) -> None:
        alert = AlertInput(
            alert_id="PRIV-1",
            title="Sudoers Modified and Admin Group Added",
            description="Unauthorized nopasswd added and admin group added for temp user.",
            dest_host="linux-app-01",
            raw_severity="high",
        )
        inc = triage_batch([alert]).incidents[0]
        ids = {m.technique_id for m in inc.mitre}
        self.assertIn("T1548.003", ids)
        self.assertIn("T1098", ids)

    def test_mitre_mapping_for_mfa_fatigue_and_recovery_inhibition(self) -> None:
        a1 = AlertInput(
            alert_id="MFA-1",
            title="MFA Fatigue Attack",
            description="Repeated mfa bombing prompts sent to executive user.",
            raw_severity="high",
        )
        a2 = AlertInput(
            alert_id="REC-1",
            title="Backup Wipe via vssadmin",
            description="Shadow copy delete executed on file server.",
            raw_severity="critical",
        )
        r1 = triage_batch([a1]).incidents[0]
        r2 = triage_batch([a2]).incidents[0]
        self.assertIn("T1621", {m.technique_id for m in r1.mitre})
        self.assertIn("T1490", {m.technique_id for m in r2.mitre})

    def test_alert_storm_burst_escalation(self) -> None:
        burst = [
            AlertInput(
                alert_id=f"BF-{i}",
                title="SSH Brute Force",
                description="Repeated failed logins detected",
                source_ip="198.51.100.77",
                dest_host="app-node-02",
                category="auth",
                raw_severity="medium",
                timestamp=f"2026-11-20T10:00:{i:02d}Z",
            )
            for i in range(6)
        ]
        result = triage_batch(burst)
        self.assertEqual(result.unique_incidents, 1)
        inc = result.incidents[0]
        self.assertEqual(inc.occurrence_count, 6)
        self.assertTrue(any("Alert storm correlation" in f for f in inc.score_factors))
        self.assertEqual(inc.mitre[0].technique_id, "T1110")

    def test_llm_enrichment_bounded_to_top_five_incidents(self) -> None:
        alerts = [
            AlertInput(
                alert_id=f"CRIT-{i}",
                title=f"SQL Injection #{i}",
                description="UNION SELECT payload",
                source_ip=f"198.51.100.{i + 1}",
                dest_host=f"prod-db-01",
                category=f"web-{i}",
                raw_severity="critical",
            )
            for i in range(8)
        ]
        fake_ai = AIAnalysis(
            provider="gemini-api",
            summary="Mocked LLM summary",
            root_cause_hypothesis="Mocked root cause",
            false_positive_likelihood="Low",
            recommended_actions=("Isolate service.",),
        )
        llm_calls = 0

        def fake_analyze(**kwargs: object) -> AIAnalysis:
            nonlocal llm_calls
            if kwargs.get("use_external_llm"):
                llm_calls += 1
                return fake_ai
            return AIAnalysis(
                provider="deterministic-soc-engine",
                summary="Fallback",
                root_cause_hypothesis="Fallback",
                false_positive_likelihood="Low",
                recommended_actions=("Inspect logs.",),
            )

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}), patch(
            "src.triage_engine.analyze_incident", side_effect=fake_analyze
        ):
            result = triage_batch(alerts, use_external_llm=True)

        self.assertEqual(result.unique_incidents, 8)
        self.assertEqual(llm_calls, MAX_LLM_INCIDENTS)

    def test_empty_batch_returns_zero_metrics(self) -> None:
        result = triage_batch([])
        self.assertEqual(result.total_alerts_ingested, 0)
        self.assertEqual(result.unique_incidents, 0)
        self.assertEqual(result.noise_reduction_pct, 0.0)


if __name__ == "__main__":
    unittest.main()
