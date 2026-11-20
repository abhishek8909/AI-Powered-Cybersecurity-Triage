"""Efficiency and Big-O linear scaling benchmark tests for the triage engine."""

from __future__ import annotations

import time
import unittest

from src.models import AlertInput
from src.triage_engine import classify_text, enrich_iocs, triage_batch


def _generate_storm_alerts(count: int) -> list[AlertInput]:
    ips = ("185.220.101.42", "91.240.118.172", "198.51.100.10", "10.0.1.15")
    hosts = ("prod-db-01", "payments-api-01", "workstation-04", "backup-srv-02", "dc-primary-01")
    titles = (
        ("SSH Brute Force", "Repeated failed logins on port 22"),
        ("SQL Injection Attempt", "UNION SELECT payload detected in query parameter"),
        ("PowerShell EncodedCommand", "Suspicious powershell reverse shell execution"),
        ("Scheduled Backup Health Check", "Routine maintenance window scan"),
    )
    return [
        AlertInput(
            alert_id=f"STORM-{i}",
            title=titles[i % 4][0],
            description=titles[i % 4][1],
            source_ip=ips[i % 4],
            dest_host=hosts[i % 5],
            category=f"cat-{i % 4}",
            raw_severity="high" if i % 4 != 3 else "low",
            timestamp="2026-11-20T12:00:00Z",
        )
        for i in range(count)
    ]


def _generate_unique_alerts(count: int) -> list[AlertInput]:
    return [
        AlertInput(
            alert_id=f"UNIQ-{i}",
            title=f"Event #{i} powershell execution",
            description=f"Unique payload nonce={i} on host-{i % 20}",
            source_ip=f"198.51.100.{i % 250}",
            dest_host=f"host-{i % 20}",
            category="edr",
            raw_severity="medium",
            timestamp="2026-11-20T12:00:00Z",
        )
        for i in range(count)
    ]


class TestEfficiency(unittest.TestCase):
    def test_ten_thousand_storm_alerts_triage_fast(self) -> None:
        classify_text.cache_clear()
        enrich_iocs.cache_clear()
        alerts = _generate_storm_alerts(10_000)
        start = time.perf_counter()
        result = triage_batch(alerts)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        self.assertEqual(result.total_alerts_ingested, 10_000)
        self.assertLessEqual(result.unique_incidents, 20)
        self.assertGreater(result.noise_reduction_pct, 99.0)
        self.assertLess(elapsed_ms, 500.0, f"10k storm took {elapsed_ms:.2f}ms")

    def test_linear_time_scaling_repetitive_storm(self) -> None:
        small = _generate_storm_alerts(1_000)
        large = _generate_storm_alerts(5_000)

        classify_text.cache_clear()
        t0 = time.perf_counter()
        triage_batch(small)
        t_small = max(time.perf_counter() - t0, 1e-6)

        classify_text.cache_clear()
        t1 = time.perf_counter()
        triage_batch(large)
        t_large = time.perf_counter() - t1

        self.assertLess(t_large / t_small, 12.0)

    def test_linear_time_scaling_unique_text(self) -> None:
        small = _generate_unique_alerts(1_000)
        large = _generate_unique_alerts(5_000)

        classify_text.cache_clear()
        t0 = time.perf_counter()
        triage_batch(small)
        t_small = max(time.perf_counter() - t0, 1e-6)

        classify_text.cache_clear()
        t1 = time.perf_counter()
        triage_batch(large)
        t_large = time.perf_counter() - t1

        self.assertLess(t_large / t_small, 12.0)

    def test_classification_lru_cache_is_bounded(self) -> None:
        classify_text.cache_clear()
        triage_batch(_generate_unique_alerts(5_000))
        info = classify_text.cache_info()
        self.assertLessEqual(info.currsize, 4096)


if __name__ == "__main__":
    unittest.main()
