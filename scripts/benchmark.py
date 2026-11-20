"""Reproducible throughput benchmark for PS06 Cybersecurity Triage."""

from __future__ import annotations

from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models import AlertInput
from src.triage_engine import classify_text, enrich_iocs, triage_batch


def build_storm_alerts(count: int) -> list[AlertInput]:
    ips = ("185.220.101.42", "91.240.118.172", "198.51.100.10", "10.0.1.15")
    hosts = ("prod-db-01", "payments-api-01", "workstation-04", "backup-srv-02", "dc-primary-01")
    templates = (
        ("SSH Brute Force", "Repeated failed logins on port 22"),
        ("SQL Injection Attempt", "UNION SELECT payload detected in query parameter"),
        ("PowerShell EncodedCommand", "Suspicious powershell reverse shell execution"),
        ("Scheduled Backup Health Check", "Routine maintenance window scan"),
    )
    return [
        AlertInput(
            alert_id=f"STORM-{i}",
            title=templates[i % 4][0],
            description=templates[i % 4][1],
            source_ip=ips[i % 4],
            dest_host=hosts[i % 5],
            category=f"cat-{i % 4}",
            raw_severity="high" if i % 4 != 3 else "low",
            timestamp="2026-11-20T12:00:00Z",
        )
        for i in range(count)
    ]


def build_unique_alerts(count: int) -> list[AlertInput]:
    return [
        AlertInput(
            alert_id=f"UNIQ-{i}",
            title=f"Alert event #{i} powershell or failed logins",
            description=f"Unique telemetry payload nonce={i} observed on host-{i % 25}",
            source_ip=f"198.51.100.{i % 250}",
            dest_host=f"host-{i % 25}",
            category="edr",
            raw_severity="medium",
            timestamp="2026-11-20T12:00:00Z",
        )
        for i in range(count)
    ]


def measure(label: str, alerts: list[AlertInput], runs: int = 3) -> None:
    best_ms = float("inf")
    for _ in range(runs):
        classify_text.cache_clear()
        enrich_iocs.cache_clear()
        t0 = time.perf_counter()
        triage_batch(alerts)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        best_ms = min(best_ms, elapsed_ms)
    rate = int(len(alerts) / (best_ms / 1000.0))
    print(f"{label:42s} | {best_ms:8.2f} ms | ~{rate:,} alerts/s")


def main() -> None:
    print("PS06 Cybersecurity Triage Benchmark (best of 3, cold cache)")
    print("-" * 72)
    for n in (10_000, 100_000):
        measure(f"Repetitive storm ({n:,} alerts)", build_storm_alerts(n))
    for n in (10_000, 100_000):
        measure(f"Unique text worst-case ({n:,} alerts)", build_unique_alerts(n))


if __name__ == "__main__":
    main()
