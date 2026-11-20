"""High-efficiency O(n) cybersecurity alert triage, deduplication, and enrichment engine.

Complexity guarantees for N alerts and K unique deduplicated incidents (K <= N):
- IOC matching & asset criticality lookup: O(1) via frozenset/dict + LRU cache.
- Text rule classification: O(R*L) per distinct alert text (R=18 rules), memoised in 4,096-entry LRU cache.
- Batch ingestion, deduplication & severity bucketing: O(N) single pass.
- Incident prioritization: O(K log K) on deduplicated incidents only.
- Optional LLM enrichment: bounded to top MAX_LLM_INCIDENTS (5) and executed concurrently.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import hashlib
import os
import re
import time
from typing import Iterable

from src.agent import run_triage_agent
from src.ai_analyst import analyze_incident
from src.models import AIAnalysis, AlertInput, BatchTriageSummary, MitreMapping, TriageIncident

MAX_LLM_INCIDENTS = 5

# O(1) Threat Intelligence IOC lookup tables (demo data).
MALICIOUS_IPS: frozenset[str] = frozenset({
    "185.220.101.42",
    "45.155.205.233",
    "91.240.118.172",
    "194.26.135.88",
    "203.0.113.66",
})

MALICIOUS_DOMAINS: frozenset[str] = frozenset({
    "c2-update-sync.evil-net.example",
    "login-verify-corp.phish.example",
    "exfil-drop.darkrelay.example",
    "payload-cdn.malicious.example",
})

MALICIOUS_HASHES: frozenset[str] = frozenset({
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "44d88612fea8a8f36de82e1278abb02f",
    "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
})

CRITICAL_ASSETS: frozenset[str] = frozenset({
    "prod-db-01",
    "dc-primary-01",
    "auth-gateway-prod",
    "payments-api-01",
    "k8s-control-plane",
})

RAW_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 45,
    "high": 32,
    "medium": 18,
    "low": 8,
    "info": 2,
}

# 18 pre-compiled linear-time detection rules mapped to MITRE ATT&CK.
_DETECTION_RULES: tuple[tuple[str, re.Pattern[str], int, MitreMapping], ...] = (
    (
        "credential_brute_force",
        re.compile(r"\b(brute[\s-]?force|failed\s+logins?|password\s+spray|credential\s+stuffing)\b", re.IGNORECASE),
        22,
        MitreMapping("Credential Access", "T1110", "Brute Force"),
    ),
    (
        "public_app_exploit",
        re.compile(r"\b(sql\s+injection|sqli|union\s+select|remote\s+code\s+execution|rce|path\s+traversal)\b", re.IGNORECASE),
        34,
        MitreMapping("Initial Access", "T1190", "Exploit Public-Facing Application"),
    ),
    (
        "webshell_implant",
        re.compile(r"\b(webshell|web\s+shell|malicious\s+jsp|php\s+backdoor)\b", re.IGNORECASE),
        34,
        MitreMapping("Persistence", "T1505.003", "Web Shell"),
    ),
    (
        "command_execution",
        re.compile(r"\b(powershell|encodedcommand|reverse\s+shell|bash\s+-i|certutil|cmd\.exe)\b", re.IGNORECASE),
        30,
        MitreMapping("Execution", "T1059", "Command and Scripting Interpreter"),
    ),
    (
        "ingress_tool_transfer",
        re.compile(r"\b(curl\s+http|wget\s+http|bitsadmin|payload\s+download|dropper\s+fetch)\b", re.IGNORECASE),
        24,
        MitreMapping("Command and Control", "T1105", "Ingress Tool Transfer"),
    ),
    (
        "app_layer_c2",
        re.compile(r"\b(c2\s+beacon|beaconing|dns\s+tunneling|http\s+c2)\b", re.IGNORECASE),
        28,
        MitreMapping("Command and Control", "T1071", "Application Layer Protocol"),
    ),
    (
        "data_exfiltration",
        re.compile(r"\b(exfiltration|unusual\s+outbound|bulk\s+egress|data\s+leak)\b", re.IGNORECASE),
        32,
        MitreMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    ),
    (
        "data_staging",
        re.compile(r"\b(data\s+staging|archive\s+staged|tar\s+dump|zip\s+exfil)\b", re.IGNORECASE),
        22,
        MitreMapping("Collection", "T1074", "Data Staged"),
    ),
    (
        "credential_dumping",
        re.compile(r"\b(mimikatz|lsass|credential\s+dump|sam\s+hive|ntds\.dit)\b", re.IGNORECASE),
        36,
        MitreMapping("Credential Access", "T1003", "OS Credential Dumping"),
    ),
    (
        "kerberos_ticket_abuse",
        re.compile(r"\b(golden\s+ticket|silver\s+ticket|kerberoasting|as-rep\s+roast)\b", re.IGNORECASE),
        34,
        MitreMapping("Credential Access", "T1558", "Steal or Forge Kerberos Tickets"),
    ),
    (
        "privilege_escalation",
        re.compile(r"\b(privilege\s+escalation|kernel\s+exploit|local\s+root\s+exploit)\b", re.IGNORECASE),
        32,
        MitreMapping("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    ),
    (
        "sudo_abuse",
        re.compile(r"\b(sudoers|sudo\s+abuse|nopasswd\s+added)\b", re.IGNORECASE),
        28,
        MitreMapping("Privilege Escalation", "T1548.003", "Sudo and Sudo Caching"),
    ),
    (
        "account_manipulation",
        re.compile(r"\b(admin\s+group\s+added|unauthorized\s+iam\s+role|ssh\s+authorized_keys\s+modified)\b", re.IGNORECASE),
        26,
        MitreMapping("Persistence", "T1098", "Account Manipulation"),
    ),
    (
        "phishing_delivery",
        re.compile(r"\b(phishing|malicious\s+attachment|spoofed\s+sender|credential\s+harvest)\b", re.IGNORECASE),
        24,
        MitreMapping("Initial Access", "T1566", "Phishing"),
    ),
    (
        "valid_accounts_abuse",
        re.compile(r"\b(impossible\s+travel|anomalous\s+sso|compromised\s+account)\b", re.IGNORECASE),
        24,
        MitreMapping("Defense Evasion", "T1078", "Valid Accounts"),
    ),
    (
        "mfa_fatigue",
        re.compile(r"\b(mfa\s+fatigue|mfa\s+bombing|suspicious\s+mfa)\b", re.IGNORECASE),
        26,
        MitreMapping("Credential Access", "T1621", "Multi-Factor Authentication Request Generation"),
    ),
    (
        "ransomware_encryption",
        re.compile(r"\b(ransomware|mass\s+encryption|file\s+locker)\b", re.IGNORECASE),
        40,
        MitreMapping("Impact", "T1486", "Data Encrypted for Impact"),
    ),
    (
        "inhibit_recovery",
        re.compile(r"\b(shadow\s+copy\s+delete|vssadmin|wbadmin\s+delete|backup\s+wipe)\b", re.IGNORECASE),
        38,
        MitreMapping("Impact", "T1490", "Inhibit System Recovery"),
    ),
)

_BENIGN_NOISE_RE = re.compile(
    r"\b(scheduled\s+backup|health\s*check|vulnerability\s+scanner|authorized\s+pentest|maintenance\s+window)\b",
    re.IGNORECASE,
)


@lru_cache(maxsize=4096)
def enrich_iocs(source_ip: str, domain: str, file_hash: str) -> tuple[tuple[str, ...], int]:
    """Perform O(1) cached threat-intelligence IOC enrichment."""
    hits: list[str] = []
    bonus = 0
    if source_ip and source_ip in MALICIOUS_IPS:
        hits.append(f"malicious_ip:{source_ip}")
        bonus += 28
    if domain and domain in MALICIOUS_DOMAINS:
        hits.append(f"malicious_domain:{domain}")
        bonus += 26
    if file_hash and file_hash in MALICIOUS_HASHES:
        hits.append(f"malicious_hash:{file_hash[:12]}...")
        bonus += 32
    return tuple(hits), bonus


@lru_cache(maxsize=4096)
def classify_text(title: str, description: str) -> tuple[int, tuple[str, ...], tuple[MitreMapping, ...], tuple[str, ...], bool]:
    """Memoised O(R*L) classification of distinct alert text across all 18 rules."""
    combined = f"{title} {description}"
    rule_score = 0
    rule_names: list[str] = []
    mitre_hits: list[MitreMapping] = []
    rule_factors: list[str] = []

    for rule_name, pattern, weight, mapping in _DETECTION_RULES:
        if pattern.search(combined):
            rule_score += weight
            rule_names.append(rule_name)
            mitre_hits.append(mapping)
            rule_factors.append(f"Rule {mapping.technique_id} ({mapping.technique_name}): +{weight}")

    looks_benign = bool(_BENIGN_NOISE_RE.search(combined))
    return rule_score, tuple(rule_names), tuple(mitre_hits), tuple(rule_factors), looks_benign


def _compute_fingerprint(alert: AlertInput, rule_names: tuple[str, ...]) -> str:
    """Create deterministic deduplication fingerprint in O(1)."""
    key = "|".join((
        alert.source_ip or "no-ip",
        alert.dest_host.lower() or "no-host",
        alert.category.lower(),
        ",".join(rule_names) if rule_names else alert.title.lower()[:48],
    ))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _severity_from_score(score: int) -> str:
    """Map numeric risk score (0-100) to SOC severity tier."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def _classify_alert(alert: AlertInput) -> tuple[int, tuple[str, ...], tuple[MitreMapping, ...], tuple[str, ...], tuple[str, ...]]:
    """Evaluate a single alert using memoised text rules, O(1) IOCs, and asset criticality."""
    base = RAW_SEVERITY_WEIGHTS.get(alert.raw_severity, 18)
    rule_score, rule_names, mitre_hits, rule_factors, looks_benign = classify_text(alert.title, alert.description)

    score = base + rule_score
    factors: list[str] = [f"Base severity ({alert.raw_severity}): +{base}"]
    if rule_factors:
        factors.extend(rule_factors)

    ioc_hits, ioc_bonus = enrich_iocs(alert.source_ip, alert.domain, alert.file_hash)
    if ioc_bonus:
        score += ioc_bonus
        factors.append(f"Threat intel IOC match ({len(ioc_hits)} hit{'s' if len(ioc_hits) > 1 else ''}): +{ioc_bonus}")

    if alert.dest_host.lower() in CRITICAL_ASSETS:
        score += 15
        factors.append(f"Critical asset target ({alert.dest_host}): +15")

    # Evasion-resistant benign discount: NEVER apply if any threat rule or IOC matched.
    if looks_benign and not ioc_hits and not rule_names:
        score = max(5, score - 25)
        factors.append("Likely authorized/maintenance activity: -25")

    clamped_score = max(0, min(100, score))
    return clamped_score, rule_names, mitre_hits, ioc_hits, tuple(factors)


def triage_batch(alerts: Iterable[AlertInput], use_external_llm: bool = False) -> BatchTriageSummary:
    """Triage, deduplicate, score, enrich, and agent-evaluate alerts in O(N) single pass."""
    start = time.perf_counter()

    groups: dict[str, dict[str, object]] = {}
    total_ingested = 0

    for alert in alerts:
        total_ingested += 1
        score, rule_names, mitre_hits, ioc_hits, factors = _classify_alert(alert)
        fp = _compute_fingerprint(alert, rule_names)

        bucket = groups.get(fp)
        if bucket is None:
            groups[fp] = {
                "alert": alert,
                "score": score,
                "mitre": mitre_hits,
                "iocs": set(ioc_hits),
                "factors": list(factors),
                "alert_ids": [alert.alert_id],
                "first_seen": alert.timestamp,
                "last_seen": alert.timestamp,
            }
        else:
            alert_ids: list[str] = bucket["alert_ids"]  # type: ignore[assignment]
            alert_ids.append(alert.alert_id)
            if score > bucket["score"]:  # type: ignore[operator]
                bucket["score"] = score
                bucket["alert"] = alert
                bucket["mitre"] = mitre_hits
                bucket["factors"] = list(factors)
            if ioc_hits:
                iocs_set: set[str] = bucket["iocs"]  # type: ignore[assignment]
                iocs_set.update(ioc_hits)
            if alert.timestamp:
                if not bucket["first_seen"] or alert.timestamp < bucket["first_seen"]:  # type: ignore[operator]
                    bucket["first_seen"] = alert.timestamp
                if not bucket["last_seen"] or alert.timestamp > bucket["last_seen"]:  # type: ignore[operator]
                    bucket["last_seen"] = alert.timestamp

    # Prepare deduplicated candidate records and sort before LLM capping.
    prepared: list[dict[str, object]] = []
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for fp, bucket in groups.items():
        rep_alert: AlertInput = bucket["alert"]  # type: ignore[assignment]
        alert_ids = bucket["alert_ids"]  # type: ignore[assignment]
        count = len(alert_ids)
        score = int(bucket["score"])  # type: ignore[arg-type]
        factors = list(bucket["factors"])  # type: ignore[arg-type]

        if count >= 5:
            burst_bonus = min(12, count)
            score = min(100, score + burst_bonus)
            factors.append(f"Alert storm correlation ({count} correlated events): +{burst_bonus}")

        severity = _severity_from_score(score)
        severity_counts[severity] += 1
        iocs = tuple(sorted(bucket["iocs"]))  # type: ignore[arg-type]
        mitre: tuple[MitreMapping, ...] = bucket["mitre"]  # type: ignore[assignment]
        confidence = round(
            min(0.99, 0.55 + 0.12 * len(mitre) + 0.15 * len(iocs) + (0.08 if count > 1 else 0.0)),
            2,
        )

        prepared.append({
            "fp": fp,
            "alert": rep_alert,
            "alert_ids": tuple(alert_ids),
            "count": count,
            "score": score,
            "severity": severity,
            "iocs": iocs,
            "mitre": mitre,
            "factors": tuple(factors),
            "confidence": confidence,
            "first_seen": str(bucket["first_seen"]),
            "last_seen": str(bucket["last_seen"]),
        })

    prepared.sort(key=lambda item: (-int(item["score"]), -int(item["count"]), str(item["fp"])))  # type: ignore[arg-type]

    # Bounded concurrent LLM enrichment for top MAX_LLM_INCIDENTS high/critical items only.
    llm_enabled = bool(use_external_llm and os.environ.get("GEMINI_API_KEY", "").strip())
    analyses: dict[int, AIAnalysis] = {}

    if llm_enabled:
        llm_indices = [
            i for i, item in enumerate(prepared)
            if item["severity"] in {"CRITICAL", "HIGH"}
        ][:MAX_LLM_INCIDENTS]
        if llm_indices:
            with ThreadPoolExecutor(max_workers=len(llm_indices)) as pool:
                futures = {
                    i: pool.submit(
                        analyze_incident,
                        title=prepared[i]["alert"].title,  # type: ignore[union-attr]
                        description=prepared[i]["alert"].description,  # type: ignore[union-attr]
                        severity=str(prepared[i]["severity"]),
                        risk_score=int(prepared[i]["score"]),  # type: ignore[arg-type]
                        mitre=prepared[i]["mitre"],  # type: ignore[arg-type]
                        matched_iocs=prepared[i]["iocs"],  # type: ignore[arg-type]
                        occurrence_count=int(prepared[i]["count"]),  # type: ignore[arg-type]
                        dest_host=prepared[i]["alert"].dest_host,  # type: ignore[union-attr]
                        source_ip=prepared[i]["alert"].source_ip,  # type: ignore[union-attr]
                        use_external_llm=True,
                    )
                    for i in llm_indices
                }
                for i, fut in futures.items():
                    analyses[i] = fut.result()

    incidents: list[TriageIncident] = []
    for idx, item in enumerate(prepared):
        rep_alert = item["alert"]  # type: ignore[assignment]
        severity = str(item["severity"])
        score = int(item["score"])  # type: ignore[arg-type]
        count = int(item["count"])  # type: ignore[arg-type]
        mitre = item["mitre"]  # type: ignore[assignment]
        iocs = item["iocs"]  # type: ignore[assignment]

        ai_analysis = analyses.get(idx) or analyze_incident(
            title=rep_alert.title,
            description=rep_alert.description,
            severity=severity,
            risk_score=score,
            mitre=mitre,
            matched_iocs=iocs,
            occurrence_count=count,
            dest_host=rep_alert.dest_host,
            source_ip=rep_alert.source_ip,
            use_external_llm=False,
        )

        decision, response_plan, agent_trace = run_triage_agent(
            title=rep_alert.title,
            severity=severity,
            risk_score=score,
            occurrence_count=count,
            matched_iocs=iocs,
            mitre=mitre,
            ai_analysis=ai_analysis,
            dest_host=rep_alert.dest_host,
            source_ip=rep_alert.source_ip,
        )

        incidents.append(
            TriageIncident(
                incident_id=f"INC-{idx + 1:04d}",
                fingerprint=str(item["fp"]),
                title=rep_alert.title,
                severity=severity,
                risk_score=score,
                confidence=float(item["confidence"]),  # type: ignore[arg-type]
                occurrence_count=count,
                alert_ids=item["alert_ids"],  # type: ignore[arg-type]
                source_ip=rep_alert.source_ip,
                dest_host=rep_alert.dest_host,
                user=rep_alert.user,
                matched_iocs=iocs,
                mitre=mitre,
                score_factors=item["factors"],  # type: ignore[arg-type]
                ai_analysis=ai_analysis,
                decision=decision,
                response_plan=response_plan,
                agent_trace=agent_trace,
                first_seen=str(item["first_seen"]),
                last_seen=str(item["last_seen"]),
            )
        )

    unique_count = len(incidents)
    suppressed = max(0, total_ingested - unique_count)
    reduction_pct = round((suppressed / total_ingested) * 100.0, 2) if total_ingested else 0.0
    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)

    return BatchTriageSummary(
        total_alerts_ingested=total_ingested,
        unique_incidents=unique_count,
        duplicates_suppressed=suppressed,
        noise_reduction_pct=reduction_pct,
        severity_counts=severity_counts,
        processing_time_ms=elapsed_ms,
        incidents=tuple(incidents),
    )
