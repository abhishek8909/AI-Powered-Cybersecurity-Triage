# PS06: AI-Powered Cybersecurity Triage

A zero-dependency SOC alert triage service, six-step auditable triage agent, and WCAG 2.1 AA accessible dashboard built with Python 3.11+ standard library and vanilla HTML/CSS/JS.

It ingests raw SIEM/EDR alert streams, suppresses duplicate alert storms in $O(N)$ time, enriches Indicators of Compromise (IOCs) in $O(1)$, maps threats across 18 MITRE ATT&CK techniques, explains every risk score factor by factor, and proposes human-approved containment plans. **No response action is ever executed automatically: containment steps are explicitly flagged for human approval.**

## Quick Start

Requires **Python 3.11+** (no third-party runtime packages required).

```
# 1. Clone the repository
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

# 2. Run the full verification suite (41 tests across 7 suites)
python3 -m unittest discover -s tests -v

# 3. Run reproducible throughput benchmarks
python3 scripts/benchmark.py

# 4. Launch the server and accessible SOC console
python3 -m src.server
# Open http://127.0.0.1:8000

```

## Architecture & Pipeline

```
Raw Alerts (JSON)
  -> Validate & Sanitise (src/security.py)
  -> Classify: 18 MITRE Rules (LRU-cached) + O(1) IOCs + Critical Assets (src/triage_engine.py)
  -> Deduplicate & Correlate Alert Storms in O(N) Single Pass
  -> Hybrid AI Analysis: Optional Concurrent Gemini (Top 5) / Instant Deterministic Fallback (src/ai_analyst.py)
  -> 6-Step Triage Agent: Observe -> Enrich -> Reason -> Plan -> Decide -> Propose (src/agent.py)
  -> Accessible SOC Console & JSON API (src/server.py, static/)

```

### Problem Statement Alignment (PS06)

| SOC Triage Capability | Implementation | 
| ----- | ----- | 
| **Alert Ingestion & Normalisation** | Strict schema validation, length bounds, and CRLF/HTML sanitisation for `/api/triage` and `/api/triage/batch` (`src/security.py`). | 
| **Deduplication & Noise Reduction** | Single-pass $O(N)$ grouping by `(source_ip, dest_host, category, matched_rules)` with burst escalation (`src/triage_engine.py`). | 
| **Threat-Intel IOC Enrichment** | $O(1)$ `frozenset` + `@lru_cache(maxsize=4096)` lookups across malicious IPs, C2 domains, and file hashes. | 
| **MITRE ATT&CK Mapping** | 18 pre-compiled ReDoS-safe rules covering `T1110`, `T1190`, `T1505.003`, `T1059`, `T1105`, `T1071`, `T1041`, `T1074`, `T1003`, `T1558`, `T1068`, `T1548.003`, `T1098`, `T1566`, `T1078`, `T1621`, `T1486`, `T1490`. | 
| **Hybrid AI Analysis** | Optional Gemini REST integration (key via `x-goog-api-key` header, prompt-injection hardened, capped at top 5 `CRITICAL`/`HIGH` incidents, concurrent) with instant deterministic fallback (`src/ai_analyst.py`). | 
| **6-Step Auditable Triage Agent** | Deterministic decision table (`CONTAIN_PENDING_APPROVAL`, `ESCALATE_TIER2`, `INVESTIGATE`, `MONITOR`, `AUTO_CLOSE_BENIGN`), approval-flagged response plan, and 6-step reasoning trace (`src/agent.py`). | 
| **Accessible SOC Dashboard** | Keyboard-first WCAG 2.1 AA console with severity filters, score breakdowns, approval badges, and expandable agent traces (`static/`). | 

## Efficiency & Benchmarks

For $N$ ingested alerts and $K$ unique deduplicated incidents ($K \le N$):

* **IOC & Critical Asset Lookups:** $O(1)$ average via `frozenset` and bounded `lru_cache(maxsize=4096)`.

* **Text Classification:** $O(R \cdot L)$ per distinct alert text ($R = 18$ rules, $L =$ text length), memoised in a 4,096-entry LRU cache.

* **Deduplication & Aggregation:** $O(N)$ single pass with slotted frozen dataclasses (`slots=True`).

* **Incident Prioritisation:** $O(K \log K)$ on deduplicated incidents only.

* **Rate Limiter:** $O(1)$ amortised per request with LRU-bounded client table (`OrderedDict`).

* **Static Serving & DOM Rendering:** Static assets served from memory; frontend uses single-reflow `DocumentFragment` insertion.

Measured with `python3 scripts/benchmark.py` (best of 3 runs, cold cache):

| Scenario | 10,000 Alerts | 100,000 Alerts | 
| ----- | ----- | ----- | 
| **Repetitive alert storm (4 distinct texts)** | \~21.4 ms (\~467k alerts/s) | \~211.2 ms (\~474k alerts/s) | 
| **Worst case: every alert text unique** | \~365.7 ms (\~27k alerts/s) | \~3.63 s (\~28k alerts/s) | 

## Security Controls

See `SECURITY.md` for the full threat model and deployment notes. Key protections:

* Strict HTTP enforcement: `415 Unsupported Media Type` on non-JSON POSTs, `411 Length Required` on missing `Content-Length`, `413 Payload Too Large` above `1 MiB`, and `400 Bad Request` above `5,000` alerts per batch.

* Optional constant-time Bearer token authentication (`TRIAGE_API_TOKEN`, `hmac.compare_digest`, `401 Unauthorized`).

* Per-client sliding-window rate limiting returning `429 Too Many Requests` with `Retry-After`.

* Hardened headers on every response: strict `Content-Security-Policy` (no `unsafe-inline`), `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, and `Cache-Control: no-store`.

* Explicit static file allowlist (eliminates path traversal) and zero `innerHTML` / `outerHTML` / `document.write` usage on the frontend.

* Prompt-injection delimiting (`<UNTRUSTED_ALERT_DATA>`), header-only Gemini API key, model name validation, sanitised LLM outputs, and evasion-resistant scoring (benign-activity keywords never discount risk if any threat rule or IOC matched).

## Accessibility (WCAG 2.1 AA)

* Semantic HTML5 landmarks (`<header>`, `<nav>`, `<main>`, `<section>`, `<footer>`), skip-to-main-content link, and zoomable viewport.

* Explicit `<label for>` associations, `aria-describedby` helper text, `aria-pressed` filter toggles, `aria-live="polite"` status updates, `role="alert"` error banners, `aria-busy` loading state, and automatic focus movement to the results heading after triage.

* Minimum `44px` touch targets, `:focus-visible` outlines, `@media (prefers-reduced-motion: reduce)`, `@media (forced-colors: active)`, and non-color-only severity badges (symbol + label + high-contrast border/fill).

* `tests/test_accessibility.py` programmatically verifies structure, ARIA attributes, and WCAG 2.1 AA contrast ratios (`>= 4.5:1`) across all foreground/background CSS pairs.

## Test Suite

Run locally with `python3 -m unittest discover -s tests -v` (also `pytest`-compatible via `pyproject.toml`):

| Test Suite | Tests | Verification Scope | 
| ----- | ----- | ----- | 
| `tests/test_triage_engine.py` | 10 | 18 MITRE rules, deduplication, scoring, evasion resistance, agent integration, bounded top-5 LLM | 
| `tests/test_agent.py` | 3 | 5-disposition decision table, human-approval flags, 6-step reasoning trace | 
| `tests/test_ai_analyst.py` | 5 | Deterministic fallback, mocked Gemini path, header-only key, injection & output sanitisation | 
| `tests/test_security.py` | 7 | Sanitisers, IOC/model validators, constant-time auth, CSP/COOP/CORP headers, LRU limiter, ReDoS | 
| `tests/test_api.py` | 5 | Live HTTP server: routes, HEAD, 400/401/404/411/413/415/429+Retry-After/500, auth, path traversal | 
| `tests/test_efficiency.py` | 4 | 10k-alert latency, linear $O(N)$ scaling (storm & unique text), bounded LRU cache | 
| `tests/test_accessibility.py` | 7 | Landmarks, ARIA, labels, WCAG AA contrast math, 44px targets, zero unsafe DOM APIs | 

## REST API Reference

| Method & Endpoint | Description | 
| ----- | ----- | 
| `GET /api/health` | Service liveness check | 
| `GET /api/sample-alerts` | Realistic demo SOC alert stream (8 alerts collapsing to 6 incidents) | 
| `POST /api/triage` | Triage a single alert JSON object | 
| `POST /api/triage/batch` | Triage a batch: `{"alerts": [...], "use_llm": false}` (max 5,000 alerts, 1 MiB) | 

All `POST` requests require `Content-Type: application/json` and, when `TRIAGE_API_TOKEN` is configured, `Authorization: Bearer <token>`.

## Configuration & Docker

Copy `.env.example` to `.env`, set any optional variables (`GEMINI_API_KEY`, `GEMINI_MODEL`, `TRIAGE_API_TOKEN`, `HOST`, `PORT`), export them, and start the server:

```
set -a; source .env; set +a
python3 -m src.server

```

A non-root, health-checked `Dockerfile` and GitHub Actions workflow (`.github/workflows/ci.yml`) are included:

```
docker build -t ps06-cyber-triage .
docker run -p 8000:8000 ps06-cyber-triage

```

## Project Structure

```
.
├── .github/workflows/ci.yml   # GitHub Actions CI (tests, benchmarks, JS check, optional lint/typecheck)
├── Dockerfile                 # Non-root Python 3.11-slim container with healthcheck
├── Makefile                   # test, benchmark, run, coverage, lint, typecheck targets
├── README.md                  # Project overview and usage
├── SECURITY.md                # Threat model and deployment limitations
├── pyproject.toml             # Packaging, pytest, coverage, ruff, and mypy config
├── requirements.txt           # Zero external runtime dependencies
├── requirements-dev.txt       # Optional developer tooling
├── scripts/benchmark.py       # Reproducible 10k / 100k throughput benchmark
├── src/                       # Backend engine, 6-step agent, AI analyst, security, HTTP server
├── static/                    # WCAG 2.1 AA SOC triage console (index.html, styles.css, app.js)
└── tests/                     # 41 automated tests across 7 suites

```

## Known Limitations

* Bundled IOC lists (`MALICIOUS_IPS`, `MALICIOUS_DOMAINS`, `MALICIOUS_HASHES`) are demonstration data; connect live STIX/TAXII or TIP feeds for production use.

* Rate limiting and LRU caches are per-process in memory; multi-worker deployments should place a shared reverse proxy/gateway in front.

* TLS termination should be handled by a reverse proxy (Nginx, Caddy, Envoy, or cloud load balancer).

* Built-in authentication uses a single shared Bearer token; production SOC teams should front the API with OIDC/SSO and RBAC.