# Security Model & Known Limitations

## Threat Model & Controls

1. **Untrusted Alert Payloads (XSS / Log Injection / ReDoS)**
   - Every text field is bounded in length, stripped of ASCII control/CRLF characters (`[\x00-\x1f\x7f]`) and HTML tags (`<[^>]{0,256}>`) via linear-time, ReDoS-safe regexes (`src/security.py`).
   - IP addresses, domains, and file hashes are strictly validated before enrichment.
   - The frontend (`static/app.js`) constructs DOM nodes exclusively with `textContent` and never uses `innerHTML`.

2. **HTTP Request & Abuse Protections**
   - Strict `Content-Type: application/json` enforcement (`415 Unsupported Media Type`).
   - Mandatory `Content-Length` (`411 Length Required`) and hard `1 MiB` payload limit (`413 Payload Too Large`).
   - Hard `5,000`-alert batch cap (`400 Bad Request`).
   - Per-client sliding-window rate limiter with LRU-bounded memory (`429 Too Many Requests` + `Retry-After`).
   - Optional shared Bearer authentication (`TRIAGE_API_TOKEN`) verified in constant time via `hmac.compare_digest` (`401 Unauthorized`).
   - Explicit static asset allowlist loaded into memory at startup (eliminates path traversal).
   - Hardened headers on every response: `Content-Security-Policy` (no `unsafe-inline`), `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cache-Control: no-store`.

3. **AI / LLM & Detection Hardening**
   - Optional Gemini API calls pass the API key via HTTP header (`x-goog-api-key`), never in the URL query string.
   - `GEMINI_MODEL` is strictly validated against `^[a-zA-Z0-9._-]{1,64}$` to prevent path injection.
   - Prompt-injection hardening separates system instructions from `<UNTRUSTED_ALERT_DATA>`, and all LLM outputs are sanitised before returning.
   - LLM calls are capped at the top 5 `CRITICAL`/`HIGH` incidents per batch and run concurrently.
   - Evasion resistance: benign-activity keywords (e.g., `"scheduled backup"`) never discount risk if any detection rule or threat-intel IOC matched.
   - Human-in-the-loop safety: the triage agent never auto-executes containment actions; every containment step carries `requires_human_approval: true`.

## Known Limitations

- Bundled IOC lists (`MALICIOUS_IPS`, `MALICIOUS_DOMAINS`, `MALICIOUS_HASHES`) are demonstration data; integrate live STIX/TAXII or TIP feeds for production.
- Rate limiting and LRU caches are per-process in memory; multi-worker deployments should place a shared reverse proxy / API gateway in front.
- The server speaks plain HTTP; terminate TLS at a reverse proxy (Nginx, Envoy, Caddy, or cloud load balancer).
- Authentication supports a single shared Bearer token; production SOC deployments should integrate OIDC/SSO with RBAC.
