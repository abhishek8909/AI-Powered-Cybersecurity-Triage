<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PS06: AI-Powered Cybersecurity Triage — Technical Documentation</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
  <style>
    /* Utilitarian · Engineering & Developer Documentation · compact answer-first hero · pipeline -> alignment -> efficiency/chart -> security & accessibility -> tests -> API -> ops/limitations · Space Grotesk + Inter + JetBrains Mono · Crisp white (#FFFFFF) + Deep Cobalt (#075985 AAA text / #0284C7 graphic) · 0px radius · inline KPI strip · SVG horizontal throughput bar chart */

    :root {
      --paper: #FFFFFF;
      --ink: #0F172A;
      --ink2: #334155;
      --mute: #475569;
      --hair: #CBD5E1;
      --accent: #0284C7;
      --accent-text: #075985;
      --accent-2: #0F766E;
      --accent-2-text: #115E59;
    }

    *,
    *::before,
    *::after {
      box-sizing: border-box;
    }

    html {
      font-size: 16px;
      scroll-behavior: smooth;
    }

    body {
      margin: 0;
      background: var(--paper);
      color: var(--ink);
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      line-height: 1.65;
      -webkit-font-smoothing: antialiased;
    }

    .page {
      padding: 64px clamp(24px, 9vw, 112px) 88px;
    }

    .grid-12 {
      display: grid;
      grid-template-columns: repeat(12, minmax(0, 1fr));
      gap: 24px;
    }

    .col-span-12 { grid-column: 1 / -1; }
    .col-left { grid-column: 1 / 5; }
    .col-right { grid-column: 5 / 13; }
    .col-half-a { grid-column: 1 / 7; }
    .col-half-b { grid-column: 7 / 13; }

    .measure {
      max-width: 68ch;
    }

    h1 {
      margin: 0 0 16px;
      font-family: 'Space Grotesk', system-ui, sans-serif;
      font-size: clamp(38px, 4.4vw, 54px);
      line-height: 1.08;
      letter-spacing: -0.025em;
      font-weight: 700;
      text-wrap: balance;
      color: var(--ink);
    }

    h2 {
      margin: 0 0 18px;
      font-family: 'Space Grotesk', system-ui, sans-serif;
      font-size: clamp(24px, 2.4vw, 32px);
      line-height: 1.2;
      letter-spacing: -0.02em;
      font-weight: 700;
      color: var(--ink);
    }

    h3 {
      margin: 0 0 10px;
      font-family: 'Space Grotesk', system-ui, sans-serif;
      font-size: 18px;
      line-height: 1.3;
      font-weight: 600;
      color: var(--ink);
    }

    p {
      margin: 0 0 14px;
      color: var(--ink2);
      font-size: 16px;
    }

    .deck {
      font-size: 18px;
      line-height: 1.55;
      color: var(--ink2);
      max-width: 66ch;
      margin-bottom: 14px;
    }

    .safety-note {
      font-size: 15px;
      font-weight: 600;
      color: var(--accent-text);
      margin-bottom: 32px;
      max-width: 68ch;
    }

    .kpi-strip {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 24px;
      border-top: 2px solid var(--ink);
      border-bottom: 1px solid var(--hair);
      padding: 20px 0;
    }

    .kpi-val {
      font-family: 'Space Grotesk', system-ui, sans-serif;
      font-size: clamp(28px, 3vw, 40px);
      font-weight: 700;
      line-height: 1.1;
      letter-spacing: -0.02em;
      color: var(--ink);
      white-space: nowrap;
    }

    .kpi-label {
      margin-top: 6px;
      font-size: 13px;
      color: var(--mute);
      line-height: 1.35;
    }

    .sec {
      margin-top: 64px;
      padding-top: 28px;
      border-top: 1px solid var(--hair);
    }

    code {
      font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, monospace;
      font-size: 13.5px;
      color: var(--accent-text);
    }

    pre {
      margin: 0 0 18px;
      padding: 14px 0 14px 18px;
      border-left: 2px solid var(--accent);
      overflow-x: auto;
      font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, monospace;
      font-size: 13px;
      line-height: 1.6;
      color: var(--ink);
    }

    ul.clean-list {
      margin: 0;
      padding: 0;
      list-style: none;
    }

    ul.clean-list li {
      position: relative;
      padding-left: 18px;
      margin-bottom: 10px;
      color: var(--ink2);
      font-size: 15.5px;
    }

    ul.clean-list li::before {
      content: "";
      position: absolute;
      left: 0;
      top: 10px;
      width: 6px;
      height: 6px;
      background: var(--accent);
    }

    .table-wrap {
      overflow-x: auto;
      margin-top: 12px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 15px;
    }

    th {
      text-align: left;
      padding: 10px 14px 10px 0;
      border-bottom: 2px solid var(--ink);
      font-family: 'JetBrains Mono', ui-monospace, monospace;
      font-size: 12px;
      font-weight: 600;
      color: var(--ink);
      white-space: nowrap;
    }

    td {
      padding: 12px 14px 12px 0;
      border-bottom: 1px solid var(--hair);
      vertical-align: top;
      color: var(--ink2);
    }

    td.num,
    th.num {
      text-align: right;
      white-space: nowrap;
      font-family: 'JetBrains Mono', ui-monospace, monospace;
      font-size: 13.5px;
    }

    td.key-col {
      font-weight: 600;
      color: var(--ink);
      white-space: nowrap;
    }

    figure {
      margin: 24px 0 0;
    }

    figure .fig-title {
      font-family: 'Space Grotesk', system-ui, sans-serif;
      font-size: 18px;
      font-weight: 600;
      color: var(--ink);
      margin-bottom: 10px;
    }

    figcaption {
      margin-top: 8px;
      font-size: 13px;
      color: var(--mute);
    }

    .split-rule {
      border-top: 1px solid var(--hair);
      padding-top: 18px;
    }

    .footer-note {
      margin-top: 64px;
      padding-top: 20px;
      border-top: 1px solid var(--hair);
      font-size: 13.5px;
      color: var(--mute);
    }

    @media (max-width: 860px) {
      .col-left,
      .col-right,
      .col-half-a,
      .col-half-b {
        grid-column: 1 / -1;
      }

      .kpi-strip {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }
  </style>
</head>
<body>
  <main class="page">
    <header>
      <h1>PS06: AI-Powered Cybersecurity Triage</h1>
      <p class="deck">
        A zero-dependency SOC alert triage service, six-step auditable triage agent, and WCAG 2.1 AA accessible dashboard built with Python 3.11+ standard library and vanilla HTML, CSS, and JavaScript.
      </p>
      <p class="safety-note">
        Human-in-the-loop guarantee: no containment action is ever executed automatically; every infrastructure or identity change is explicitly flagged for analyst approval.
      </p>

      <div class="kpi-strip">
        <div>
          <div class="kpi-val">467k/s</div>
          <div class="kpi-label">Peak storm throughput (10k alerts in ~21.4 ms)</div>
        </div>
        <div>
          <div class="kpi-val">18</div>
          <div class="kpi-label">Pre-compiled MITRE ATT&amp;CK detection rules</div>
        </div>
        <div>
          <div class="kpi-val">41</div>
          <div class="kpi-label">Automated tests across 7 verification suites</div>
        </div>
        <div>
          <div class="kpi-val">0</div>
          <div class="kpi-label">External runtime dependencies (Python 3.11+)</div>
        </div>
      </div>
    </header>

    <section class="sec grid-12">
      <div class="col-left">
        <h2>Quick start and end-to-end triage pipeline</h2>
        <p>
          Every alert stream passes through strict sanitisation, memoised rule classification, single-pass deduplication, hybrid AI reasoning, and an auditable six-step agent before reaching the console.
        </p>
      </div>
      <div class="col-right">
        <h3>Run locally</h3>
        <pre># 1. Clone the repository
git clone https://github.com/&lt;your-username&gt;/&lt;your-repo&gt;.git
cd &lt;your-repo&gt;

# 2. Run the full verification suite (41 tests across 7 suites)
python3 -m unittest discover -s tests -v

# 3. Run reproducible throughput benchmarks
python3 scripts/benchmark.py

# 4. Launch the server and accessible SOC console
python3 -m src.server
# Open http://127.0.0.1:8000</pre>

        <h3>Pipeline stages</h3>
        <pre>Raw Alerts (JSON)
  -&gt; Validate &amp; Sanitise (src/security.py)
  -&gt; Classify: 18 MITRE Rules (LRU-cached) + O(1) IOCs + Critical Assets (src/triage_engine.py)
  -&gt; Deduplicate &amp; Correlate Alert Storms in O(N) Single Pass
  -&gt; Hybrid AI Analysis: Optional Concurrent Gemini (Top 5) / Deterministic Fallback (src/ai_analyst.py)
  -&gt; 6-Step Triage Agent: Observe -&gt; Enrich -&gt; Reason -&gt; Plan -&gt; Decide -&gt; Propose (src/agent.py)
  -&gt; Accessible SOC Console &amp; JSON API (src/server.py, static/)</pre>
      </div>
    </section>

    <section class="sec">
      <h2>Every PS06 capability maps directly to a dedicated module</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>SOC Triage Capability</th>
              <th>Implementation</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td class="key-col">Alert Ingestion &amp; Normalisation</td>
              <td>Strict schema validation, length bounds, and CRLF/HTML sanitisation for <code>/api/triage</code> and <code>/api/triage/batch</code> (<code>src/security.py</code>).</td>
            </tr>
            <tr>
              <td class="key-col">Deduplication &amp; Noise Reduction</td>
              <td>Single-pass O(N) grouping by <code>(source_ip, dest_host, category, matched_rules)</code> with alert-storm burst escalation (<code>src/triage_engine.py</code>).</td>
            </tr>
            <tr>
              <td class="key-col">Threat-Intel IOC Enrichment</td>
              <td>O(1) <code>frozenset</code> + <code>@lru_cache(maxsize=4096)</code> lookups across malicious IPs, C2 domains, and file hashes.</td>
            </tr>
            <tr>
              <td class="key-col">MITRE ATT&amp;CK Mapping</td>
              <td>18 pre-compiled ReDoS-safe rules covering <code>T1110</code>, <code>T1190</code>, <code>T1505.003</code>, <code>T1059</code>, <code>T1105</code>, <code>T1071</code>, <code>T1041</code>, <code>T1074</code>, <code>T1003</code>, <code>T1558</code>, <code>T1068</code>, <code>T1548.003</code>, <code>T1098</code>, <code>T1566</code>, <code>T1078</code>, <code>T1621</code>, <code>T1486</code>, <code>T1490</code>.</td>
            </tr>
            <tr>
              <td class="key-col">Hybrid AI Analysis</td>
              <td>Optional Gemini REST integration (key via <code>x-goog-api-key</code> header, prompt-injection hardened, capped at top 5 <code>CRITICAL</code>/<code>HIGH</code> incidents, concurrent) with instant deterministic fallback (<code>src/ai_analyst.py</code>).</td>
            </tr>
            <tr>
              <td class="key-col">6-Step Auditable Triage Agent</td>
              <td>Deterministic decision table (<code>CONTAIN_PENDING_APPROVAL</code>, <code>ESCALATE_TIER2</code>, <code>INVESTIGATE</code>, <code>MONITOR</code>, <code>AUTO_CLOSE_BENIGN</code>), approval-flagged response plan, and 6-step reasoning trace (<code>src/agent.py</code>).</td>
            </tr>
            <tr>
              <td class="key-col">Accessible SOC Dashboard</td>
              <td>Keyboard-first WCAG 2.1 AA console with severity filters, score breakdowns, approval badges, and expandable agent traces (<code>static/</code>).</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="sec">
      <h2>Linear O(N) scaling sustains 474k alerts/sec during alert storms</h2>
      <p class="measure">
        For N ingested alerts and K unique deduplicated incidents (K &le; N): IOC and asset lookups run in O(1), text classification runs in O(R &middot; L) per distinct text memoised in a 4,096-entry LRU cache, deduplication runs in a single O(N) pass using slotted dataclasses, prioritisation runs in O(K log K) on deduplicated incidents only, rate limiting runs in O(1) amortised via an LRU-bounded <code>OrderedDict</code>, and static assets are served from memory.
      </p>

      <figure>
        <div class="fig-title">LRU-cached storm triage finishes 100k alerts in 211 ms while unique text scales linearly</div>
        <svg viewBox="0 0 700 320" width="100%" role="img" aria-label="Horizontal bar chart comparing measured latency and throughput across 10,000 and 100,000 alerts for repetitive storms versus unique text">
          <!-- Vertical gridlines (log-friendly proportional visual scale with exact labels; linear scale to 4000 ms) -->
          <line x1="220" y1="24" x2="220" y2="262" stroke="#CBD5E1" stroke-width="1"/>
          <line x1="320" y1="24" x2="320" y2="262" stroke="#CBD5E1" stroke-width="1" stroke-dasharray="3 3"/>
          <line x1="420" y1="24" x2="420" y2="262" stroke="#CBD5E1" stroke-width="1" stroke-dasharray="3 3"/>
          <line x1="520" y1="24" x2="520" y2="262" stroke="#CBD5E1" stroke-width="1" stroke-dasharray="3 3"/>
          <line x1="620" y1="24" x2="620" y2="262" stroke="#CBD5E1" stroke-width="1" stroke-dasharray="3 3"/>

          <!-- Axis ticks -->
          <text x="220" y="284" text-anchor="middle" font-family="JetBrains Mono, monospace" font-size="13" fill="#475569">0 ms</text>
          <text x="320" y="284" text-anchor="middle" font-family="JetBrains Mono, monospace" font-size="13" fill="#475569">1,000</text>
          <text x="420" y="284" text-anchor="middle" font-family="JetBrains Mono, monospace" font-size="13" fill="#475569">2,000</text>
          <text x="520" y="284" text-anchor="middle" font-family="JetBrains Mono, monospace" font-size="13" fill="#475569">3,000</text>
          <text x="620" y="284" text-anchor="middle" font-family="JetBrains Mono, monospace" font-size="13" fill="#475569">4,000 ms</text>
          <text x="420" y="308" text-anchor="middle" font-family="Inter, sans-serif" font-size="13" fill="#475569">Batch processing time (milliseconds, lower is faster)</text>

          <!-- Row 1: 10k storm (21.4 ms -> 2.14px, draw min 6px visible marker) -->
          <text x="208" y="60" text-anchor="end" font-family="Inter, sans-serif" font-size="14" font-weight="600" fill="#0F172A">10k storm (4 texts)</text>
          <rect x="220" y="42" width="6" height="26" fill="#0284C7"/>
          <text x="236" y="60" font-family="JetBrains Mono, monospace" font-size="13.5" font-weight="600" fill="#075985">21.4 ms (~467k/s)</text>

          <!-- Row 2: 100k storm (211.2 ms -> 21.1px) -->
          <text x="208" y="118" text-anchor="end" font-family="Inter, sans-serif" font-size="14" font-weight="600" fill="#0F172A">100k storm (4 texts)</text>
          <rect x="220" y="100" width="21" height="26" fill="#0284C7"/>
          <text x="251" y="118" font-family="JetBrains Mono, monospace" font-size="13.5" font-weight="600" fill="#075985">211.2 ms (~474k/s)</text>

          <!-- Row 3: 10k unique (365.7 ms -> 36.6px) -->
          <text x="208" y="176" text-anchor="end" font-family="Inter, sans-serif" font-size="14" font-weight="600" fill="#0F172A">10k unique texts</text>
          <rect x="220" y="158" width="37" height="26" fill="#0F766E"/>
          <text x="267" y="176" font-family="JetBrains Mono, monospace" font-size="13.5" font-weight="600" fill="#115E59">365.7 ms (~27k/s)</text>

          <!-- Row 4: 100k unique (3628 ms -> 362.8px) -->
          <text x="208" y="234" text-anchor="end" font-family="Inter, sans-serif" font-size="14" font-weight="600" fill="#0F172A">100k unique texts</text>
          <rect x="220" y="216" width="363" height="26" fill="#0F766E"/>
          <text x="592" y="234" font-family="JetBrains Mono, monospace" font-size="13.5" font-weight="600" fill="#115E59">3.63 s (~28k/s)</text>
        </svg>
        <figcaption>Measured with <code>python3 scripts/benchmark.py</code> (best of 3 runs, cold LRU cache, Python 3.11).</figcaption>
      </figure>
    </section>

    <section class="sec grid-12">
      <div class="col-half-a">
        <h2>Hardened security controls</h2>
        <p>Full threat model and deployment notes live in <code>SECURITY.md</code>.</p>
        <ul class="clean-list">
          <li><strong>HTTP status enforcement:</strong> <code>415</code> on non-JSON POSTs, <code>411</code> on missing <code>Content-Length</code>, <code>413</code> above 1 MiB, and <code>400</code> above 5,000 alerts per batch.</li>
          <li><strong>Authentication &amp; rate limits:</strong> Optional constant-time Bearer token auth (<code>TRIAGE_API_TOKEN</code>, <code>401</code>) and per-client sliding-window rate limiting (<code>429</code> + <code>Retry-After</code>).</li>
          <li><strong>Response headers:</strong> Strict <code>Content-Security-Policy</code> (no <code>unsafe-inline</code>), <code>Cross-Origin-Opener-Policy</code>, <code>Cross-Origin-Resource-Policy</code>, <code>X-Content-Type-Options: nosniff</code>, <code>X-Frame-Options: DENY</code>, and <code>Referrer-Policy: no-referrer</code>.</li>
          <li><strong>Injection &amp; evasion defence:</strong> Explicit static file allowlist, zero <code>innerHTML</code>/<code>document.write</code> usage, <code>&lt;UNTRUSTED_ALERT_DATA&gt;</code> prompt delimiters, header-only Gemini API key, validated model name, and evasion-resistant scoring.</li>
        </ul>
      </div>

      <div class="col-half-b">
        <h2>WCAG 2.1 AA accessibility</h2>
        <p>Verified programmatically in <code>tests/test_accessibility.py</code>.</p>
        <ul class="clean-list">
          <li><strong>Semantic landmarks:</strong> Full <code>&lt;header&gt;</code>, <code>&lt;nav&gt;</code>, <code>&lt;main&gt;</code>, <code>&lt;section&gt;</code>, and <code>&lt;footer&gt;</code> hierarchy, skip-to-main-content link, and zoomable viewport.</li>
          <li><strong>ARIA &amp; focus management:</strong> Explicit <code>&lt;label for&gt;</code> bindings, <code>aria-describedby</code> hints, <code>aria-pressed</code> filters, <code>aria-live="polite"</code> status updates, <code>role="alert"</code> errors, <code>aria-busy</code> loading state, and focus moved to the results heading after triage.</li>
          <li><strong>Visual &amp; motor ergonomics:</strong> Minimum <code>44px</code> touch targets, visible <code>:focus-visible</code> outlines, <code>prefers-reduced-motion</code> and <code>forced-colors</code> support, and non-color-only severity badges (symbol + label + border).</li>
          <li><strong>Automated contrast math:</strong> Every foreground/background CSS pair is audited against WCAG 2.1 AA (<code>&ge; 4.5:1</code>).</li>
        </ul>
      </div>
    </section>

    <section class="sec">
      <h2>41 automated tests verify logic, security, speed, and accessibility</h2>
      <p class="measure">
        Run locally with <code>python3 -m unittest discover -s tests -v</code> or via <code>pytest</code> (configured in <code>pyproject.toml</code>).
      </p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Test Suite</th>
              <th class="num">Tests</th>
              <th>Verification Scope</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>tests/test_triage_engine.py</code></td>
              <td class="num">10</td>
              <td>18 MITRE rules, deduplication, scoring, evasion resistance, agent integration, bounded top-5 LLM</td>
            </tr>
            <tr>
              <td><code>tests/test_agent.py</code></td>
              <td class="num">3</td>
              <td>5-disposition decision table, human-approval flags, 6-step reasoning trace</td>
            </tr>
            <tr>
              <td><code>tests/test_ai_analyst.py</code></td>
              <td class="num">5</td>
              <td>Deterministic fallback, mocked Gemini path, header-only key, injection &amp; output sanitisation</td>
            </tr>
            <tr>
              <td><code>tests/test_security.py</code></td>
              <td class="num">7</td>
              <td>Sanitisers, IOC/model validators, constant-time auth, CSP/COOP/CORP headers, LRU limiter, ReDoS</td>
            </tr>
            <tr>
              <td><code>tests/test_api.py</code></td>
              <td class="num">5</td>
              <td>Live HTTP server: routes, HEAD, 400/401/404/411/413/415/429+Retry-After/500, auth, path traversal</td>
            </tr>
            <tr>
              <td><code>tests/test_efficiency.py</code></td>
              <td class="num">4</td>
              <td>10k-alert latency, linear O(N) scaling (storm &amp; unique text), bounded LRU cache</td>
            </tr>
            <tr>
              <td><code>tests/test_accessibility.py</code></td>
              <td class="num">7</td>
              <td>Landmarks, ARIA, labels, WCAG AA contrast math, 44px targets, zero unsafe DOM APIs</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="sec">
      <h2>REST API reference</h2>
      <p class="measure">
        All <code>POST</code> requests require <code>Content-Type: application/json</code> and, when <code>TRIAGE_API_TOKEN</code> is configured, <code>Authorization: Bearer &lt;token&gt;</code>.
      </p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Method &amp; Endpoint</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>GET /api/health</code></td>
              <td>Service liveness check</td>
            </tr>
            <tr>
              <td><code>GET /api/sample-alerts</code></td>
              <td>Realistic demo SOC alert stream (8 alerts collapsing to 6 incidents)</td>
            </tr>
            <tr>
              <td><code>POST /api/triage</code></td>
              <td>Triage a single alert JSON object</td>
            </tr>
            <tr>
              <td><code>POST /api/triage/batch</code></td>
              <td>Triage a batch: <code>{"alerts": [...], "use_llm": false}</code> (max 5,000 alerts, 1 MiB)</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="sec grid-12">
      <div class="col-half-a">
        <h2>Configuration, Docker, and repository layout</h2>
        <p>Copy <code>.env.example</code> to <code>.env</code>, set optional variables (<code>GEMINI_API_KEY</code>, <code>GEMINI_MODEL</code>, <code>TRIAGE_API_TOKEN</code>, <code>HOST</code>, <code>PORT</code>), and launch:</p>
        <pre>set -a; source .env; set +a
python3 -m src.server

# Or build and run the non-root container
docker build -t ps06-cyber-triage .
docker run -p 8000:8000 ps06-cyber-triage</pre>

        <h3>Repository layout</h3>
        <pre>.
├── .github/workflows/ci.yml   # CI: tests, benchmarks, JS check, lint/typecheck
├── Dockerfile                 # Non-root Python 3.11-slim container + healthcheck
├── Makefile                   # test, benchmark, run, coverage, lint, typecheck
├── README.md                  # Project overview and usage
├── SECURITY.md                # Threat model and deployment limitations
├── pyproject.toml             # Packaging, pytest, coverage, ruff, mypy config
├── requirements.txt           # Zero external runtime dependencies
├── requirements-dev.txt       # Optional developer tooling
├── scripts/benchmark.py       # Reproducible 10k / 100k throughput benchmark
├── src/                       # Engine, 6-step agent, AI analyst, security, server
├── static/                    # WCAG 2.1 AA SOC console (index.html, styles.css, app.js)
└── tests/                     # 41 automated tests across 7 suites</pre>
      </div>

      <div class="col-half-b">
        <h2>Known limitations</h2>
        <p>Honest boundaries of the current single-node implementation:</p>
        <ul class="clean-list">
          <li><strong>Demo threat-intel feeds:</strong> Bundled IOC lists (<code>MALICIOUS_IPS</code>, <code>MALICIOUS_DOMAINS</code>, <code>MALICIOUS_HASHES</code>) are demonstration data; integrate live STIX/TAXII or TIP feeds for production.</li>
          <li><strong>In-process state:</strong> Rate limiting and LRU caches are per-process in memory; multi-worker deployments should place a shared reverse proxy or API gateway in front.</li>
          <li><strong>TLS termination:</strong> The server speaks plain HTTP; terminate TLS at Nginx, Caddy, Envoy, or a cloud load balancer.</li>
          <li><strong>Shared-token authentication:</strong> Built-in auth uses a single shared Bearer token; production SOC teams should front the API with OIDC/SSO and RBAC.</li>
        </ul>
      </div>
    </section>

    <footer class="footer-note">
      PS06: AI-Powered Cybersecurity Triage &mdash; Static self-contained HTML documentation generated directly from the verified repository.
    </footer>
  </main>
</body>
</html>
