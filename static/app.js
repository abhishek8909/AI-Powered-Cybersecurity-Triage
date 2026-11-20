"use strict";

(() => {
  const SEVERITY_PREFIX = {
    CRITICAL: "[!] CRITICAL",
    HIGH: "[!] HIGH",
    MEDIUM: "[~] MEDIUM",
    LOW: "[i] LOW",
  };

  let allIncidents = [];
  let activeSeverity = "ALL";

  const alertsInput = document.getElementById("alerts-json-input");
  const loadSampleBtn = document.getElementById("load-sample-btn");
  const runTriageBtn = document.getElementById("run-triage-btn");
  const errorBanner = document.getElementById("error-banner");
  const statusBanner = document.getElementById("status-banner");
  const incidentsHeading = document.getElementById("incidents-heading");
  const incidentsList = document.getElementById("incidents-list");
  const filterButtons = Array.from(document.querySelectorAll(".filter-btn"));

  const metricIngested = document.getElementById("metric-ingested");
  const metricUnique = document.getElementById("metric-unique");
  const metricNoise = document.getElementById("metric-noise");
  const metricLatency = document.getElementById("metric-latency");

  function showError(message) {
    errorBanner.textContent = message;
    errorBanner.hidden = false;
    statusBanner.hidden = true;
  }

  function showStatus(message) {
    statusBanner.textContent = message;
    statusBanner.hidden = false;
    errorBanner.hidden = true;
  }

  function createEl(tag, className, text) {
    const el = document.createElement(tag);
    if (className) {
      el.className = className;
    }
    if (text !== undefined) {
      el.textContent = text;
    }
    return el;
  }

  function renderIncidents() {
    const filtered = activeSeverity === "ALL"
      ? allIncidents
      : allIncidents.filter((inc) => inc.severity === activeSeverity);

    incidentsList.replaceChildren();

    if (filtered.length === 0) {
      incidentsList.appendChild(
        createEl("p", "empty-state", "No incidents match the selected severity filter.")
      );
      return;
    }

    const fragment = document.createDocumentFragment();
    for (const inc of filtered) {
      const card = createEl("article", "incident-card");

      const top = createEl("div", "incident-top");
      const heading = createEl("h3", "", `${inc.incident_id}: ${inc.title}`);
      const badge = createEl(
        "span",
        `badge badge-${inc.severity}`,
        `${SEVERITY_PREFIX[inc.severity] || inc.severity} • Risk ${inc.risk_score}/100`
      );
      top.append(heading, badge);

      const meta = createEl("div", "meta-row");
      meta.append(
        createEl("span", "decision-pill", `Decision: ${inc.decision}`),
        createEl("span", "", `Events: ${inc.occurrence_count}`),
        createEl("span", "", `Confidence: ${Math.round(inc.confidence * 100)}%`),
        createEl("span", "", `Host: ${inc.dest_host || "N/A"}`),
        createEl("span", "", `Source IP: ${inc.source_ip || "N/A"}`),
        createEl("span", "", `FP Risk: ${inc.ai_analysis.false_positive_likelihood}`)
      );

      const mitreText = inc.mitre.length
        ? inc.mitre.map((m) => `${m.technique_id} ${m.technique_name} (${m.tactic})`).join(", ")
        : "No high-severity MITRE signature matched";
      const mitreEl = createEl("p", "detail-block", `MITRE ATT&CK: ${mitreText}`);

      const iocText = inc.matched_iocs.length ? inc.matched_iocs.join(", ") : "None";
      const iocEl = createEl("p", "detail-block", `Matched IOCs: ${iocText}`);

      const summaryEl = createEl("p", "detail-block", `AI Summary: ${inc.ai_analysis.summary}`);
      const rootCauseEl = createEl(
        "p",
        "detail-block",
        `Root-Cause Hypothesis: ${inc.ai_analysis.root_cause_hypothesis}`
      );

      const planLabel = createEl("p", "detail-block", "Proposed Response Plan (Human-Approved):");
      const planList = createEl("ol", "actions-list");
      const steps = Array.isArray(inc.response_plan) ? inc.response_plan : [];
      for (const step of steps) {
        const li = createEl("li", "", step.action);
        if (step.requires_human_approval) {
          li.appendChild(createEl("span", "approval-tag", "Requires Human Approval"));
        }
        planList.appendChild(li);
      }

      const details = createEl("details", "trace-details");
      details.appendChild(createEl("summary", "", "Score Breakdown & 6-Step Agent Trace"));

      const factorsLabel = createEl("p", "detail-block", "Risk Score Factors:");
      const factorsList = createEl("ul", "factors-list");
      for (const factor of inc.score_factors || []) {
        factorsList.appendChild(createEl("li", "", factor));
      }

      const traceLabel = createEl("p", "detail-block", "Agent Reasoning Trace:");
      const traceList = createEl("ol", "trace-list");
      for (const step of inc.agent_trace || []) {
        traceList.appendChild(createEl("li", "", `${step.stage}: ${step.detail}`));
      }

      details.append(factorsLabel, factorsList, traceLabel, traceList);
      card.append(top, meta, mitreEl, iocEl, summaryEl, rootCauseEl, planLabel, planList, details);
      fragment.appendChild(card);
    }

    incidentsList.appendChild(fragment);
  }

  async function loadSampleAlerts() {
    try {
      const response = await fetch("/api/sample-alerts");
      if (!response.ok) {
        throw new Error("Could not load sample alerts.");
      }
      const data = await response.json();
      alertsInput.value = JSON.stringify(data.alerts, null, 2);
      showStatus(`Loaded ${data.alerts.length} sample SOC alerts. Ready to triage.`);
    } catch (err) {
      showError(err instanceof Error ? err.message : "Failed to load sample alerts.");
    }
  }

  async function runTriage() {
    let alerts;
    try {
      alerts = JSON.parse(alertsInput.value.trim());
      if (!Array.isArray(alerts) || alerts.length === 0) {
        throw new Error("Please provide a non-empty JSON array of alert objects.");
      }
    } catch (err) {
      showError(err instanceof Error ? err.message : "Invalid JSON input.");
      return;
    }

    runTriageBtn.disabled = true;
    incidentsList.setAttribute("aria-busy", "true");
    try {
      const response = await fetch("/api/triage/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alerts }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Triage request failed.");
      }

      allIncidents = data.incidents || [];
      metricIngested.textContent = String(data.total_alerts_ingested);
      metricUnique.textContent = String(data.unique_incidents);
      metricNoise.textContent = `${data.noise_reduction_pct}%`;
      metricLatency.textContent = `${data.processing_time_ms} ms`;

      renderIncidents();
      showStatus(
        `Triaged ${data.total_alerts_ingested} alerts into ${data.unique_incidents} prioritized incidents in ${data.processing_time_ms} ms.`
      );
      incidentsHeading.focus();
    } catch (err) {
      showError(err instanceof Error ? err.message : "Triage failed.");
    } finally {
      runTriageBtn.disabled = false;
      incidentsList.setAttribute("aria-busy", "false");
    }
  }

  for (const btn of filterButtons) {
    btn.addEventListener("click", () => {
      activeSeverity = btn.dataset.severity || "ALL";
      for (const other of filterButtons) {
        other.setAttribute("aria-pressed", String(other === btn));
      }
      renderIncidents();
    });
  }

  loadSampleBtn.addEventListener("click", loadSampleAlerts);
  runTriageBtn.addEventListener("click", runTriage);
})();
