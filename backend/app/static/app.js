const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const TERMINAL = new Set(["completed", "failed", "cancelled"]);

const state = {
  stats: null,
  assets: [],
  findings: [],
  scans: [],
  watchedScanId: null,
  pollTimer: null,
  refreshInFlight: false,
  noticeTimer: null,
  explanations: {},
  explanationLoading: new Set(),
  scopePlan: null,
  scanRequest: null,
  pipelines: {},
  pipelineLoading: new Set(),
  pipelineErrors: {},
  historyFindings: {},
  historyFindingsLoading: new Set(),
  historyFindingsErrors: {},
  selectedPipelineId: null,
  deepAnalyses: {},
  deepAnalysisLoading: new Set(),
  deepAnalysisErrors: {},
  refreshQueued: false,
  manualRefreshQueued: false,
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      message = body?.error?.message || body?.detail || message;
      if (Array.isArray(message)) message = message.map((item) => item.msg).join("; ");
    } catch {
      // Keep the HTTP status message when the server has no JSON error body.
    }
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  if (response.status === 204) return null;
  return response.json();
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

function dateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function timeAgo(value) {
  if (!value) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function setNotice(message, kind = "error") {
  const notice = $("#notice");
  notice.textContent = message;
  notice.className = `notice ${kind}`;
  notice.hidden = false;
  clearTimeout(state.noticeTimer);
  state.noticeTimer = setTimeout(() => { notice.hidden = true; }, 7000);
}

function setApiStatus(online) {
  const pill = $(".connection-pill");
  $("#api-status").textContent = online ? "Local service connected" : "Local service unavailable";
  pill.classList.toggle("offline", !online);
}

function activeScan(scans = state.scans) {
  return scans.find((scan) => ["pending", "running"].includes(scan.status));
}

function renderStats() {
  const stats = state.stats;
  if (!stats) return;
  $("#stat-assets").textContent = stats.alive_assets ?? 0;
  $("#stat-services").textContent = stats.total_services ?? 0;
  $("#stat-findings").textContent = stats.open_findings ?? 0;
  $("#stat-high").textContent = stats.high_or_critical_findings ?? 0;
  $("#stat-scans").textContent = stats.scans_24h ?? 0;
  $("#asset-nav-count").textContent = stats.alive_assets ?? 0;
  $("#finding-nav-count").textContent = stats.open_findings ?? 0;
}

function serviceMarkup(services = []) {
  if (!services.length) return '<span class="muted-cell">No open services observed</span>';
  const shown = services.slice(0, 3);
  const remaining = services.length - shown.length;
  return `<div class="service-tags">${shown.map((service) => `<span class="service-tag">${escapeHtml(service.port)}/${escapeHtml(service.protocol || "tcp")}</span>`).join("")}${remaining > 0 ? `<span class="service-more">+${remaining} more</span>` : ""}</div>`;
}

function riskMarkup(score) {
  const value = Math.max(0, Math.min(100, Number(score) || 0));
  const tone = value >= 70 ? "#fb7c81" : value >= 40 ? "#f4bd62" : "#56d5a5";
  return `<span class="risk-value"><span>${value}</span><span class="risk-bar"><span style="width:${value}%;background:${tone}"></span></span></span>`;
}

function assetRow(asset) {
  const name = asset.hostname || `Network device`;
  const services = asset.services || [];
  return `<tr class="asset-row" data-asset-id="${Number(asset.id)}" title="Click to view services">
    <td><div class="device-cell"><span class="device-icon">⌘</span><span><span class="device-title">${escapeHtml(name)}</span><span class="device-subtitle">${asset.is_alive ? '<span class="status-dot green"></span> Responding' : "Previously discovered"}</span></span></div></td>
    <td class="address-cell">${escapeHtml(asset.ip)}</td>
    <td>${serviceMarkup(services)}</td>
    <td>${riskMarkup(asset.risk_score)}</td>
    <td>${escapeHtml(timeAgo(asset.last_seen))}</td>
  </tr>`;
}

function renderAssets() {
  const assets = state.assets;
  $("#asset-preview-body").innerHTML = assets.slice(0, 5).map(assetRow).join("");
  $("#asset-table-body").innerHTML = assets.map(assetRow).join("");
  $("#asset-preview-empty").hidden = assets.length > 0;
  $("#asset-empty").hidden = assets.length > 0;
  $("#asset-result-count").textContent = `${assets.length} asset${assets.length === 1 ? "" : "s"}`;
  bindAssetRows();
}

function severityClass(severity) {
  return ["critical", "high", "medium", "low", "info"].includes(String(severity).toLowerCase()) ? String(severity).toLowerCase() : "info";
}

function severityMarkup(severity) {
  const value = severityClass(severity);
  return `<span class="severity ${value}"><span class="severity-dot"></span>${escapeHtml(value)}</span>`;
}

function renderFindingRow(finding) {
  const asset = state.assets.find((item) => item.id === finding.asset_id);
  const evidence = finding.evidence || "No additional evidence recorded.";
  const explanation = state.explanations[finding.id];
  const aiSelected = explanation?.mode === "ai";
  const isLoading = state.explanationLoading.has(finding.id);
  const explanationBody = aiSelected
    ? explanation.error
      ? `<p class="explanation-error">${escapeHtml(explanation.error)}</p>`
      : `<p>${isLoading ? '<span class="spinner spinner-small" aria-hidden="true"></span>' : ""}${escapeHtml(explanation.text || "Generating an AI explanation…")}</p>${explanation.model ? `<span class="explanation-model">Model: ${escapeHtml(explanation.model)}</span>` : ""}`
    : `<p><strong>Observed:</strong> ${escapeHtml(evidence)}</p><p><strong>Why it matters:</strong> ${escapeHtml(finding.description)}</p><p><strong>Suggested action:</strong> ${escapeHtml(finding.recommendation)}</p>`;
  return `<tr>
    <td>${severityMarkup(finding.severity)}</td>
    <td><div class="finding-title">${escapeHtml(finding.title)}</div>
      <div class="explanation-controls">
        <button class="explanation-button ${aiSelected ? "" : "selected"}" type="button" data-explanation-mode="rules" data-finding-id="${Number(finding.id)}" aria-pressed="${!aiSelected}">Rule-based</button>
        <button class="explanation-button ${aiSelected ? "selected" : ""}" type="button" data-explanation-mode="ai" data-finding-id="${Number(finding.id)}" aria-pressed="${aiSelected}" ${isLoading ? "disabled" : ""}>${isLoading ? "Generating…" : "Explain with AI"}</button>
      </div>
      <div class="finding-explanation ${aiSelected ? "ai-explanation" : ""}">${explanationBody}</div>
    </td>
    <td class="address-cell">${escapeHtml(asset?.ip || (finding.asset_id ? `Asset #${finding.asset_id}` : "Network-wide"))}</td>
    <td><div class="finding-evidence">${escapeHtml(evidence)}</div></td>
    <td><span class="status-open">● Open</span></td>
  </tr>`;
}

function renderFindings() {
  const findings = state.findings;
  $("#recent-findings").innerHTML = findings.slice(0, 3).map((finding) => {
    const asset = state.assets.find((item) => item.id === finding.asset_id);
    const severity = severityClass(finding.severity);
    return `<div class="finding-mini"><span class="finding-mini-dot" style="background:${severity === "high" || severity === "critical" ? "#fb7c81" : severity === "medium" ? "#f4bd62" : "#65aaff"}"></span><div><div class="finding-mini-title">${escapeHtml(finding.title)}</div><div class="finding-mini-host">${escapeHtml(asset?.ip || "Network finding")}</div></div>${severityMarkup(severity)}</div>`;
  }).join("") || '<div class="table-empty compact-empty"><strong>Nothing to review</strong><span>Run a scan to check for exposed services.</span></div>';
  $("#finding-table-body").innerHTML = findings.map(renderFindingRow).join("");
  $("#finding-empty").hidden = findings.length > 0;
  $("#finding-result-count").textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
}

async function explainFinding(findingId, mode) {
  const finding = state.findings.find((item) => item.id === findingId);
  if (!finding) return;
  if (mode === "rules") {
    state.explanations[findingId] = { mode: "rules" };
    renderFindings();
    return;
  }

  state.explanations[findingId] = { mode: "ai", text: "" };
  state.explanationLoading.add(findingId);
  renderFindings();
  try {
    const result = await api(`/findings/${findingId}/explanation`, { method: "POST" });
    state.explanations[findingId] = {
      mode: "ai",
      text: result.explanation,
      model: result.model,
    };
  } catch (error) {
    state.explanations[findingId] = { mode: "ai", error: error.message };
  } finally {
    state.explanationLoading.delete(findingId);
    renderFindings();
  }
}

function renderHistory() {
  const scans = state.scans;
  $("#history-table-body").innerHTML = scans.map((scan) => {
    const statusClass = ["running", "pending", "failed", "cancelled"].includes(scan.status) ? scan.status : "completed";
    const statusLabel = statusClass.charAt(0).toUpperCase() + statusClass.slice(1);
    return `<tr>
      <td><span class="history-name">${escapeHtml(scan.name || `Scan #${scan.id}`)}</span><span class="history-id">#${Number(scan.id)}</span></td>
      <td><span class="scan-type ${scan.deep_scan ? "deep" : "quick"}">${scan.deep_scan ? "Deep Scan" : "Quick scan"}</span></td>
      <td class="address-cell">${escapeHtml(scan.target_spec || scan.targets || "—")}</td>
      <td><span class="history-status ${statusClass}"><span class="status-dot ${statusClass === "completed" ? "green" : "gray"}"></span>${statusLabel}</span></td>
      <td>${Number(scan.hosts_up || 0)}</td><td>${Number(scan.ports_found || 0)}</td>
      <td>${Number(scan.findings_count || 0)}</td><td>${escapeHtml(dateTime(scan.created_at))}</td>
      <td>${statusClass === "completed" ? `<button class="analysis-button" type="button" data-analyze-scan="${Number(scan.id)}">${state.pipelineLoading.has(scan.id) || state.deepAnalysisLoading.has(scan.id) ? "Analyzing…" : state.deepAnalysisErrors[scan.id] ? "Retry analysis" : "View analysis"}</button>` : '<span class="muted-cell">Available when complete</span>'}</td>
      <td><button class="delete-scan-button" type="button" data-delete-scan="${Number(scan.id)}" aria-label="Delete ${escapeHtml(scan.name || `scan ${scan.id}`)}" ${["pending", "running"].includes(statusClass) ? "disabled title=\"Stop the scan before deleting it\"" : "title=\"Delete this scan\""}>×</button></td>
    </tr>`;
  }).join("");
  $("#history-empty").hidden = scans.length > 0;
  $("#history-result-count").textContent = `${scans.length} scan${scans.length === 1 ? "" : "s"}`;
  renderSelectedPipeline();
}

function renderWorkflow(scan, status) {
  const exists = Boolean(scan);
  const running = ["pending", "running"].includes(status);
  const completed = status === "completed";
  const deep = Boolean(scan?.deep_scan);
  const agentRunning = deep && state.deepAnalysisLoading.has(scan.id);
  const agentDone = deep && Boolean(state.deepAnalyses[scan.id]?.analysis);
  const agentFailed = deep && Boolean(state.deepAnalysisErrors[scan.id]);
  const steps = deep ? [
    ["01", "Agent scope plan", exists ? "Selected and validated service ports" : "Choose useful TCP ports", exists ? "complete" : "pending"],
    ["02", "Safe TCP discovery", running ? "Checking approved targets" : completed ? "Connection checks complete" : "Only the approved addresses", running ? "active" : completed ? "complete" : "pending"],
    ["03", "History comparison", completed ? "Comparing with previous observations" : "Runs after discovery", completed ? "complete" : "pending"],
    ["04", "AI evidence analysis", agentRunning ? "Reviewing measured findings" : agentDone ? "Analysis ready" : agentFailed ? "Analysis needs a retry" : completed ? "Ready to analyze" : "Starts after discovery", agentRunning ? "active" : agentDone ? "complete" : agentFailed ? "attention" : "pending"],
  ] : [
    ["01", "Scope validation", exists ? "Targets checked against safety rules" : "Checks your approved targets", exists ? "complete" : "pending"],
    ["02", "Common-port discovery", running ? "Checking approved targets" : completed ? "Connection checks complete" : "Built-in service ports", running ? "active" : completed ? "complete" : "pending"],
    ["03", "Evidence-based results", completed ? "Findings ranked and verified" : "Results appear after discovery", completed ? "complete" : "pending"],
  ];
  $("#analysis-workflow").innerHTML = `<div class="workflow-title"><strong>${deep ? "Deep Scan workflow" : "Quick Scan workflow"}</strong><span>${deep ? "Local agents plan and analyze · safe checks only" : "Fast, deterministic · safe checks only"}</span></div><ol class="workflow-steps">${steps.map(([number, label, detail, stepState]) => `<li class="workflow-step ${stepState}"><span class="workflow-step-icon">${number}</span><span class="workflow-step-copy"><strong>${label}</strong><small>${detail}</small></span><span class="workflow-step-state">${stepState === "complete" ? "Done" : stepState === "active" ? "In progress" : stepState === "attention" ? "Retry" : "Waiting"}</span></li>`).join("")}</ol>`;
}

function renderSelectedPipeline() {
  const panel = $("#history-analysis");
  if (state.selectedPipelineId === null) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  const scanId = state.selectedPipelineId;
  const scan = state.scans.find((item) => item.id === scanId);
  const name = scan?.name || `Scan #${scanId}`;
  if (state.pipelineLoading.has(scanId)) {
    panel.innerHTML = `<div class="pipeline-loading"><span class="spinner" aria-hidden="true"></span><strong>Loading scan analysis</strong><span>Retrieving history changes, risk ranking, and evidence checks…</span></div>`;
    return;
  }
  if (state.pipelineErrors[scanId]) {
    panel.innerHTML = `<div class="pipeline-heading"><div><div class="eyebrow"><span class="eyebrow-line"></span> SCAN ANALYSIS</div><h2>${escapeHtml(name)}</h2></div><button class="analysis-button" data-dismiss-analysis type="button">Close</button></div><div class="pipeline-error" role="alert">${escapeHtml(state.pipelineErrors[scanId])}</div>`;
    return;
  }
  const pipeline = state.pipelines[scanId];
  if (!pipeline) {
    panel.innerHTML = "";
    panel.hidden = true;
    return;
  }
  const changes = pipeline.evidence_changes || [];
  const ranked = pipeline.review_order || [];
  const verifications = pipeline.verifications || [];
  const changeLabel = (item) => item.port ? `${item.change.replaceAll("_", " ")} · TCP/${Number(item.port)}` : item.change.replaceAll("_", " ");
  panel.innerHTML = `<div class="pipeline-heading"><div><div class="eyebrow"><span class="eyebrow-line"></span> SCAN ANALYSIS</div><h2>${escapeHtml(name)}</h2><p class="panel-description">${scan?.deep_scan ? "Review verified observations alongside the planning agent’s recommendations and evidence-based analysis." : "This deterministic scan compares observed ports with previous scans and verifies findings against evidence."}</p></div><button class="analysis-button" data-dismiss-analysis type="button">Close</button></div>
    <div class="pipeline-grid">
      <section class="pipeline-section"><h3>History comparison <span>${changes.length} change${changes.length === 1 ? "" : "s"}</span></h3>${changes.length ? `<ul class="pipeline-list">${changes.map((item) => `<li><span class="change-marker">${item.change === "baseline" ? "•" : "↗"}</span><div><strong>${escapeHtml(item.ip)} · ${escapeHtml(changeLabel(item))}</strong><small>${escapeHtml(item.evidence)}</small></div></li>`).join("")}</ul>` : '<p class="pipeline-empty">No changes against previously observed hosts and ports.</p>'}</section>
      <section class="pipeline-section"><h3>Risk priority <span>${ranked.length} ranked</span></h3>${ranked.length ? `<ol class="pipeline-list ranked-list">${ranked.map((item) => `<li><span class="rank-number">${Number(item.rank)}</span><div><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.asset_ip || "Network-wide")} · ${escapeHtml(item.priority_grade)} · asset risk ${Number(item.risk_score)}/100</small></div>${severityMarkup(item.severity)}</li>`).join("")}</ol>` : '<p class="pipeline-empty">No findings were generated for this scan.</p>'}</section>
      <section class="pipeline-section verification-section"><h3>Evidence verification <span>${verifications.filter((item) => item.verified).length}/${verifications.length} verified</span></h3>${verifications.length ? `<ul class="pipeline-list">${verifications.map((item) => `<li><span class="verification-mark ${item.verified ? "verified" : "unverified"}">${item.verified ? "✓" : "!"}</span><div><strong>${escapeHtml(item.claim)}</strong><small>${escapeHtml(item.reason)}${item.observed_open_ports?.length ? ` Observed open ports: ${escapeHtml(item.observed_open_ports.join(", "))}.` : ""}</small></div></li>`).join("")}</ul>` : '<p class="pipeline-empty">No findings required verification.</p>'}</section>
    </div>${renderHistoryFindingExplanations(scanId)}${scan?.deep_scan ? renderDeepAnalysis(scanId) : ""}`;
}

function renderHistoryFindingExplanations(scanId) {
  if (state.historyFindingsLoading.has(scanId)) {
    return `<section class="agent-analysis"><div class="pipeline-loading"><span class="spinner" aria-hidden="true"></span><strong>Loading scan findings</strong><span>Retrieving the findings recorded for this scan…</span></div></section>`;
  }
  if (state.historyFindingsErrors[scanId]) {
    return `<section class="agent-analysis"><h3>AI explanations</h3><p class="pipeline-error" role="alert">${escapeHtml(state.historyFindingsErrors[scanId])}</p></section>`;
  }
  const findings = state.historyFindings[scanId] || [];
  const content = findings.length
    ? `<ul class="agent-priorities">${findings.map((finding) => {
      const explanation = state.explanations[finding.id];
      const loading = state.explanationLoading.has(finding.id);
      return `<li><span>${severityMarkup(finding.severity)}</span><span><strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(finding.evidence || finding.description)}</small>${explanation?.mode === "ai"
        ? explanation.error
          ? `<span class="pipeline-error" role="alert">${escapeHtml(explanation.error)}</span>`
          : `<span class="history-ai-explanation"><b>AI explanation${explanation.model ? ` · ${escapeHtml(explanation.model)}` : ""}</b><br>${escapeHtml(explanation.text || "Generating an explanation…")}</span>`
        : ""}<button class="analysis-button" type="button" data-explain-history="${Number(finding.id)}" ${loading ? "disabled" : ""}>${loading ? "Generating…" : explanation?.mode === "ai" ? "Generate again" : "Explain with AI"}</button></span></li>`;
    }).join("")}</ul>`
    : '<p class="pipeline-empty">No findings were recorded for this scan.</p>';
  return `<section class="agent-analysis"><div class="agent-analysis-heading"><div><h3>AI explanations</h3><p>Generate plain-language explanations for this scan’s findings.</p></div></div>${content}</section>`;
}

function renderDeepAnalysis(scanId) {
  if (state.deepAnalysisLoading.has(scanId)) {
    return `<section class="agent-analysis"><div class="pipeline-loading"><span class="spinner" aria-hidden="true"></span><strong>Analysis agent is reviewing the evidence</strong><span>It is comparing history and prioritizing measured findings.</span></div></section>`;
  }
  if (state.deepAnalysisErrors[scanId]) {
    return `<section class="agent-analysis"><div class="agent-analysis-heading"><h3>Deep Scan analysis</h3><button class="analysis-button" data-retry-deep-analysis="${scanId}" type="button">Retry</button></div><p class="pipeline-error" role="alert">${escapeHtml(state.deepAnalysisErrors[scanId])}</p></section>`;
  }
  const result = state.deepAnalyses[scanId];
  if (!result?.analysis) {
    return `<section class="agent-analysis"><div class="agent-analysis-heading"><h3>Deep Scan analysis</h3><button class="analysis-button" data-retry-deep-analysis="${scanId}" type="button">Run analysis</button></div><p class="pipeline-empty">The local analysis agent will summarize scan changes and explain its finding priorities.</p></section>`;
  }
  const analysis = result.analysis;
  const analysisSource = result.model === "No AI analysis needed"
    ? "No findings were detected, so local AI analysis was skipped."
    : `Generated by ${escapeHtml(result.model)} from this scan’s measured results.`;
  const deviceProfile = result.plan?.device_profile;
  const deviceContext = deviceProfile
    ? `<div class="agent-summary"><strong>Scanner device context</strong><p>${escapeHtml(deviceProfile.platform)}${deviceProfile.listeners_available
      ? ` · TCP listeners detected: ${(deviceProfile.listening_services || []).map((listener) => `${Number(listener.port)} (${(listener.processes || []).map(escapeHtml).join(", ")})`).join(", ") || "none"}`
      : " · Could not read local listening ports; using OS and built-in candidates."}</p></div>`
    : "";
  return `<section class="agent-analysis"><div class="agent-analysis-heading"><div><h3>Deep Scan · Agent analysis</h3><p>${analysisSource}</p></div><button class="analysis-button" data-retry-deep-analysis="${scanId}" type="button">View saved analysis</button></div>
    ${deviceContext}<div class="agent-summary"><strong>Overall assessment</strong><p>${escapeHtml(analysis.summary)}</p><strong>History comparison</strong><p>${escapeHtml(analysis.history_summary)}</p></div>
    ${analysis.ranked_findings?.length ? `<h4>Why these findings matter</h4><ol class="agent-priorities">${analysis.ranked_findings.map((item, index) => {
      const finding = (state.pipelines[scanId]?.review_order || []).find((row) => row.finding_id === item.finding_id);
      return `<li><span class="rank-number">${index + 1}</span><span><strong>${escapeHtml(finding?.title || `Finding #${item.finding_id}`)}</strong><small>${escapeHtml(finding?.asset_ip || "Network-wide")} · ${escapeHtml(finding?.severity || "unverified")}</small><span>${escapeHtml(item.rationale)}</span></span></li>`;
    }).join("")}</ol>` : ""}
    ${analysis.recommendations?.length ? `<h4>Suggested next steps</h4><ul class="agent-recommendations">${analysis.recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}
  </section>`;
}

async function loadDeepAnalysis(scanId) {
  if (state.deepAnalysisLoading.has(scanId)) return;
  state.deepAnalysisLoading.add(scanId);
  delete state.deepAnalysisErrors[scanId];
  renderSelectedPipeline();
  try {
    state.deepAnalyses[scanId] = await api(`/scans/${scanId}/deep-analysis`, { method: "POST" });
  } catch (error) {
    state.deepAnalysisErrors[scanId] = error.message;
    setNotice(`Deep Scan analysis failed: ${error.message}`);
  } finally {
    state.deepAnalysisLoading.delete(scanId);
    renderHistory();
    const scan = state.scans.find((item) => item.id === scanId);
    if (scan) renderCurrentScan(scan);
  }
}

async function loadPipeline(scanId) {
  state.selectedPipelineId = scanId;
  state.pipelineErrors[scanId] = "";
  state.pipelineLoading.add(scanId);
  state.historyFindingsLoading.add(scanId);
  renderHistory();
  try {
    const [pipeline, findings] = await Promise.all([
      api(`/scans/${scanId}/pipeline`),
      api(`/findings?scan_id=${scanId}&limit=200`),
    ]);
    state.pipelines[scanId] = pipeline;
    state.historyFindings[scanId] = findings;
    delete state.historyFindingsErrors[scanId];
  } catch (error) {
    state.pipelineErrors[scanId] = error.message;
    state.historyFindingsErrors[scanId] = error.message;
  } finally {
    state.pipelineLoading.delete(scanId);
    state.historyFindingsLoading.delete(scanId);
    renderHistory();
  }
  const scan = state.scans.find((item) => item.id === scanId);
  if (scan?.deep_scan) await loadDeepAnalysis(scanId);
  $("#history-analysis").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function explainHistoryFinding(findingId, scanId) {
  if (state.explanationLoading.has(findingId)) return;
  state.explanationLoading.add(findingId);
  state.explanations[findingId] = { mode: "ai", text: "" };
  renderSelectedPipeline();
  try {
    const result = await api(`/findings/${findingId}/explanation`, { method: "POST" });
    state.explanations[findingId] = {
      mode: "ai",
      text: result.explanation,
      model: result.model,
    };
  } catch (error) {
    state.explanations[findingId] = { mode: "ai", error: error.message };
    setNotice(`AI explanation failed: ${error.message}`);
  } finally {
    state.explanationLoading.delete(findingId);
    if (state.selectedPipelineId === scanId) renderSelectedPipeline();
  }
}

function renderCurrentScan(scan, progress = null) {
  const pill = $("#current-scan-state");
  const content = $("#current-scan-content");
  if (!scan) {
    renderWorkflow(null, "idle");
    pill.className = "scan-state-pill";
    pill.innerHTML = '<span class="status-dot gray"></span> IDLE';
    content.className = "empty-activity";
    content.innerHTML = '<div class="empty-orbit"><span>⌁</span></div><strong>Ready when you are</strong><p>Start a scan to discover devices and open services.</p>';
    return;
  }
  const status = progress?.status || scan.status;
  renderWorkflow(scan, status);
  const running = ["pending", "running"].includes(status);
  pill.className = `scan-state-pill ${running ? "running" : status === "failed" ? "failed" : ""}`;
  pill.innerHTML = `<span class="status-dot ${running ? "green" : status === "completed" ? "green" : "gray"}"></span> ${escapeHtml(status).toUpperCase()}`;
  const done = Number(progress?.completed_targets ?? scan.completed_targets ?? 0);
  const total = Number(progress?.total_targets ?? scan.total_targets ?? 0);
  const percent = total > 0 ? Math.min(100, Math.round(done / total * 100)) : (status === "completed" ? 100 : 0);
  if (running) {
    content.className = "scan-progress";
    content.innerHTML = `<div class="scan-progress-head"><strong>${escapeHtml(scan.name || `Scan #${scan.id}`)}</strong><span>${total ? `${percent}%` : "Preparing"}</span></div>
      <div class="scan-progress-meta">${total ? `${done} of ${total} targets checked` : "Waiting for the local worker to start"}</div>
      <div class="progress-track"><div class="progress-fill ${total ? "" : "indeterminate"}" style="width:${total ? `${percent}%` : "35%"}"></div></div>
      <div class="scan-progress-bottom"><span>${Number(progress?.hosts_up ?? scan.hosts_up ?? 0)} devices · ${Number(progress?.ports_found ?? scan.ports_found ?? 0)} services</span><button class="cancel-button" data-cancel-scan="${Number(scan.id)}">Cancel scan</button></div>`;
  } else if (status === "completed") {
    content.className = "";
    const resultSummary = `${Number(progress?.hosts_up ?? scan.hosts_up ?? 0)} responding devices, ${Number(progress?.ports_found ?? scan.ports_found ?? 0)} open services, and ${Number(progress?.findings_count ?? scan.findings_count ?? 0)} findings.`;
    const agentStatus = scan.deep_scan
      ? state.deepAnalysisLoading.has(scan.id)
        ? "The analysis agent is reviewing the measured results now."
        : state.deepAnalysisErrors[scan.id]
          ? "Scan is complete; the analysis agent needs a retry in Scan History."
          : state.deepAnalyses[scan.id]?.analysis
            ? "The analysis agent has completed its evidence review."
            : "The local analysis agent is preparing its review."
      : "Findings are ranked from deterministic rules and saved evidence.";
    content.innerHTML = `<div class="scan-complete"><strong>✓ ${scan.deep_scan ? "Deep Scan discovery complete" : "Quick Scan complete"}</strong><p>${escapeHtml(scan.name || `Scan #${scan.id}`)} found ${resultSummary}</p><p>${escapeHtml(agentStatus)}</p></div>`;
  } else {
    const detail = progress?.error_message || scan.error_message || (status === "cancelled" ? "This scan was cancelled." : "The scan did not complete.");
    content.className = "";
    content.innerHTML = `<div class="scan-complete scan-message"><strong>${escapeHtml(status === "cancelled" ? "Scan cancelled" : "Scan needs attention")}</strong><p>${escapeHtml(detail)}</p></div>`;
  }
  const cancelButton = content.querySelector("[data-cancel-scan]");
  if (cancelButton) cancelButton.addEventListener("click", () => cancelScan(Number(cancelButton.dataset.cancelScan)));
}

function renderOverview() {
  renderStats();
  renderAssets();
  renderFindings();
  renderHistory();
  const current = activeScan() || (state.watchedScanId ? state.scans.find((scan) => scan.id === state.watchedScanId) : null);
  renderCurrentScan(current, state.progress);
}

async function refreshData(manual = false) {
  if (state.refreshInFlight) {
    state.refreshQueued = true;
    state.manualRefreshQueued = state.manualRefreshQueued || manual;
    return;
  }
  state.refreshInFlight = true;
  const refreshButton = $("#refresh-button");
  refreshButton.classList.add("is-refreshing");
  refreshButton.disabled = true;
  try {
    const [stats, assets, findings, scans] = await Promise.all([
      api("/stats/overview"),
      api("/assets?limit=200"),
      api("/findings?status=open&limit=100"),
      api("/scans?limit=50"),
    ]);
    state.stats = stats;
    state.assets = assets;
    state.findings = findings;
    state.scans = scans;
    setApiStatus(true);
    const active = activeScan();
    if (active) state.watchedScanId = active.id;
    renderOverview();
    if (state.watchedScanId && active) await refreshProgress(state.watchedScanId);
    else if (state.watchedScanId) {
      const finished = scans.find((scan) => scan.id === state.watchedScanId);
      if (finished) {
        renderCurrentScan(finished);
        if (finished.deep_scan && !state.deepAnalyses[finished.id] && !state.deepAnalysisErrors[finished.id] && !state.deepAnalysisLoading.has(finished.id)) {
          void loadDeepAnalysis(finished.id);
        }
      }
    }
    if (manual) setNotice("Dashboard refreshed.", "success");
  } catch (error) {
    setApiStatus(false);
    console.error("Could not refresh dashboard data:", error);
    if (manual) setNotice(`Could not refresh dashboard: ${error.message}`);
  } finally {
    state.refreshInFlight = false;
    refreshButton.classList.remove("is-refreshing");
    refreshButton.disabled = false;
    if (state.refreshQueued) {
      const queuedManual = state.manualRefreshQueued;
      state.refreshQueued = false;
      state.manualRefreshQueued = false;
      void refreshData(queuedManual);
    }
  }
}

async function refreshProgress(scanId) {
  try {
    state.progress = await api(`/scans/${scanId}/progress`);
    const scan = state.scans.find((item) => item.id === scanId) || { id: scanId, status: state.progress.status };
    renderCurrentScan(scan, state.progress);
    if (TERMINAL.has(state.progress.status)) {
      state.watchedScanId = scanId;
      state.progress = null;
      await refreshData();
    }
  } catch (error) {
    console.error(`Could not refresh scan ${scanId}:`, error);
  }
}

async function cancelScan(scanId) {
  try {
    await api(`/scans/${scanId}/cancel`, { method: "POST" });
    setNotice("Scan cancelled.", "success");
    await refreshData();
  } catch (error) {
    setNotice(error.message);
  }
}

function bindAssetRows() {
  $$(".asset-row").forEach((row) => row.addEventListener("click", () => {
    const asset = state.assets.find((item) => item.id === Number(row.dataset.assetId));
    if (!asset) return;
    const details = (asset.services || []).map((service) => `TCP/${service.port}${service.service_name ? ` · ${service.service_name}` : ""}`).join("\n");
    setNotice(details ? `${asset.ip} services:\n${details}` : `${asset.ip} responded to a TCP connection check; no configured ports returned an open service.`, "info");
  }));
}

function scanInput(includePorts = false) {
  const fields = new FormData($("#scan-form"));
  const name = String(fields.get("name") || "").trim();
  const typedTargets = String(fields.get("targets") || "").trim();
  const selectedTargets = $$('input[name="target-preset"]:checked').map((input) => input.value);
  const targets = [...selectedTargets, typedTargets].filter(Boolean).join(",");
  const request = { name: name || null, targets };

  const selectedPorts = $$('input[name="port-preset"]:checked').map((input) => input.value.trim()).filter(Boolean);
  const manualPorts = String(fields.get("ports") || "")
    .split(/[\s,]+/)
    .map((part) => part.trim())
    .filter(Boolean);
  const ports = [...new Set([...selectedPorts, ...manualPorts])].join(",");
  if (includePorts && ports) request.ports = ports;
  return request;
}

function validateScanRequest(request) {
  if (!request.targets) {
    setNotice("Choose a target preset or enter an address.");
    return false;
  }
  if (!$("#scan-authorized").checked) {
    setNotice("Confirm that you own these targets or have permission to scan them.");
    return false;
  }
  return true;
}

function setScanFormDisabled(disabled) {
  $$("#scan-form input").forEach((input) => { input.disabled = disabled; });
}

async function quickScan() {
  const request = scanInput(true);
  if (!validateScanRequest(request)) return;
  const button = $("#quick-scan");
  button.disabled = true;
  button.classList.add("is-loading");
  setScanFormDisabled(true);
  try {
    const scan = await api("/scans", {
      method: "POST",
      body: JSON.stringify(request),
    });
    state.watchedScanId = scan.id;
    state.progress = null;
    setNotice(request.ports
      ? "Quick Scan queued with your custom port selection."
      : "Quick Scan queued. Checking the selected targets with common service ports.", "success");
    await refreshData();
  } catch (error) {
    setNotice(error.message);
  } finally {
    button.disabled = false;
    button.classList.remove("is-loading");
    setScanFormDisabled(false);
  }
}

async function prepareDeepScan() {
  const request = scanInput();
  if (!validateScanRequest(request)) return;
  const button = $("#deep-scan");
  button.disabled = true;
  button.classList.add("is-loading");
  button.querySelector("span").textContent = "Planning with AI…";
  setScanFormDisabled(true);
  state.scopePlan = null;
  state.scanRequest = null;
  $("#scope-plan").hidden = true;
  try {
    const result = await api("/scans/deep/plan", {
      method: "POST",
      body: JSON.stringify(request),
    });
    state.scopePlan = result.plan;
    state.scanRequest = request;
    const deviceProfile = state.scopePlan.device_profile;
    const localListeners = (deviceProfile?.listening_services || [])
      .map((listener) => `${Number(listener.port)} (${(listener.processes || []).map(escapeHtml).join(", ")})`)
      .join(", ");
    $("#scope-plan-content").innerHTML = `<div class="plan-metrics"><span><strong>${Number(state.scopePlan.host_ips.length).toLocaleString()}</strong><small>authorized hosts</small></span><span><strong>${Number(state.scopePlan.ports.length).toLocaleString()}</strong><small>agent-selected ports</small></span><span><strong>${Number(state.scopePlan.check_count).toLocaleString()}</strong><small>TCP checks</small></span></div>
      <div class="plan-detail"><strong>Targets (unchanged)</strong><code>${escapeHtml(state.scopePlan.target_spec)}</code></div>
      <div class="plan-detail"><strong>Exact authorized addresses</strong><code>${escapeHtml(state.scopePlan.host_ips.join(", "))}</code></div>
      ${deviceProfile ? `<div class="plan-detail"><strong>Scanner device context</strong><code>${escapeHtml(deviceProfile.platform)} · ${deviceProfile.listeners_available ? `Listening TCP ports: ${localListeners || "none"}` : "Local listener details unavailable; OS and built-in candidates used."}</code></div>` : ""}
      <div class="plan-detail"><strong>Selected ports · ${escapeHtml(state.scopePlan.model)}</strong><code>${escapeHtml(state.scopePlan.ports.join(", "))}</code></div>
      <div class="plan-detail"><strong>Agent's reason for this selection</strong><p class="agent-rationale">${escapeHtml(state.scopePlan.rationale)}</p></div>`;
    $("#scope-plan").hidden = false;
    $("#scope-plan").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    setNotice(error.status === 404
      ? "Deep Scan is not available in the running backend. Stop and restart Netra AI from the updated backend, then try again."
      : error.message);
  } finally {
    button.disabled = false;
    button.classList.remove("is-loading");
    button.querySelector("span").textContent = "Deep Scan";
    setScanFormDisabled(false);
  }
}

function invalidateScopePlan() {
  state.scopePlan = null;
  state.scanRequest = null;
  if (!$("#scope-plan")) return;
  $("#scope-plan").hidden = true;
}

async function approveScan() {
  if (!state.scopePlan || !state.scanRequest) {
    setNotice("Create and review the agent plan before approving the Deep Scan.");
    return;
  }
  const button = $("#approve-scan");
  button.disabled = true;
  button.classList.add("is-loading");
  button.querySelector("span").textContent = "Queuing approved scan…";
  setScanFormDisabled(true);
  try {
    const result = await api("/scans/deep", {
      method: "POST",
      body: JSON.stringify({
        ...state.scanRequest,
        ports: state.scopePlan.ports,
        rationale: state.scopePlan.rationale,
      }),
    });
    const scan = result.scan;
    state.watchedScanId = scan.id;
    state.progress = null;
    state.scopePlan = null;
    state.scanRequest = null;
    $("#scope-plan").hidden = true;
    setNotice("Deep Scan queued. The scan agent will review measured results when discovery finishes.", "success");
    await refreshData();
  } catch (error) {
    setNotice(error.status === 404
      ? "Deep Scan is not available in the running backend. Stop and restart Netra AI from the updated backend, then try again."
      : error.message);
  } finally {
    button.disabled = false;
    button.classList.remove("is-loading");
    button.querySelector("span").textContent = "Approve plan & start Deep Scan";
    setScanFormDisabled(false);
  }
}

async function deleteScan(scanId) {
  const scan = state.scans.find((item) => item.id === scanId);
  if (!scan || ["pending", "running"].includes(scan.status)) {
    setNotice("Stop an active scan before deleting it.");
    return;
  }
  if (!window.confirm(`Delete "${scan.name || `Scan #${scanId}`}" and its saved analysis?`)) return;
  try {
    await api(`/scans/${scanId}`, { method: "DELETE" });
    delete state.pipelines[scanId];
    delete state.deepAnalyses[scanId];
    delete state.deepAnalysisErrors[scanId];
    delete state.historyFindings[scanId];
    delete state.historyFindingsErrors[scanId];
    if (state.selectedPipelineId === scanId) state.selectedPipelineId = null;
    if (state.watchedScanId === scanId) {
      state.watchedScanId = null;
      state.progress = null;
    }
    setNotice("Scan and its saved analysis deleted.", "success");
    await refreshData();
  } catch (error) {
    setNotice(error.message);
  }
}

async function deleteAllScans() {
  if (!state.scans.length) {
    setNotice("There is no scan history to delete.", "info");
    return;
  }
  if (!window.confirm("Delete all completed and stopped scans and clear all current assets and findings? Active scans will be kept.")) return;
  const button = $("#delete-all-scans");
  button.disabled = true;
  try {
    const result = await api("/scans", { method: "DELETE" });
    state.pipelines = {};
    state.deepAnalyses = {};
    state.deepAnalysisErrors = {};
    state.historyFindings = {};
    state.historyFindingsErrors = {};
    state.selectedPipelineId = null;
    const watched = state.scans.find((scan) => scan.id === state.watchedScanId);
    if (watched && !["pending", "running"].includes(watched.status)) {
      state.watchedScanId = null;
      state.progress = null;
    }
    setNotice(
      `${result.deleted_count} scan${result.deleted_count === 1 ? "" : "s"} deleted; current assets and findings cleared.${result.retained_active_count ? ` ${result.retained_active_count} active scan${result.retained_active_count === 1 ? " was" : "s were"} kept.` : ""}`,
      "success",
    );
    await refreshData();
  } catch (error) {
    setNotice(error.message);
  } finally {
    button.disabled = false;
  }
}

function showView(name) {
  const valid = ["overview", "assets", "findings", "history"].includes(name) ? name : "overview";
  $$(".view-panel").forEach((panel) => panel.classList.toggle("active", panel.id === `view-${valid}`));
  $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === valid));
  const labels = { overview: "Overview", assets: "Assets", findings: "Findings", history: "Scan history" };
  $("#current-section").textContent = labels[valid];
}

$("#scan-form").addEventListener("submit", (event) => {
  event.preventDefault();
  quickScan();
});
$("#scan-form").addEventListener("input", invalidateScopePlan);
$("#scan-form").addEventListener("change", invalidateScopePlan);
$("#quick-scan").addEventListener("click", quickScan);
$("#deep-scan").addEventListener("click", prepareDeepScan);
$("#approve-scan").addEventListener("click", approveScan);
$$(".nav-item").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
$$("[data-view-link]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.viewLink)));
$("#jump-to-scan").addEventListener("click", () => {
  showView("overview");
  $("#scan-targets").focus({ preventScroll: true });
  $("#new-scan-panel").scrollIntoView({ behavior: "smooth", block: "center" });
});
$("#refresh-button").addEventListener("click", () => refreshData(true));
$("#delete-all-scans").addEventListener("click", deleteAllScans);
$("#finding-table-body").addEventListener("click", (event) => {
  const button = event.target.closest("[data-explanation-mode]");
  if (!button) return;
  explainFinding(Number(button.dataset.findingId), button.dataset.explanationMode);
});
$("#history-table-body").addEventListener("click", (event) => {
  const target = event.target;
  const deleteButton = target.closest("[data-delete-scan]");
  if (deleteButton) {
    deleteScan(Number(deleteButton.dataset.deleteScan));
    return;
  }
  const retryButton = target.closest("[data-retry-deep-analysis]");
  if (retryButton) {
    loadDeepAnalysis(Number(retryButton.dataset.retryDeepAnalysis));
    return;
  }
  const analyzeButton = target.closest("[data-analyze-scan]");
  if (analyzeButton) loadPipeline(Number(analyzeButton.dataset.analyzeScan));
});
$("#history-analysis").addEventListener("click", (event) => {
  const explainButton = event.target.closest("[data-explain-history]");
  if (explainButton) {
    explainHistoryFinding(
      Number(explainButton.dataset.explainHistory),
      state.selectedPipelineId,
    );
    return;
  }
  const retryButton = event.target.closest("[data-retry-deep-analysis]");
  if (retryButton) {
    loadDeepAnalysis(Number(retryButton.dataset.retryDeepAnalysis));
    return;
  }
  if (event.target.closest("[data-dismiss-analysis]")) {
    state.selectedPipelineId = null;
    renderSelectedPipeline();
  }
});

state.pollTimer = setInterval(refreshData, 5000);
refreshData();
