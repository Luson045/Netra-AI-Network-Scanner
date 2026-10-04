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
    throw new Error(message);
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
  return `<tr>
    <td>${severityMarkup(finding.severity)}</td>
    <td><div class="finding-title">${escapeHtml(finding.title)}</div><div class="finding-description">${escapeHtml(finding.description)}</div><div class="recommendation">${escapeHtml(finding.recommendation)}</div></td>
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

function renderHistory() {
  const scans = state.scans;
  $("#history-table-body").innerHTML = scans.map((scan) => {
    const statusClass = ["running", "pending", "failed", "cancelled"].includes(scan.status) ? scan.status : "completed";
    const statusLabel = statusClass.charAt(0).toUpperCase() + statusClass.slice(1);
    return `<tr>
      <td><span class="history-name">${escapeHtml(scan.name || `Scan #${scan.id}`)}</span><span class="history-id">#${Number(scan.id)}</span></td>
      <td class="address-cell">${escapeHtml(scan.target_spec || scan.targets || "—")}</td>
      <td><span class="history-status ${statusClass}"><span class="status-dot ${statusClass === "completed" ? "green" : "gray"}"></span>${statusLabel}</span></td>
      <td>${Number(scan.hosts_up || 0)}</td><td>${Number(scan.ports_found || 0)}</td>
      <td>${Number(scan.findings_count || 0)}</td><td>${escapeHtml(dateTime(scan.created_at))}</td>
    </tr>`;
  }).join("");
  $("#history-empty").hidden = scans.length > 0;
  $("#history-result-count").textContent = `${scans.length} scan${scans.length === 1 ? "" : "s"}`;
}

function renderCurrentScan(scan, progress = null) {
  const pill = $("#current-scan-state");
  const content = $("#current-scan-content");
  if (!scan) {
    pill.className = "scan-state-pill";
    pill.innerHTML = '<span class="status-dot gray"></span> IDLE';
    content.className = "empty-activity";
    content.innerHTML = '<div class="empty-orbit"><span>⌁</span></div><strong>Ready when you are</strong><p>Start a scan to discover devices and open services.</p>';
    return;
  }
  const status = progress?.status || scan.status;
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
      <div class="progress-track"><div class="progress-fill" style="width:${percent}%"></div></div>
      <div class="scan-progress-bottom"><span>${Number(progress?.hosts_up ?? scan.hosts_up ?? 0)} devices · ${Number(progress?.ports_found ?? scan.ports_found ?? 0)} services</span><button class="cancel-button" data-cancel-scan="${Number(scan.id)}">Cancel scan</button></div>`;
  } else if (status === "completed") {
    content.className = "";
    content.innerHTML = `<div class="scan-complete"><strong>✓ Scan complete</strong><p>${escapeHtml(scan.name || `Scan #${scan.id}`)} found ${Number(progress?.hosts_up ?? scan.hosts_up ?? 0)} responding devices, ${Number(progress?.ports_found ?? scan.ports_found ?? 0)} open services, and ${Number(progress?.findings_count ?? scan.findings_count ?? 0)} rule-based findings.</p><p>Results have been saved locally.</p></div>`;
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

async function refreshData() {
  if (state.refreshInFlight) return;
  state.refreshInFlight = true;
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
      if (finished) renderCurrentScan(finished);
    }
  } catch (error) {
    setApiStatus(false);
    console.error("Could not refresh dashboard data:", error);
  } finally {
    state.refreshInFlight = false;
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

async function startScan(form) {
  const fields = new FormData(form);
  const name = String(fields.get("name") || "").trim();
  const targets = String(fields.get("targets") || "").trim();
  const ports = String(fields.get("ports") || "").trim();
  if (!$("#scan-authorized").checked) {
    setNotice("Confirm that you own these targets or are authorized to scan them.");
    return;
  }
  const button = $("#scan-submit");
  button.disabled = true;
  button.querySelector("span").textContent = "Validating scope…";
  try {
    const preview = await api("/scans/preview", {
      method: "POST",
      body: JSON.stringify({ name: name || null, targets, ports: ports || null }),
    });
    const scope = preview.targets.join(", ");
    const portList = preview.ports.join(", ");
    const approved = window.confirm(
      `Review approved scope\n\nTargets (${preview.host_count}): ${scope}\nTCP ports (${preview.ports.length}): ${portList}\nConnection checks: ${preview.check_count}\n\nOnly safe TCP connection checks will run. Continue?`,
    );
    if (!approved) return;
    button.querySelector("span").textContent = "Queuing scan…";
    const scan = await api("/scans", {
      method: "POST",
      body: JSON.stringify({ name: name || null, targets, ports: ports || null }),
    });
    state.watchedScanId = scan.id;
    state.progress = null;
    setNotice("Scan scope accepted. The local worker is starting your scan.", "success");
    await refreshData();
  } catch (error) {
    setNotice(error.message);
  } finally {
    button.disabled = false;
    button.querySelector("span").textContent = "Start safe scan";
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
  startScan(event.currentTarget);
});
$$(".nav-item").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
$$("[data-view-link]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.viewLink)));
$("#jump-to-scan").addEventListener("click", () => {
  showView("overview");
  $("#scan-targets").focus({ preventScroll: true });
  $("#new-scan-panel").scrollIntoView({ behavior: "smooth", block: "center" });
});
$("#refresh-button").addEventListener("click", () => refreshData());

state.pollTimer = setInterval(refreshData, 5000);
refreshData();
