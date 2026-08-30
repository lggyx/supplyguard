// SupplyGuard console — hand-written vanilla ES module (zero dependencies
// for logic; ECharts is vendored for the chart). No build step, no framework.

const state = {
  view: "overview",
  summary: null,
  recent: [],
  detail: null,
  auditEntries: [],
  auditVerification: null,
  lastCounts: {},
  chart: null,
  es: null,
  retry: 0,
  refreshTimer: null,
};

const $ = (id) => document.getElementById(id);

const TITLES = {
  overview: "总览 Overview",
  scans: "扫描详情 Scan Detail",
  timeline: "裁决时间线 Timeline",
  audit: "审计链 Audit Chain",
};

function show(el) { el.classList.remove("hidden"); }
function hide(el) { el.classList.add("hidden"); }

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function api(path, options) {
  const response = await fetch(path, options);
  const text = await response.text();
  let body = {};
  try { body = text ? JSON.parse(text) : {}; } catch { body = {}; }
  if (!response.ok) throw new Error(body?.error?.code || String(response.status));
  return body;
}

function markError(err) {
  $("errorText").textContent =
    "数据加载失败：" + (err?.message || "网络错误") + " —— 可点击重试";
  show($("errorBar"));
}

function setConn(on) {
  $("conn").classList.toggle("off", !on);
  $("connLabel").textContent = on ? "SSE 已连接" : "连接断开";
  $("navDot").classList.toggle("off", !on);
  if (on) hide($("reconnBar")); else show($("reconnBar"));
}

/* ---------- data loading ---------- */

async function refreshOverview() {
  state.summary = await api("/api/overview");
  state.recent = state.summary.recent_sessions || [];
  renderOverview();
}

async function refreshAudit() {
  const data = await api("/api/audit");
  state.auditEntries = data.entries || [];
  state.auditVerification = data.verification;
  renderAudit();
}

let refreshing = false;
async function refreshAll() {
  if (refreshing) return;
  refreshing = true;
  hide($("errorBar"));
  show($("recentSkeleton"));
  try {
    await Promise.all([refreshOverview(), refreshAudit()]);
  } catch (err) {
    markError(err);
  } finally {
    refreshing = false;
    hide($("recentSkeleton"));
  }
}

async function loadDetail(id) {
  try {
    state.detail = await api("/api/scans/" + id);
    renderDetail();
  } catch (err) { markError(err); }
}

async function loadTimeline() {
  const id = $("timelineSession").value;
  if (!id) return;
  try {
    const data = await api("/api/scans/" + id + "/timeline");
    renderTimeline(data.steps || []);
  } catch (err) { markError(err); }
}

/* ---------- rendering ---------- */

function riskCards() {
  const s = state.summary || {};
  return [
    { label: "critical", value: s.critical || 0, cls: "critical" },
    { label: "high", value: s.high || 0, cls: "high" },
    { label: "medium", value: s.medium || 0, cls: "medium" },
    { label: "low", value: s.low || 0, cls: "low" },
    { label: "sessions", value: s.total_sessions || 0, cls: "" },
  ];
}

function renderOverview() {
  const cards = riskCards().map((c) => {
    const bump = state.lastCounts[c.label] !== undefined && state.lastCounts[c.label] !== c.value
      ? " bump" : "";
    return '<div class="card stat ' + c.cls + '">' +
      '<div class="stat-num' + bump + '">' + escapeHtml(c.value) + "</div>" +
      '<div class="stat-label">' + escapeHtml(c.label) + "</div></div>";
  }).join("");
  $("statCards").innerHTML = cards;
  state.lastCounts = Object.fromEntries(
    riskCards().map((c) => [c.label, c.value]),
  );

  if (state.recent.length === 0) {
    show($("recentEmpty"));
    hide($("recentTable"));
  } else {
    hide($("recentEmpty"));
    show($("recentTable"));
    $("recentBody").innerHTML = state.recent.map((r) =>
      "<tr><td class=\"mono\">" + escapeHtml(r.session_id) + "</td>" +
      "<td>" + escapeHtml(r.source) + "</td>" +
      "<td><span class=\"pill " + escapeHtml(r.risk_level) + "\">" + escapeHtml(r.risk_level) + "</span></td>" +
      "<td><span class=\"pill " + escapeHtml(r.verdict) + "\">" + escapeHtml(r.verdict) + "</span></td></tr>",
    ).join("");
  }
  renderChart();
  renderSessionPickers();
}

function renderSessionPickers() {
  // Session list in the scans view.
  if (state.recent.length === 0) {
    show($("scanListEmpty"));
    hide($("scanListTable"));
  } else {
    hide($("scanListEmpty"));
    show($("scanListTable"));
    $("scanListBody").innerHTML = state.recent.map((r) =>
      "<tr><td class=\"mono\">" + escapeHtml(r.session_id) + "</td>" +
      "<td><span class=\"pill " + escapeHtml(r.risk_level) + "\">" + escapeHtml(r.risk_level) + "</span></td>" +
      "<td><span class=\"pill " + escapeHtml(r.verdict) + "\">" + escapeHtml(r.verdict) + "</span></td>" +
      "<td><button class=\"btn small\" data-detail=\"" + escapeHtml(r.session_id) + "\">查看</button></td></tr>",
    ).join("");
    for (const button of document.querySelectorAll("[data-detail]")) {
      button.addEventListener("click", () => loadDetail(button.dataset.detail));
    }
  }
  // Timeline picker.
  const picker = $("timelineSession");
  const previous = picker.value;
  picker.innerHTML = state.recent.map((r) =>
    "<option value=\"" + escapeHtml(r.session_id) + "\">" + escapeHtml(r.session_id) + "</option>",
  ).join("");
  if (state.recent.some((r) => r.session_id === previous)) picker.value = previous;
  if (state.recent.length === 0) {
    show($("timelineEmpty"));
    hide($("timelinePicker"));
    hide($("timelineSteps"));
  } else {
    hide($("timelineEmpty"));
    show($("timelinePicker"));
  }
}

function renderDetail() {
  const detail = state.detail;
  if (!detail) { hide($("detailPanel")); return; }
  show($("detailPanel"));
  $("detailSession").textContent = detail.session_id;
  const reasons = detail.risk_profile?.human_review_reasons || [];
  $("detailReasons").innerHTML = reasons.map((reason) =>
    '<div class="reason">' + escapeHtml(reason) + "</div>").join("");
  const packages = detail.snapshot?.packages || [];
  if (packages.length === 0) { hide($("pkgTable")); } else {
    show($("pkgTable"));
    $("pkgBody").innerHTML = packages.map((p) =>
      "<tr><td class=\"mono\">" + escapeHtml(p.name) + "</td>" +
      "<td class=\"mono\">" + escapeHtml(p.version) + "</td>" +
      "<td>" + escapeHtml(p.license || "unknown") + "</td>" +
      "<td>" + (p.direct ? "是" : "否") + "</td></tr>").join("");
  }
  const evidence = detail.risk_profile?.evidence_chain || [];
  if (evidence.length === 0) { hide($("evidenceTable")); } else {
    show($("evidenceTable"));
    $("evidenceBody").innerHTML = evidence.map((e) =>
      "<tr><td class=\"mono\">" + escapeHtml(e.skill) + "</td>" +
      "<td>" + escapeHtml(e.source) + "</td>" +
      "<td>" + escapeHtml(e.confidence) + "</td>" +
      "<td class=\"wrap\">" + escapeHtml(e.summary) + "</td></tr>").join("");
  }
}

function renderTimeline(steps) {
  const el = $("timelineSteps");
  if (!steps || steps.length === 0) { hide(el); return; }
  show(el);
  el.innerHTML = steps.map((step, index) => {
    const done = index < steps.length - 1 ? " done" : "";
    const time = new Date(Number(step.timestamp)).toLocaleTimeString();
    return '<div class="tl-node"><div class="tl-dot' + done + '"></div>' +
      '<div class="tl-state">' + escapeHtml(step.state) + "</div>" +
      '<div class="tl-time dim mono">' + escapeHtml(time) + "</div></div>";
  }).join("");
}

function renderAudit() {
  const intact = state.auditVerification?.intact;
  const pill = $("auditPill");
  if (state.auditVerification) {
    show(pill);
    pill.className = "pill " + (intact ? "ok" : "danger");
    pill.textContent = intact ? "✓ 链完整" : "✗ 自 " + (state.auditVerification.broken_at ?? "?") + " 号起断裂";
  }
  if (state.auditEntries.length === 0) {
    show($("auditEmpty"));
    hide($("auditTable"));
  } else {
    hide($("auditEmpty"));
    show($("auditTable"));
    $("auditBody").innerHTML = state.auditEntries.map((e) =>
      "<tr><td>" + escapeHtml(e.id) + "</td>" +
      "<td class=\"mono\">" + escapeHtml(e.session_id) + "</td>" +
      "<td>" + escapeHtml(e.event) + "</td>" +
      "<td>" + escapeHtml(e.verdict || "—") + "</td>" +
      "<td class=\"mono wrap\">" + escapeHtml(e.evidence_hash || "—") + "</td>" +
      "<td class=\"mono wrap\">" + escapeHtml((e.entry_hash || []).slice(0, 6).join("")) + "…</td></tr>").join("");
  }
}

/* ---------- chart ---------- */

function tokenColor(name, fallback) {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

function renderChart() {
  const el = $("chart-risk");
  if (!el || typeof echarts === "undefined") return;
  if (!state.chart) {
    state.chart = echarts.init(el, null, { renderer: "canvas" });
    window.addEventListener("resize", () => state.chart && state.chart.resize());
  }
  const s = state.summary || {};
  state.chart.setOption({
    backgroundColor: "transparent",
    textStyle: { color: tokenColor("--text-2", "#9aa3b8") },
    tooltip: { trigger: "item" },
    series: [{
      type: "pie",
      radius: ["52%", "78%"],
      itemStyle: {
        borderColor: tokenColor("--bg-1", "#11151f"),
        borderWidth: 2,
        borderRadius: 6,
      },
      label: { color: tokenColor("--text-2", "#9aa3b8") },
      data: [
        { name: "critical", value: s.critical || 0, itemStyle: { color: tokenColor("--critical", "#f43f5e") } },
        { name: "high", value: s.high || 0, itemStyle: { color: tokenColor("--danger", "#f87171") } },
        { name: "medium", value: s.medium || 0, itemStyle: { color: tokenColor("--warn", "#fbbf24") } },
        { name: "low", value: s.low || 0, itemStyle: { color: tokenColor("--ok", "#34d399") } },
      ].filter((d) => d.value > 0),
    }],
  });
}

/* ---------- SSE ---------- */

function connectSse() {
  if (state.es) state.es.close();
  state.es = new EventSource("/api/events");
  state.es.onopen = () => { state.retry = 0; setConn(true); };
  state.es.onerror = () => {
    setConn(false);
    const delay = Math.min(5000, 500 * 2 ** state.retry);
    state.retry += 1;
    setTimeout(connectSse, delay);
  };
  const debouncedRefresh = () => {
    clearTimeout(state.refreshTimer);
    state.refreshTimer = setTimeout(() => { refreshAll(); }, 200);
  };
  for (const name of ["scan_progress", "guard_verdict", "scan_completed", "audit_appended"]) {
    state.es.addEventListener(name, debouncedRefresh);
  }
}

/* ---------- view switching + triggers ---------- */

function showView(view) {
  state.view = view;
  for (const section of document.querySelectorAll("section.view")) {
    section.classList.add("hidden");
  }
  show($("view-" + view));
  for (const button of document.querySelectorAll(".nav-item")) {
    button.classList.toggle("active", button.dataset.view === view);
  }
  $("title").textContent = TITLES[view];
  if (view === "overview") renderChart();
  if (view === "audit") refreshAudit();
}

async function triggerScan() {
  const button = $("btnScan");
  button.disabled = true;
  try {
    await api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: $("scanPath").value, include_dev: false }),
    });
  } catch (err) { markError(err); }
  button.disabled = false;
}

async function triggerGuard() {
  const button = $("btnGuard");
  button.disabled = true;
  try {
    await api("/api/guard", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: "fixtures/diffs/add_lodos_v3.diff" }),
    });
  } catch (err) { markError(err); }
  button.disabled = false;
}

/* ---------- boot ---------- */

function boot() {
  for (const button of document.querySelectorAll(".nav-item")) {
    button.addEventListener("click", () => showView(button.dataset.view));
  }
  $("btnScan").addEventListener("click", triggerScan);
  $("btnGuard").addEventListener("click", triggerGuard);
  $("btnRetry").addEventListener("click", () => refreshAll());
  $("timelineSession").addEventListener("change", loadTimeline);
  showView("overview");
  refreshAll();
  connectSse();
}

boot();
