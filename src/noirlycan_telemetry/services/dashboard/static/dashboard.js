const charts = {};
const fingerprints = {};
const REFRESH_MS = 4000;
const LIVE_REFRESH_DEBOUNCE_MS = 2000;
const SESSION_TABS = new Set(["findings", "network", "primitives", "events", "files"]);

// ---------------------------------------------------------------------------
// Demo mode — toggled via ?demo=1 URL parameter. Disables auto-refresh,
// shows a watermark, and applies CSS tweaks for thesis screenshots.
// ---------------------------------------------------------------------------
const URL_PARAMS = new URLSearchParams(window.location.search);
const DEMO_MODE = URL_PARAMS.get("demo") === "1";

// ---------------------------------------------------------------------------
// URL hash state — deep-linkable filter + tab + selected finding.
// Format: #tab=findings&log=session-xxx.jsonl&query=...&severity=high&pid=1337&type=primitive&finding=3
// ---------------------------------------------------------------------------
const HASH_KEYS = ["tab", "log", "query", "severity", "pid", "type", "finding"];
let suppressHashWrite = false;

function readHash() {
  const raw = window.location.hash.replace(/^#/, "");
  const params = new URLSearchParams(raw);
  const result = {};
  HASH_KEYS.forEach((key) => {
    const value = params.get(key);
    if (value !== null && value !== "") result[key] = value;
  });
  return result;
}

function writeHash(updates) {
  if (suppressHashWrite) return;
  const current = readHash();
  const next = { ...current, ...updates };
  const params = new URLSearchParams();
  HASH_KEYS.forEach((key) => {
    const value = next[key];
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  });
  const serialized = params.toString();
  const target = serialized ? `#${serialized}` : window.location.pathname + window.location.search;
  if (target !== `#${window.location.hash.replace(/^#/, "")}` && target !== window.location.pathname + window.location.search) {
    history.replaceState(null, "", target);
  }
}

function debounce(fn, ms) {
  let timer = null;
  return function debounced(...args) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      fn.apply(this, args);
    }, ms);
  };
}

const state = {
  activeLog: "",
  activeTab: "overview",
  overview: null,
  session: null,
  runtime: null,
  runtimeSaving: false,
  liveSocketConnected: false,
  corpus: null,
  filters: {
    query: "",
    severity: "",
    pid: "",
    type: "",
  },
};

const t = (key, vars) => NoirlycanI18n.t(key, vars);

let loadingCount = 0;
let loadingShownAt = 0;
let loadingHideTimer = null;

function chartStyle() {
  const root = getComputedStyle(document.documentElement);
  return {
    text: root.getPropertyValue("--chart-text").trim() || "#6b7c93",
    grid: root.getPropertyValue("--chart-grid").trim() || "rgba(15, 23, 42, 0.08)",
  };
}

function clearChart(id) {
  if (charts[id]) {
    charts[id].destroy();
    delete charts[id];
  }
}

function setChartPlaceholder(id, show) {
  const placeholder = document.querySelector(`[data-chart-placeholder="${id}"]`);
  const canvas = document.getElementById(`${id}-chart`);
  if (placeholder) {
    placeholder.classList.toggle("hidden", !show);
  }
  if (canvas) {
    canvas.style.display = show ? "none" : "";
  }
}

function setLoading(active) {
  const shell = document.getElementById("dashboard-shell");
  const overlay = document.getElementById("dashboard-loading");
  if (!shell || !overlay) return;

  if (active) {
    loadingCount += 1;
    if (loadingCount === 1) {
      loadingShownAt = Date.now();
      if (loadingHideTimer) {
        clearTimeout(loadingHideTimer);
        loadingHideTimer = null;
      }
      loadingHideTimer = setTimeout(() => {
        if (loadingCount > 0) {
          overlay.classList.remove("hidden");
          shell.setAttribute("aria-busy", "true");
        }
      }, 200);
    }
    return;
  }

  loadingCount = Math.max(0, loadingCount - 1);
  if (loadingCount > 0) return;

  const elapsed = Date.now() - loadingShownAt;
  const hide = () => {
    overlay.classList.add("hidden");
    shell.removeAttribute("aria-busy");
    loadingHideTimer = null;
  };

  if (elapsed < 200 && loadingShownAt) {
    setTimeout(hide, 200 - elapsed);
    return;
  }
  hide();
}

function showToast(message, type = "error") {
  const container = document.getElementById("toast-container");
  if (!container || !message) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 5000);
}

function updateAutoRefreshLabel() {
  const label = document.getElementById("auto-refresh-label");
  const toggle = document.getElementById("auto-refresh");
  if (!label || !toggle) return;
  if (state.liveSocketConnected) {
    label.textContent = t("toolbar.autoRefresh.live");
    return;
  }
  if (toggle.checked) {
    label.textContent = t("toolbar.autoRefresh.polling");
    return;
  }
  label.textContent = t("toolbar.autoRefresh.paused");
}

function renderStatusBar(overview) {
  const collector = document.getElementById("status-collector");
  const live = document.getElementById("status-live");
  const session = document.getElementById("status-session");
  const events = document.getElementById("status-events");
  const online = Boolean(overview?.collector_online);

  if (collector) {
    collector.textContent = online ? t("status.collectorOnline") : t("status.collectorOffline");
    collector.classList.toggle("online", online);
    collector.classList.toggle("offline", !online);
  }
  if (live) {
    const connected = Boolean(state.liveSocketConnected);
    live.textContent = connected ? t("status.liveConnected") : t("status.liveDisconnected");
    live.classList.toggle("live", connected);
  }
  if (session) {
    const activeLog = overview?.active_log || state.activeLog || "";
    session.textContent = activeLog || t("status.noSession");
  }
  if (events) {
    const count = overview?.stats?.totals?.events ?? 0;
    events.textContent = t("status.events", { count });
  }
  updateAutoRefreshLabel();
}

function bustFingerprints() {
  Object.keys(fingerprints).forEach((key) => delete fingerprints[key]);
}

function rerenderDashboard() {
  bustFingerprints();
  NoirlycanI18n.applyI18n();
  ensureMetricCards(true);
  if (state.overview) {
    renderStatusBar(state.overview);
    if (state.activeTab === "overview") {
      renderOverview(state.overview);
    }
    if (state.activeTab === "upload") {
      renderUploads(
        state.overview.uploads || [],
        state.overview.db_path || "",
        Boolean(state.overview.collector_online),
      );
    }
    if (state.activeTab === "sessions") {
      renderFiles(state.overview.files, state.activeLog);
    }
    if (state.activeTab === "chains") {
      renderInjectionChainsFromStats(chainsStatsSource());
    }
    if (state.activeTab === "corpus" && state.corpus) {
      renderCorpus(state.corpus, { forceCards: true });
    }
  }
  if (state.session) {
    renderSessionViews(state.session);
  }
  if (state.activeTab === "rules" && classifierRulesDraft) {
    renderClassifierRules(classifierRulesDraft, classifierRulesDraft.config_path);
  }
  if (state.runtime) {
    renderRuntimeControls(state.runtime);
  }
}

const palette = {
  critical: "#ff6b8a",
  high: "#ffb347",
  medium: "#4f8cff",
  low: "#3de0c5",
  allocate: "#4f8cff",
  write: "#9f7aea",
  execute: "#3de0c5",
};

Chart.defaults.animation = false;
Chart.defaults.transitions.active.animation.duration = 0;

function formatBytes(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function shortPath(value) {
  if (!value) return "-";
  const parts = value.split(/[\\/]/);
  return parts[parts.length - 1] || value;
}

function fingerprint(data) {
  return JSON.stringify(data);
}

function shouldRender(key, data) {
  const next = fingerprint(data);
  if (fingerprints[key] === next) {
    return false;
  }
  fingerprints[key] = next;
  return true;
}

function updateChart(id, updater) {
  const chart = charts[id];
  if (!chart) {
    return false;
  }
  updater(chart);
  chart.update("none");
  return true;
}

function currentFilters() {
  const pidValue = document.getElementById("filter-pid").value.trim();
  return {
    query: document.getElementById("filter-query").value.trim(),
    severity: document.getElementById("filter-severity").value,
    pid: pidValue ? Number(pidValue) : "",
    type: document.getElementById("filter-type").value,
  };
}

function buildSessionQuery(filters) {
  const params = new URLSearchParams();
  if (filters.query) params.set("q", filters.query);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.pid !== "" && !Number.isNaN(filters.pid)) params.set("pid", String(filters.pid));
  if (filters.type) params.set("type", filters.type);
  const query = params.toString();
  return query ? `?${query}` : "";
}

function ensureMetricCards(force = false) {
  const root = document.getElementById("metric-cards");
  if (!force && root.childElementCount) {
    return;
  }
  const cards = [
    { key: "events", label: t("metric.events"), className: "" },
    { key: "findings", label: t("metric.findings"), className: "findings" },
    { key: "network", label: t("metric.network"), className: "sysmon" },
    { key: "primitives", label: t("metric.primitives"), className: "primitives" },
    { key: "sysmon", label: t("metric.sysmon"), className: "sysmon" },
    { key: "frida_raw", label: t("metric.frida"), className: "" },
    { key: "triage", label: t("metric.triage"), className: "findings" },
  ];
  root.innerHTML = cards
    .map(
      (card) => `
      <article class="metric-card ${card.className}" data-metric="${card.key}">
        <div class="label">${card.label}</div>
        <div class="value">0</div>
      </article>`
    )
    .join("");
}

function renderMetrics(totals) {
  if (!shouldRender("metrics", totals)) {
    return;
  }
  ensureMetricCards();
  document.querySelectorAll("[data-metric]").forEach((card) => {
    const key = card.dataset.metric;
    const valueNode = card.querySelector(".value");
    const nextValue = String(totals[key] ?? 0);
    if (valueNode.textContent !== nextValue) {
      valueNode.textContent = nextValue;
    }
  });
}

function renderSeverityChart(severity) {
  if (!shouldRender("severity", severity)) {
    return;
  }
  const labels = Object.keys(severity);
  if (!labels.length) {
    clearChart("severity");
    setChartPlaceholder("severity", true);
    return;
  }
  setChartPlaceholder("severity", false);
  const values = labels.map((key) => severity[key]);
  const colors = labels.map((label) => palette[label] || "#60738f");
  const style = chartStyle();

  if (
    updateChart("severity", (chart) => {
      chart.data.labels = labels;
      chart.data.datasets[0].data = values;
      chart.data.datasets[0].backgroundColor = colors;
    })
  ) {
    return;
  }

  const ctx = document.getElementById("severity-chart");
  charts.severity = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }],
    },
    options: {
      animation: false,
      plugins: { legend: { position: "bottom", labels: { color: style.text } } },
    },
  });
}

function renderPrimitiveChart(kinds) {
  if (!shouldRender("primitive", kinds)) {
    return;
  }
  const labels = Object.keys(kinds);
  if (!labels.length) {
    clearChart("primitive");
    setChartPlaceholder("primitive", true);
    return;
  }
  setChartPlaceholder("primitive", false);
  const values = labels.map((key) => kinds[key]);
  const colors = labels.map((label) => palette[label] || "#4f8cff");
  const style = chartStyle();

  if (
    updateChart("primitive", (chart) => {
      chart.data.labels = labels;
      chart.data.datasets[0].data = values;
      chart.data.datasets[0].backgroundColor = colors;
    })
  ) {
    return;
  }

  const ctx = document.getElementById("primitive-chart");
  charts.primitive = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: colors, borderRadius: 10 }],
    },
    options: {
      animation: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: style.text }, grid: { color: style.grid } },
        y: { ticks: { color: style.text }, grid: { color: style.grid } },
      },
    },
  });
}

function renderTimelineChart(timeline) {
  if (!shouldRender("timeline", timeline)) {
    return;
  }
  if (!timeline.length) {
    clearChart("timeline");
    setChartPlaceholder("timeline", true);
    return;
  }
  setChartPlaceholder("timeline", false);
  const labels = timeline.map(([bucket]) => bucket);
  const values = timeline.map(([, count]) => count);
  const style = chartStyle();

  if (
    updateChart("timeline", (chart) => {
      chart.data.labels = labels;
      chart.data.datasets[0].data = values;
    })
  ) {
    return;
  }

  const ctx = document.getElementById("timeline-chart");
  charts.timeline = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          data: values,
          borderColor: "#3de0c5",
          backgroundColor: "rgba(61, 224, 197, 0.12)",
          fill: true,
          tension: 0.35,
          pointRadius: 2,
        },
      ],
    },
    options: {
      animation: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: style.text, maxRotation: 0 }, grid: { color: style.grid } },
        y: { ticks: { color: style.text }, grid: { color: style.grid } },
      },
    },
  });
}

function renderRankList(elementId, rows) {
  if (!shouldRender(elementId, rows)) {
    return;
  }
  const root = document.getElementById(elementId);
  if (!rows.length) {
    root.innerHTML = `<div class="empty">${t("rank.noData")}</div>`;
    return;
  }
  // Normalise: rows can be either Counter-style tuples [name, count] or
  // enriched actor objects {image, count, apis: [[api, n], ...]}.
  const normalised = rows.map((row) => {
    if (Array.isArray(row)) {
      return { name: String(row[0] ?? ""), count: Number(row[1] ?? 0), apis: [] };
    }
    return {
      name: String(row.image ?? row.name ?? ""),
      count: Number(row.count ?? 0),
      apis: Array.isArray(row.apis) ? row.apis : [],
    };
  });
  const max = Math.max(...normalised.map((row) => row.count)) || 1;
  root.innerHTML = normalised
    .map((row) => {
      const apiTags = row.apis
        .map(([api, n]) => `<span class="api-chip" title="${api} (${n})">${api}<small>·${n}</small></span>`)
        .join("");
      return `
      <div class="rank-item ${row.apis.length ? "rank-item-rich" : ""}">
        <div class="rank-head">
          <div class="name" title="${row.name}">${shortPath(row.name)}</div>
          <div class="count">${row.count}</div>
        </div>
        <div class="bar"><span style="width:${(row.count / max) * 100}%"></span></div>
        ${apiTags ? `<div class="api-chip-row">${apiTags}</div>` : ""}
      </div>`;
    })
    .join("");
}

function formatTechnique(row) {
  const technique = row.technique || "unclassified";
  const confidence = row.technique_confidence ? ` (${row.technique_confidence})` : "";
  const recursive = row.is_recursive ? " ↻" : "";
  return `${technique}${confidence}${recursive}`;
}

function formatInjectionTarget(row) {
  const image = row.target_image;
  const pid = row.target_pid;
  if (image && pid != null) {
    return `<span class="mono" title="${image}">${shortPath(image)} <span class="muted">(${pid})</span></span>`;
  }
  if (image) {
    return `<span class="mono" title="${image}">${shortPath(image)}</span>`;
  }
  if (pid != null) {
    return `pid ${pid}`;
  }
  return "-";
}

function renderNetworkSummary(networkRows) {
  const endpoints = (networkRows || [])
    .map((row) => row.endpoint)
    .filter(Boolean)
    .slice(0, 3);
  if (!endpoints.length) return "-";
  return endpoints.join(", ");
}

function chainsStatsSource() {
  return state.session?.stats || state.overview?.stats || null;
}

function renderInjectionChains(chains, recursiveCount) {
  const payload = { chains: chains || [], recursiveCount: recursiveCount ?? null };
  if (!shouldRender("injection-chains", payload)) {
    return;
  }
  const chip = document.getElementById("chain-count-chip");
  const body = document.getElementById("chains-body");
  if (!body) return;

  const rows = payload.chains;
  const recursive = Number(
    payload.recursiveCount ?? rows.filter((chain) => chain.is_recursive).length,
  );
  if (chip) {
    if (!rows.length) {
      chip.textContent = t("chains.chip.zero");
    } else if (recursive > 0) {
      chip.textContent = t("chains.chip.recursive", { count: rows.length, recursive });
    } else if (rows.length === 1) {
      chip.textContent = t("chains.chip.one");
    } else {
      chip.textContent = t("chains.chip.many", { count: rows.length });
    }
  }

  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="5" class="empty">${t("chains.empty")}</td></tr>`;
    return;
  }

  body.innerHTML = rows
    .map((chain) => {
      const pids = (chain.pids || []).join(" → ");
      const imageList = chain.images || [];
      const imagesShort = imageList.map((img) => shortPath(img) || "?").join(" → ");
      const imagesFull = imageList.filter(Boolean).join(" → ");
      const techniques = [...new Set((chain.techniques || []).filter(Boolean))]
        .map((name) => formatTechniqueLabel(name))
        .join(", ");
      const scores = (chain.scores || []).filter((value) => value != null);
      const scoreHint = scores.length ? ` title="edge scores: ${scores.join(", ")}"` : "";
      return `
      <tr class="chains-row"${scoreHint}>
        <td>${chain.depth ?? "-"}</td>
        <td>${chain.is_recursive ? '<span class="tag">yes</span>' : "no"}</td>
        <td class="mono">${pids || "-"}</td>
        <td class="mono" title="${escapeHtml(imagesFull)}">${escapeHtml(imagesShort || "-")}</td>
        <td class="mono">${techniques || "-"}</td>
      </tr>`;
    })
    .join("");
}

function renderInjectionChainsFromStats(stats) {
  if (!stats) {
    renderInjectionChains([], 0);
    return;
  }
  renderInjectionChains(stats.injection_chains || [], stats.recursive_chain_count);
}

function renderFindings(rows) {
  if (!shouldRender("findings", rows)) {
    return;
  }
  const body = document.getElementById("findings-body");
  if (!rows.length) {
    // Diagnostic: if primitives were captured but the 2/3 rule did not fire,
    // surface the most likely cause (late attach) instead of a generic message.
    const overview = state.overview && state.overview.stats;
    const primitives = overview ? Number(overview.totals?.primitives ?? 0) : 0;
    const kinds = overview ? Object.keys(overview.primitive_kinds || {}) : [];
    let hint = t("findings.empty");
    if (primitives > 0 && kinds.length < 2) {
      hint = `<strong>${t("findings.lateAttachTitle")}</strong><br>${t("findings.lateAttachBody", {
        primitives,
        kinds: kinds.join(", ") || "—",
      })}`;
    }
    body.innerHTML = `<tr><td colspan="8" class="empty">${hint}</td></tr>`;
    return;
  }
  body.innerHTML = rows
    .map((row, index) => {
      const severity = String(row.severity || "unknown").toLowerCase();
      return `
      <tr class="clickable" data-finding-index="${index}">
        <td>${formatTime(row.timestamp)}</td>
        <td><span class="severity ${severity}">${severity}</span></td>
        <td>${row.score ?? "-"}</td>
        <td>${formatInjectionTarget(row)}</td>
        <td class="mono">${formatTechnique(row)}</td>
        <td class="mono">${(row.apis || []).join(", ")}</td>
        <td class="mono">${renderNetworkSummary(row.network)}</td>
        <td>${row.description || row.title || "-"}</td>
      </tr>`;
    })
    .join("");
}

function renderNetwork(rows) {
  if (!shouldRender("network", rows)) {
    return;
  }
  const body = document.getElementById("network-body");
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">${t("network.empty")}</td></tr>`;
    return;
  }
  body.innerHTML = rows
    .map((row) => {
      const beacon = row.beacon_candidate
        ? '<span class="beacon yes">candidate</span>'
        : '<span class="beacon no">-</span>';
      return `
      <tr class="clickable" data-network-pid="${row.pid ?? ""}">
        <td>${formatTime(row.timestamp)}</td>
        <td>${row.pid ?? "-"}</td>
        <td class="mono">${shortPath(row.image)}</td>
        <td class="mono">${row.endpoint || "-"}</td>
        <td>${row.protocol || "-"}</td>
        <td>${beacon}</td>
      </tr>`;
    })
    .join("");
}

function buildFileDropRows(pendingRows, triagedRows) {
  const analyzed = (triagedRows || []).map((row) => ({
    ...row,
    status: row.status || "analyzed",
  }));
  const pending = (pendingRows || []).map((row) => ({
    ...row,
    status: "pending",
    score: row.score ?? null,
    sha256: row.sha256 ?? null,
  }));
  const seen = new Set();
  const merged = [];
  for (const row of [...pending, ...analyzed]) {
    const key = String(row.path || "").toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    merged.push(row);
  }
  return merged.sort(
    (left, right) =>
      String(right.timestamp || "").localeCompare(String(left.timestamp || ""))
  );
}

function renderTriages(pendingRows, triagedRows) {
  const rows = buildFileDropRows(pendingRows, triagedRows);
  if (!shouldRender("triages", rows)) {
    return;
  }
  const body = document.getElementById("triage-body");
  const collectorOnline = Boolean(state.runtime?.collector_online);
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="10" class="empty">${t("files.empty")}</td></tr>`;
    return;
  }
  body.innerHTML = rows
    .map((row) => {
      const reasons = (row.reasons || []).join(", ") || "-";
      const sha = row.sha256 ? `${row.sha256.slice(0, 12)}…` : "-";
      const apiStatus = row.api_status || (row.status === "pending" ? "pending" : "started");
      const isPending = apiStatus === "pending";
      const statusClass = isPending ? "status-pending" : apiStatus === "failed" ? "status-pending" : "status-analyzed";
      const statusLabel = isPending ? "pending" : apiStatus === "failed" ? "api failed" : "hooks active";
      const analyzeBtn = isPending
        ? `<button type="button" class="btn-analyze" data-analyze-path="${encodeURIComponent(
            row.path || ""
          )}" ${collectorOnline ? "" : "disabled"} title="${
            collectorOnline ? t("files.analyzeTitle") : t("files.analyzeDisabled")
          }">${t("files.analyzeApis")}</button>`
        : "-";
      return `
      <tr>
        <td>${formatTime(row.timestamp)}</td>
        <td class="mono" title="${row.path || ""}">${shortPath(row.path)}</td>
        <td>${row.score ?? "-"}</td>
        <td>${row.pe === true ? "yes" : row.pe === false ? "no" : "-"}</td>
        <td>${row.signed === true ? "yes" : row.signed === false ? "no" : "-"}</td>
        <td>${row.entropy != null ? Number(row.entropy).toFixed(2) : "-"}</td>
        <td class="mono" title="${row.sha256 || ""}">${sha}</td>
        <td>${reasons}</td>
        <td class="${statusClass}">${statusLabel}</td>
        <td>${analyzeBtn}</td>
      </tr>`;
    })
    .join("");
}

function renderPrimitives(rows) {
  if (!shouldRender("primitives", rows)) {
    return;
  }
  const body = document.getElementById("primitives-body");
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="7" class="empty">${t("primitives.empty")}</td></tr>`;
    return;
  }
  body.innerHTML = rows
    .map(
      (row) => `
      <tr>
        <td>${formatTime(row.timestamp)}</td>
        <td><span class="kind ${row.kind || ""}">${row.kind || "-"}</span></td>
        <td class="mono">${row.api || "-"}</td>
        <td class="mono">${shortPath(row.actor_image)} (${row.actor_pid ?? "-"})</td>
        <td>${formatInjectionTarget(row)}</td>
        <td class="mono">${row.address ?? "-"}</td>
        <td>${row.size ?? "-"}</td>
      </tr>`
    )
    .join("");
}

function summarizeEvent(event) {
  const value = event.value || {};
  if (event.type === "finding") {
    return `${value.severity || "finding"} score ${value.score ?? "-"} target ${value.target_pid ?? "-"}`;
  }
  if (event.type === "primitive") {
    return `${value.kind || "primitive"} ${value.api || ""} -> PID ${value.target_pid ?? "-"}`;
  }
  if (event.type === "network") {
    return `${value.protocol || "tcp"} ${value.destination_hostname || value.destination_ip || "-"}:${value.destination_port ?? "-"}`;
  }
  if (event.type === "sysmon") {
    return `Sysmon EID ${value.event_id ?? "-"} ${shortPath(value.image)}`;
  }
  return JSON.stringify(value).slice(0, 120);
}

function renderEvents(rows) {
  if (!shouldRender("events", rows)) {
    return;
  }
  const body = document.getElementById("events-body");
  document.getElementById("event-count-label").textContent = t("events.count", { count: rows.length });
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="3" class="empty">${t("events.empty")}</td></tr>`;
    return;
  }
  body.innerHTML = rows
    .map(
      (event) => `
      <tr>
        <td><span class="event-type">${event.type || "-"}</span></td>
        <td>${formatTime(event.value?.timestamp || event.timestamp)}</td>
        <td class="mono">${summarizeEvent(event)}</td>
      </tr>`
    )
    .join("");
}

function renderFiles(rows, activeLog) {
  if (!shouldRender("files", { rows, activeLog })) {
    return;
  }
  const body = document.getElementById("files-body");
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">${t("sessions.empty")}</td></tr>`;
    return;
  }
  body.innerHTML = rows
    .map((row) => {
      const active = row.name === activeLog ? "active-row" : "";
      return `
      <tr class="clickable ${active}" data-session-name="${row.name}">
        <td class="mono">${row.name}</td>
        <td>${formatTime(row.modified_at)}</td>
        <td>${row.event_count}</td>
        <td>${row.finding_count}</td>
        <td>${row.critical_count}</td>
        <td>${formatBytes(row.size_bytes)}</td>
      </tr>`;
    })
    .join("");
}

function ensureCorpusMetricCards(force = false) {
  const root = document.getElementById("corpus-metric-cards");
  if (!root || (!force && root.childElementCount)) return;
  const cards = [
    { key: "samples", label: t("corpus.metric.samples") },
    { key: "detected", label: t("corpus.metric.detected") },
    { key: "rate", label: t("corpus.metric.rate") },
    { key: "recursive", label: t("corpus.metric.recursive") },
  ];
  root.innerHTML = cards
    .map(
      (card) => `
      <article class="metric-card" data-corpus-metric="${card.key}">
        <div class="label">${card.label}</div>
        <div class="value">0</div>
      </article>`
    )
    .join("");
}

function ensureCorpusDbMetricCards(force = false) {
  const root = document.getElementById("corpus-db-metric-cards");
  if (!root || (!force && root.childElementCount)) return;
  const cards = [
    { key: "rows", label: t("corpus.db.metric.rows") },
    { key: "sessions", label: t("corpus.db.metric.sessions") },
    { key: "techniques", label: t("corpus.db.metric.techniques") },
  ];
  root.innerHTML = cards
    .map(
      (card) => `
      <article class="metric-card" data-corpus-db-metric="${card.key}">
        <div class="label">${card.label}</div>
        <div class="value">0</div>
      </article>`
    )
    .join("");
}

function renderCorpusDbFindings(dbFindings, { forceCards = false } = {}) {
  ensureCorpusDbMetricCards(forceCards);
  const rows = Number(dbFindings?.finding_rows || 0);
  const sessions = Number(dbFindings?.session_count || 0);
  const techniqueMap = dbFindings?.technique_distribution || {};
  const techniqueCount = Object.keys(techniqueMap).length;

  const chip = document.getElementById("corpus-db-chip");
  if (chip) chip.textContent = t("corpus.dbChip", { rows, sessions });

  const metrics = { rows, sessions, techniques: techniqueCount };
  document.querySelectorAll("[data-corpus-db-metric]").forEach((card) => {
    const key = card.dataset.corpusDbMetric;
    const valueNode = card.querySelector(".value");
    if (valueNode) valueNode.textContent = String(metrics[key] ?? 0);
  });

  const dbTechniqueRoot = document.getElementById("corpus-db-techniques");
  if (!dbTechniqueRoot) return;
  const techniques = Object.entries(techniqueMap).sort((left, right) => right[1] - left[1]);
  if (!rows || !techniques.length) {
    dbTechniqueRoot.innerHTML = `<div class="empty">${t("corpus.db.empty")}</div>`;
    return;
  }
  renderRankList("corpus-db-techniques", techniques);
}

function renderCorpus(payload, { forceCards = false } = {}) {
  if (!payload) return;
  ensureCorpusMetricCards(forceCards);
  const sampleCount = Number(payload.samples || 0);
  const chip = document.getElementById("corpus-sample-chip");
  if (chip) chip.textContent = t("corpus.chip", { count: sampleCount });

  const metrics = {
    samples: sampleCount,
    detected: Number(payload.injection_detected_count || 0),
    rate: sampleCount
      ? `${Math.round(Number(payload.injection_detection_rate || 0) * 100)}%`
      : "0%",
    recursive: Number(payload.recursive_sample_count || 0),
  };
  document.querySelectorAll("[data-corpus-metric]").forEach((card) => {
    const key = card.dataset.corpusMetric;
    const valueNode = card.querySelector(".value");
    if (valueNode) valueNode.textContent = String(metrics[key] ?? 0);
  });

  const techniques = Object.entries(payload.technique_distribution || {}).sort(
    (left, right) => right[1] - left[1]
  );
  const techniqueRoot = document.getElementById("corpus-techniques");
  if (techniqueRoot) {
    if (!techniques.length) {
      techniqueRoot.innerHTML = `<div class="empty">${t("rank.noData")}</div>`;
    } else {
      renderRankList("corpus-techniques", techniques);
    }
  }

  const body = document.getElementById("corpus-sessions-body");
  if (body) {
    const rows = payload.sessions || [];
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="4" class="empty">${t("corpus.empty")}</td></tr>`;
    } else {
      body.innerHTML = rows
        .map(
          (row) => `
        <tr class="clickable" data-session-name="${row.session}">
          <td class="mono">${row.session}</td>
          <td>${row.findings ?? 0}</td>
          <td>${row.injection_detected ? "yes" : "no"}</td>
          <td>${row.max_score ?? 0}</td>
        </tr>`
        )
        .join("");
    }
  }

  renderCorpusDbFindings(payload.db_findings || {}, { forceCards });
}

async function loadCorpus({ force = false } = {}) {
  if (!force && state.corpus) {
    renderCorpus(state.corpus);
    return state.corpus;
  }
  setLoading(true);
  try {
    const response = await fetch("/api/corpus");
    if (!response.ok) {
      throw new Error(t("corpus.loadFailed"));
    }
    const payload = await response.json();
    state.corpus = payload;
    renderCorpus(payload);
    return payload;
  } catch (error) {
    console.error(error);
    showToast(error.message || t("corpus.loadFailed"), "error");
    return null;
  } finally {
    setLoading(false);
  }
}

async function requestReclassify() {
  const selected = document.getElementById("log-select")?.value || state.activeLog;
  if (!selected) {
    showToast(t("status.noLogSelected"), "error");
    return;
  }
  const writeSidecar = Boolean(document.getElementById("reclassify-write-sidecar")?.checked);
  setLoading(true);
  try {
    const query = writeSidecar ? "?write=sidecar" : "";
    const response = await fetch(`/api/reclassify/${encodeURIComponent(selected)}${query}`);
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || t("corpus.reclassifyFailed"));
    }
    const summary = t("corpus.reclassifyDone", {
      original: payload.original_finding_count ?? 0,
      next: payload.reclassified_finding_count ?? 0,
      delta: payload.delta_findings ?? 0,
    });
    const output = document.getElementById("reclassify-output");
    if (output) {
      output.textContent = JSON.stringify(
        {
          summary,
          written_path: payload.written_path || null,
          original_techniques: payload.original_techniques,
          reclassified_techniques: payload.reclassified_techniques,
          findings: payload.findings,
        },
        null,
        2
      );
    }
    const toastMessage = payload.written_path
      ? `${summary} · ${t("corpus.writtenPath", { path: payload.written_path })}`
      : summary;
    showToast(toastMessage, "success");
    if (writeSidecar) {
      state.corpus = null;
      await loadCorpus({ force: true });
    }
  } catch (error) {
    console.error(error);
    showToast(error.message || t("corpus.reclassifyFailed"), "error");
  } finally {
    setLoading(false);
  }
}

function shortSha(value) {
  if (!value) return "-";
  return value.length > 16 ? `${value.slice(0, 16)}…` : value;
}

function renderUploadCollectorStatus(collectorOnline) {
  const chip = document.getElementById("upload-collector-chip");
  const banner = document.getElementById("upload-collector-banner");
  if (chip) {
    if (collectorOnline) {
      chip.textContent = t("upload.collectorOnline");
      chip.classList.add("online");
      chip.classList.remove("offline");
    } else {
      chip.textContent = t("upload.collectorOffline");
      chip.classList.add("offline");
      chip.classList.remove("online");
    }
  }
  if (banner) {
    banner.classList.toggle("hidden", Boolean(collectorOnline));
  }
}

function renderUploads(rows, dbPath, collectorOnline = false) {
  if (!shouldRender("uploads", { rows, dbPath, collectorOnline })) {
    return;
  }
  renderUploadCollectorStatus(collectorOnline);
  const chip = document.getElementById("db-path-chip");
  if (chip) {
    chip.textContent = dbPath ? dbPath.split(/[\\/]/).pop() : "SQLite";
    chip.title = dbPath || "";
  }
  const body = document.getElementById("uploads-body");
  if (!body) return;
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">${t("upload.empty")}</td></tr>`;
    return;
  }
  body.innerHTML = rows
    .map((row) => {
      const isExecutable = row.content_kind === "executable";
      const status = row.status || "";
      const canRun = isExecutable && !["queued", "spawned", "running"].includes(status);
      const canReport = ["spawned", "running", "parsed", "queued"].includes(status);
      const runDisabled = canRun ? "" : "disabled";
      const reportBtn = canReport
        ? `<button type="button" class="btn-mini" data-upload-report="${row.id}">${t("upload.viewReport")}</button>`
        : "";
      const runBtn = isExecutable
        ? `<button type="button" class="btn-mini" data-upload-run="${row.id}" ${runDisabled}>${t("upload.run")}</button>`
        : "";
      const deleteBtn = `<button type="button" class="btn-mini danger" data-upload-delete="${row.id}">${t("upload.delete")}</button>`;
      return `
      <tr data-upload-id="${row.id}">
        <td>${formatTime(row.uploaded_at)}</td>
        <td class="mono" title="${row.stored_path || ""}">${row.original_name || "-"}</td>
        <td>${row.content_kind || "-"}</td>
        <td title="${row.error_message || ""}">${row.status_label || status || "-"}</td>
        <td><div class="upload-actions">${runBtn}${reportBtn}${deleteBtn}</div></td>
        <td class="mono" title="${row.sha256 || ""}">${shortSha(row.sha256)}</td>
      </tr>`;
    })
    .join("");
}

function setUploadStatus(message, kind = "") {
  const node = document.getElementById("upload-status");
  if (!node) return;
  node.textContent = message;
  node.classList.remove("ok", "error");
  if (kind) node.classList.add(kind);
}

async function uploadDroppedFile(file) {
  if (!file) return;
  const suffix = (file.name.split(".").pop() || "").toLowerCase();
  if (!["jsonl", "exe", "dll"].includes(suffix)) {
    setUploadStatus(t("upload.unsupported"), "error");
    showToast(t("upload.unsupported"), "error");
    return;
  }
  const formData = new FormData();
  formData.append("file", file, file.name);
  const pidInput = document.getElementById("upload-target-pid");
  const pidValue = pidInput ? Number(pidInput.value) : NaN;
  if (suffix !== "jsonl" && Number.isFinite(pidValue) && pidValue > 0) {
    formData.append("target_pid", String(Math.trunc(pidValue)));
  }
  setUploadStatus(t("upload.uploading", { name: file.name }));
  try {
    const response = await fetch("/api/upload", { method: "POST", body: formData });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || `Upload failed (${response.status})`);
    }
    if (payload.kind === "jsonl") {
      const parsedMessage = t("upload.parsed", {
        session: payload.session_name,
        findings: payload.parsed?.finding_count ?? 0,
      });
      setUploadStatus(parsedMessage, "ok");
      showToast(parsedMessage, "success");
      if (payload.session_name) {
        await loadDashboard(payload.session_name, { force: true });
        switchTab("findings");
      }
    } else {
      const savedMessage = payload.message || t("upload.saved");
      setUploadStatus(savedMessage, "ok");
      showToast(savedMessage, "success");
    }
    const overview = await loadOverview(state.activeLog);
    if (overview) {
      state.overview = overview;
      renderUploads(
        overview.uploads || [],
        overview.db_path || "",
        Boolean(overview.collector_online),
      );
    }
  } catch (error) {
    console.error(error);
    const uploadError = error.message || "Upload failed";
    setUploadStatus(uploadError, "error");
    showToast(uploadError, "error");
  }
}

async function runUploadAnalysis(uploadId, button) {
  const pidInput = document.getElementById("upload-target-pid");
  const pidValue = pidInput ? Number(pidInput.value) : NaN;
  const payload = {};
  if (Number.isFinite(pidValue) && pidValue > 0) {
    payload.target_pid = Math.trunc(pidValue);
  }
  if (button) {
    button.disabled = true;
    button.textContent = "Running…";
  }
  setUploadStatus("Queueing analysis…");
  try {
    const response = await fetch(`/api/uploads/${uploadId}/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || `Run failed (${response.status})`);
    }
    setUploadStatus(result.message || "Analysis queued.", "ok");
    const overview = await loadOverview(state.activeLog);
    if (overview) {
      state.overview = overview;
      renderUploads(
        overview.uploads || [],
        overview.db_path || "",
        Boolean(overview.collector_online),
      );
    }
  } catch (error) {
    console.error(error);
    setUploadStatus(error.message || "Could not start analysis", "error");
    if (button) {
      button.disabled = false;
      button.textContent = "Run";
    }
  }
}

async function deleteUpload(uploadId) {
  if (!window.confirm("Delete this upload and its report?")) {
    return;
  }
  setUploadStatus("Deleting upload…");
  try {
    const response = await fetch(`/api/uploads/${uploadId}/delete`, { method: "POST" });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || `Delete failed (${response.status})`);
    }
    setUploadStatus(result.message || "Upload deleted.", "ok");
    const overview = await loadOverview(state.activeLog);
    if (overview) {
      state.overview = overview;
      renderUploads(
        overview.uploads || [],
        overview.db_path || "",
        Boolean(overview.collector_online),
      );
    }
  } catch (error) {
    console.error(error);
    setUploadStatus(error.message || "Could not delete upload", "error");
  }
}

function openUploadReportModal(payload) {
  const upload = payload.upload || {};
  const report = payload.report || {};
  const stats = report.stats || {};
  const totals = stats.totals || {};
  const techniques = stats.techniques || {};
  const modal = document.getElementById("upload-report-modal");
  document.getElementById("upload-report-title").textContent = upload.original_name || "Upload report";
  document.getElementById("upload-report-summary").innerHTML = `
    <dt>Status</dt><dd>${upload.status || "-"}</dd>
    <dt>Events</dt><dd>${report.event_count ?? totals.events ?? 0}</dd>
    <dt>Findings</dt><dd>${report.finding_count ?? totals.findings ?? 0}</dd>
    <dt>Primitives</dt><dd>${report.primitive_count ?? totals.primitives ?? 0}</dd>
    <dt>Parsed</dt><dd>${formatTime(report.parsed_at)}</dd>
    <dt>Session</dt><dd class="mono">${report.session_name || "-"}</dd>
  `;
  const techniqueTags = Object.entries(techniques)
    .map(([name, count]) => `<span class="tag">${formatTechniqueLabel(name)} · ${count}</span>`)
    .join("");
  document.getElementById("upload-report-techniques").innerHTML =
    techniqueTags || '<span class="empty">No techniques detected.</span>';
  const findings = report.findings || stats.recent_findings || [];
  document.getElementById("upload-report-findings").innerHTML = findings.length
    ? `<table>
        <thead><tr><th>Score</th><th>Technique</th><th>Severity</th><th>Actor</th><th>Target</th></tr></thead>
        <tbody>
          ${findings
            .map(
              (finding) => `
            <tr>
              <td>${finding.score ?? "-"}</td>
              <td>${formatTechniqueLabel(finding.technique)}</td>
              <td>${finding.severity || "-"}</td>
              <td>${finding.actor_pid ?? "-"}</td>
              <td>${finding.target_pid ?? "-"}</td>
            </tr>`,
            )
            .join("")}
        </tbody>
      </table>`
    : '<div class="empty">No findings in this report.</div>';
  modal.showModal();
}

async function openUploadReport(uploadId) {
  setUploadStatus("Loading report…");
  try {
    const response = await fetch(`/api/uploads/${uploadId}/report`);
    const payload = await response.json();
    if (response.status === 202) {
      setUploadStatus(payload.error || "No telemetry yet — wait for collector findings.", "error");
      return;
    }
    if (!response.ok) {
      throw new Error(payload.error || `Report unavailable (${response.status})`);
    }
    openUploadReportModal(payload);
    const hint = payload.live_snapshot ? "Live snapshot loaded (collector still running)." : "Report loaded.";
    setUploadStatus(hint, "ok");
  } catch (error) {
    console.error(error);
    setUploadStatus(error.message || "Could not load report", "error");
  }
}

function setupUploadDropzone() {
  const dropzone = document.getElementById("upload-dropzone");
  const input = document.getElementById("upload-input");
  if (!dropzone || !input) return;

  dropzone.addEventListener("click", () => input.click());
  dropzone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      input.click();
    }
  });
  input.addEventListener("change", () => {
    const file = input.files && input.files[0];
    uploadDroppedFile(file);
    input.value = "";
  });
  ["dragenter", "dragover"].forEach((name) => {
    dropzone.addEventListener(name, (event) => {
      event.preventDefault();
      dropzone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach((name) => {
    dropzone.addEventListener(name, (event) => {
      event.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });
  dropzone.addEventListener("drop", (event) => {
    const file = event.dataTransfer?.files?.[0];
    uploadDroppedFile(file);
  });
}

function populateLogSelect(files, activeLog) {
  const select = document.getElementById("log-select");
  const names = files.map((file) => file.name);
  if (!shouldRender("log-select", { names, activeLog })) {
    if (activeLog && select.value !== activeLog) {
      select.value = activeLog;
    }
    return;
  }

  const previous = select.value;
  select.innerHTML = files.length
    ? files
        .map(
          (file) => `
      <option value="${file.name}" ${file.name === activeLog ? "selected" : ""}>
        ${file.name}
      </option>`
        )
        .join("")
    : '<option value="">No logs found</option>';

  if (activeLog) {
    select.value = activeLog;
  } else if (previous && [...select.options].some((option) => option.value === previous)) {
    select.value = previous;
  }
}

function showLoadError(message) {
  const label = message || t("error.loadDashboard");
  document.getElementById("active-log-label").textContent = label;
  document.getElementById("file-count").textContent = t("status.loadFailed");
  showToast(label, "error");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatRuleMatchFromPayload(rule) {
  if (!rule) return "-";
  const groups = rule.api_groups;
  if (Array.isArray(groups) && groups.length) {
    return groups
      .map((group, index) => {
        const apis = Array.isArray(group) ? group.join(" or ") : String(group);
        return `Step ${index + 1}: ${apis}`;
      })
      .join("\n");
  }
  if (rule.match_summary) return rule.match_summary;
  return rule.description || "-";
}

function ruleHasActiveGates(rule) {
  if (!rule) return false;
  return Boolean(
    rule.require_execution
    || rule.require_cross_process
    || rule.require_same_process
    || rule.require_section_mapping
    || rule.require_context_read
    || Number(rule.min_finding_score ?? 0) > 0
    || Number(rule.min_primitive_kinds ?? 2) > 2,
  );
}

function setRuleViewNextSteps(html) {
  const node = document.getElementById("rule-view-next-steps");
  if (!node) return;
  if (html) {
    node.innerHTML = html;
    node.classList.remove("hidden");
  } else {
    node.innerHTML = "";
    node.classList.add("hidden");
  }
}

function formatAutoConfidenceLabel(value) {
  const raw = String(value || "by_kinds").trim();
  const labels = {
    by_kinds: "Auto by primitive kinds (2→medium, 3→high)",
    high: "High",
    medium: "Medium",
    low: "Low",
    auto: "Auto",
    high_if_context_else_medium: "High if context read, else medium",
    high_if_execute_else_medium: "High if execution, else medium",
  };
  return labels[raw] || raw.replace(/_/g, " ");
}

function formatTechniqueLabel(name) {
  if (!name) return "unknown";
  return String(name).replace(/_/g, " ");
}

function renderTechniques(techniques) {
  const entries = Object.entries(techniques || {}).sort((a, b) => b[1] - a[1]);
  renderRankList(
    "technique-list",
    entries.map(([name, count]) => [formatTechniqueLabel(name), count]),
  );
}

function renderEvasionSummary(evasion) {
  const chip = document.getElementById("evasion-chip");
  const total = Number(evasion?.total || 0);
  if (chip) {
    chip.textContent = t("chart.evasionChip", { count: total });
  }
  const rows = Object.entries(evasion?.by_kind || {})
    .sort((a, b) => b[1] - a[1])
    .map(([kind, count]) => [kind.replace(/_/g, " "), count]);
  if (evasion?.apis?.length) {
    rows.push(["APIs", evasion.apis.join(", ")]);
  }
  renderRankList("evasion-summary", rows);
}

function renderOverview(payload) {
  renderMetrics(payload.stats.totals);
  renderSeverityChart(payload.stats.severity);
  renderPrimitiveChart(payload.stats.primitive_kinds);
  renderTimelineChart(payload.stats.timeline);
  renderRankList("api-list", payload.stats.top_apis);
  renderRankList("actor-list", payload.stats.top_actors);
  renderTechniques(payload.stats.techniques);
  renderEvasionSummary(payload.stats.evasion);
}

let classifierRulesDraft = null;
let classifierTechniques = [];
let ruleEditorMode = null;
let ruleEditorRuleId = null;

function slugifyRuleId(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .replace(/^([^a-z])/, "r_$1")
    .slice(0, 64);
}

function parseApiList(value) {
  return String(value || "")
    .split(/[,;\n]/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

function formatApiList(values) {
  return (values || []).join(", ");
}

function populateTechniqueSelect(select, techniques) {
  if (!select) return;
  const options = (techniques || []).map(
    (item) => `<option value="${item.value}">${item.label || item.value}</option>`,
  );
  select.innerHTML = options.join("");
}

function formatApiGroupsText(apiGroups) {
  if (!Array.isArray(apiGroups) || !apiGroups.length) return "";
  return apiGroups
    .map((group) => (Array.isArray(group) ? group.join(", ") : String(group)))
    .join("\n");
}

function parseApiGroupsText(text) {
  return String(text || "")
    .split(/\r?\n/)
    .map((line) => parseApiList(line))
    .filter((group) => group.length > 0);
}

function setRuleEditorSectionVisible(id, visible) {
  document.getElementById(id)?.classList.toggle("hidden", !visible);
}

function formatGatesHuman(rule) {
  if (!rule) return "-";
  const lines = [];
  lines.push(rule.enabled !== false ? "Rule enabled" : "Rule disabled");
  if (rule.require_execution) lines.push("Require execution (SetThreadContext, CreateRemoteThread, NtTestAlert…)");
  if (rule.require_cross_process) lines.push("Require cross-process inject");
  if (rule.require_same_process) lines.push("Require same-process (self-inject)");
  if (rule.require_section_mapping) lines.push("Require section mapping");
  if (rule.require_context_read) lines.push("Require thread context read");
  lines.push(`Need ≥ ${rule.min_primitive_kinds ?? 2} primitive kinds (allocate / write / execute)`);
  const minScore = Number(rule.min_finding_score ?? 0);
  if (minScore > 0) lines.push(`Finding score ≥ ${minScore}`);
  return lines.join(" · ");
}

function setRuleEditorHelp(html) {
  const node = document.getElementById("rule-editor-help");
  if (node) node.innerHTML = html;
}

function populateRuleViewPanel(rule, { isBuiltin }) {
  const summary = document.getElementById("rule-view-summary");
  const apis = document.getElementById("rule-view-apis");
  const conditions = document.getElementById("rule-view-conditions");
  const technique = document.getElementById("rule-view-technique");
  const confidence = document.getElementById("rule-view-confidence");
  if (!summary) return;
  summary.textContent = isBuiltin
    ? rule.description || "Built-in rule — fixed API list, not editable directly."
    : rule.description || rule.rationale || "Custom rule — you choose APIs from the log.";
  apis.textContent = formatRuleMatchFromPayload(rule);
  if ((rule.signals || []).length) {
    apis.textContent += `\n\nAdditional signals: ${rule.signals.join(", ")}`;
  }
  conditions.textContent = formatGatesHuman(rule);
  technique.textContent = formatTechniqueLabel(rule.technique);
  confidence.textContent = formatAutoConfidenceLabel(rule.confidence || rule.auto_confidence || "auto");
  if (isBuiltin) {
    setRuleViewNextSteps(
      "<p><strong>What can you change?</strong></p>"
      + "<p>• Toggle or tighten gates → click <strong>Edit gates</strong> below.</p>"
      + "<p>• Change API list → click <strong>Duplicate to custom</strong>.</p>",
    );
  } else {
    setRuleViewNextSteps(
      "<p><strong>Want to edit?</strong> Click <strong>Edit</strong> → fill APIs (one step per line) → open "
      + "<em>Gate conditions</em> if you need cross-process / execution filters.</p>",
    );
  }
}

function populateRuleEditorGates(rule, { includeCustomSignals = false } = {}) {
  const data = rule || {};
  document.getElementById("rule-editor-min-kinds").value = String(data.min_primitive_kinds ?? 2);
  document.getElementById("rule-editor-min-score").value = String(data.min_finding_score ?? 0);
  document.getElementById("rule-editor-confidence").value = data.confidence || "";
  document.getElementById("rule-editor-enabled").checked = data.enabled !== false;
  document.getElementById("rule-editor-req-exec").checked = Boolean(data.require_execution);
  document.getElementById("rule-editor-req-cross").checked = Boolean(data.require_cross_process);
  document.getElementById("rule-editor-req-same").checked = Boolean(data.require_same_process);
  const sectionToggle = document.getElementById("rule-editor-req-section");
  const contextToggle = document.getElementById("rule-editor-req-context");
  if (sectionToggle) {
    sectionToggle.checked = Boolean(data.require_section_mapping);
    sectionToggle.closest("label")?.classList.toggle("hidden", !includeCustomSignals);
  }
  if (contextToggle) {
    contextToggle.checked = Boolean(data.require_context_read);
    contextToggle.closest("label")?.classList.toggle("hidden", !includeCustomSignals);
  }
}

function populateRuleEditorCustom(rule) {
  const isEdit = Boolean(rule?.id);
  const idInput = document.getElementById("rule-editor-id");
  idInput.value = rule?.id || "";
  idInput.readOnly = isEdit;
  document.getElementById("rule-editor-label").value = rule?.label || "";
  document.getElementById("rule-editor-technique").value = rule?.technique || "unclassified";
  document.getElementById("rule-editor-priority").value = String(rule?.priority ?? 500);
  document.getElementById("rule-editor-phase").value = rule?.eval_phase || "before_builtin";
  document.getElementById("rule-editor-api-groups").value = formatApiGroupsText(rule?.api_groups);
  document.getElementById("rule-editor-required-apis").value = formatApiList(rule?.required_apis);
  document.getElementById("rule-editor-any-apis").value = formatApiList(rule?.any_apis);
  document.getElementById("rule-editor-description").value = rule?.description || "";
  document.getElementById("rule-editor-rationale").value = rule?.rationale || "";
  document.querySelectorAll("#rule-editor-kinds input[type=checkbox]").forEach((input) => {
    input.checked = (rule?.required_kinds || []).includes(input.value);
  });
}

function openRuleEditor(mode, rule) {
  const modal = document.getElementById("rule-editor-modal");
  if (!modal) return;
  ruleEditorMode = mode;
  ruleEditorRuleId = rule?.id || null;

  const title = document.getElementById("rule-editor-title");
  const eyebrow = document.getElementById("rule-editor-eyebrow");
  const saveBtn = document.getElementById("rule-editor-save-btn");
  const editBtn = document.getElementById("rule-editor-edit-btn");
  const deleteBtn = document.getElementById("rule-editor-delete-btn");
  const duplicateBtn = document.getElementById("rule-editor-duplicate-btn");

  const isBuiltin = mode.startsWith("builtin");
  const isView = mode.endsWith("-view");
  const isEdit = !isView;

  setRuleEditorSectionVisible("rule-editor-view-panel", isView);
  setRuleEditorSectionVisible("rule-editor-custom-panel", mode === "custom-new" || mode === "custom-edit");
  setRuleEditorSectionVisible("rule-editor-gates-panel", isEdit);

  const gatesDetails = document.getElementById("rule-editor-gates-details");
  const gatesSummary = document.getElementById("rule-editor-gates-summary");
  if (gatesDetails) {
    if (mode === "builtin-edit") {
      gatesDetails.open = true;
      gatesDetails.classList.add("gates-required");
      if (gatesSummary) gatesSummary.textContent = "Edit gate conditions";
    } else {
      gatesDetails.classList.remove("gates-required");
      if (gatesSummary) gatesSummary.textContent = "Gate conditions (expand if needed)";
      if (mode === "custom-new") {
        gatesDetails.open = false;
      } else if (mode === "custom-edit") {
        gatesDetails.open = ruleHasActiveGates(rule);
      }
    }
  }

  document.querySelectorAll(".gate-custom-only").forEach((node) => {
    node.classList.toggle("hidden", isBuiltin);
  });

  if (!isView) {
    setRuleViewNextSteps("");
  }

  if (isBuiltin) {
    eyebrow.textContent = "Built-in rule";
    title.textContent = rule?.label || rule?.id || "Built-in rule";
    if (isView) {
      setRuleEditorHelp(
        "<p><strong>How to read this:</strong> The rule matches when the log contains the APIs below. "
        + "You <em>cannot edit</em> the API list — only toggle the rule or adjust <strong>gate conditions</strong>. "
        + "To change APIs → click <strong>Duplicate to custom</strong>.</p>",
      );
      populateRuleViewPanel(rule, { isBuiltin: true });
    } else {
      setRuleEditorHelp(
        "<p><strong>Edit gates:</strong> Enable a condition to require it on the finding. "
        + "Example: enable <em>cross-process</em> so the rule skips same-process inject.</p>",
      );
      populateRuleEditorGates(rule, { includeCustomSignals: false });
    }
  } else if (mode === "custom-view") {
    eyebrow.textContent = "Custom rule";
    title.textContent = rule?.label || rule?.id || "Custom rule";
    setRuleEditorHelp("<p>Your custom rule. Click <strong>Edit</strong> to change APIs or gate conditions.</p>");
    populateRuleViewPanel(rule, { isBuiltin: false });
  } else {
    eyebrow.textContent = "Custom rule";
    title.textContent = mode === "custom-edit" ? `Edit: ${rule?.label || rule?.id}` : "Add new rule";
    setRuleEditorHelp(
      "<p><strong>3 steps:</strong> (1) Name + technique. "
      + "(2) Fill APIs — one step per line in the inject chain. "
      + "(3) Enable gate conditions if needed (often <em>cross-process</em> for inject into Edge).</p>"
      + "<p class=\"rule-help-example\"><strong>Edge example:</strong><br>"
      + "<code>ntallocatevirtualmemory</code><br><code>ntwritevirtualmemory</code><br>"
      + "<code>ntmapviewofsection</code><br><code>setthreadcontext</code></p>",
    );
    populateRuleEditorCustom(rule || {});
    populateRuleEditorGates(rule || {}, { includeCustomSignals: true });
  }

  editBtn.textContent = isBuiltin ? "Edit gates" : "Edit";
  editBtn.classList.toggle("hidden", !isView);
  saveBtn.classList.toggle("hidden", isView);
  deleteBtn.classList.toggle("hidden", mode !== "custom-edit");
  duplicateBtn.classList.toggle("hidden", !isBuiltin || !isView);

  modal.showModal();
}

function builtinRuleToCustomDraft(rule) {
  const suffix = "_custom";
  let id = slugifyRuleId(`${rule.id}${suffix}`);
  const existing = new Set((classifierRulesDraft?.custom_rules || []).map((item) => item.id));
  let counter = 2;
  while (existing.has(id)) {
    id = slugifyRuleId(`${rule.id}${suffix}${counter}`);
    counter += 1;
  }
  return {
    id,
    label: `${rule.label || rule.id} (custom)`,
    technique: rule.technique || "unclassified",
    enabled: true,
    priority: 700,
    eval_phase: "before_builtin",
    confidence: rule.confidence || "",
    api_groups: Array.isArray(rule.api_groups) ? rule.api_groups.map((group) => [...group]) : [],
    required_apis: [],
    any_apis: [],
    required_kinds: [],
    min_primitive_kinds: rule.min_primitive_kinds ?? 2,
    min_finding_score: rule.min_finding_score ?? 0,
    require_execution: Boolean(rule.require_execution),
    require_cross_process: Boolean(rule.require_cross_process),
    require_same_process: Boolean(rule.require_same_process),
    require_section_mapping: false,
    require_context_read: false,
    description: rule.description || "",
    rationale: `Custom copy of built-in rule ${rule.id}.`,
    source: "custom",
  };
}

function collectCustomRulePayload() {
  const idRaw = document.getElementById("rule-editor-id")?.value || "";
  const label = document.getElementById("rule-editor-label")?.value || "";
  let id = slugifyRuleId(idRaw || label);
  if (!/^[a-z][a-z0-9_-]{1,63}$/.test(id)) {
    throw new Error("Rule ID must be a slug: lowercase letters, numbers, underscores, hyphens.");
  }
  const requiredKinds = [];
  document.querySelectorAll("#rule-editor-kinds input[type=checkbox]:checked").forEach((input) => {
    requiredKinds.push(input.value);
  });
  const apiGroups = parseApiGroupsText(document.getElementById("rule-editor-api-groups")?.value);
  return {
    id,
    label: label || id,
    technique: document.getElementById("rule-editor-technique")?.value || "unclassified",
    enabled: Boolean(document.getElementById("rule-editor-enabled")?.checked),
    priority: Number(document.getElementById("rule-editor-priority")?.value || 500),
    eval_phase: document.getElementById("rule-editor-phase")?.value || "before_builtin",
    confidence: document.getElementById("rule-editor-confidence")?.value || "",
    api_groups: apiGroups,
    required_apis: parseApiList(document.getElementById("rule-editor-required-apis")?.value),
    any_apis: parseApiList(document.getElementById("rule-editor-any-apis")?.value),
    required_kinds: requiredKinds,
    min_primitive_kinds: Number(document.getElementById("rule-editor-min-kinds")?.value || 2),
    min_finding_score: Number(document.getElementById("rule-editor-min-score")?.value || 0),
    require_execution: Boolean(document.getElementById("rule-editor-req-exec")?.checked),
    require_cross_process: Boolean(document.getElementById("rule-editor-req-cross")?.checked),
    require_same_process: Boolean(document.getElementById("rule-editor-req-same")?.checked),
    require_section_mapping: Boolean(document.getElementById("rule-editor-req-section")?.checked),
    require_context_read: Boolean(document.getElementById("rule-editor-req-context")?.checked),
    description: document.getElementById("rule-editor-description")?.value || "",
    rationale: document.getElementById("rule-editor-rationale")?.value || "",
    source: "custom",
  };
}

function collectBuiltinGatePayload(ruleId) {
  return {
    id: ruleId,
    enabled: Boolean(document.getElementById("rule-editor-enabled")?.checked),
    min_primitive_kinds: Number(document.getElementById("rule-editor-min-kinds")?.value || 2),
    min_finding_score: Number(document.getElementById("rule-editor-min-score")?.value || 0),
    require_execution: Boolean(document.getElementById("rule-editor-req-exec")?.checked),
    require_cross_process: Boolean(document.getElementById("rule-editor-req-cross")?.checked),
    require_same_process: Boolean(document.getElementById("rule-editor-req-same")?.checked),
    confidence: document.getElementById("rule-editor-confidence")?.value || "",
  };
}

async function saveRuleEditor() {
  try {
    if (ruleEditorMode === "builtin-edit") {
      if (!ruleEditorRuleId) throw new Error("Missing built-in rule id.");
      const gatePayload = collectBuiltinGatePayload(ruleEditorRuleId);
      setRulesStatus("Saving gates…");
      const response = await fetch("/api/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          minimum_score: classifierRulesDraft?.minimum_score ?? 50,
          minimum_operational_kinds: classifierRulesDraft?.minimum_operational_kinds ?? 2,
          classification_enabled: classifierRulesDraft?.classification_enabled ?? true,
          require_cross_process_findings: classifierRulesDraft?.require_cross_process_findings ?? false,
          ignore_same_process_findings: classifierRulesDraft?.ignore_same_process_findings ?? false,
          rules: [gatePayload],
          custom_rules: classifierRulesDraft?.custom_rules || [],
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || `Save failed (${response.status})`);
      document.getElementById("rule-editor-modal")?.close();
      renderClassifierRules(result, result.config_path);
      setRulesStatus(result.message || "Gates saved.", "ok");
      return;
    }

    if (ruleEditorMode === "custom-new" || ruleEditorMode === "custom-edit") {
      const payload = collectCustomRulePayload();
      if (ruleEditorMode === "custom-edit" && ruleEditorRuleId && ruleEditorRuleId !== payload.id) {
        throw new Error("Cannot change Rule ID while editing. Delete and recreate if needed.");
      }
      if (!payload.api_groups.length && !payload.required_apis.length) {
        throw new Error("Need at least API groups or Required APIs.");
      }
      setRulesStatus("Saving custom rule…");
      const response = await fetch(`/api/rules/custom/${encodeURIComponent(payload.id)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || `Save failed (${response.status})`);
      document.getElementById("rule-editor-modal")?.close();
      renderClassifierRules(result, result.config_path);
      setRulesStatus(result.message || "Custom rule saved.", "ok");
    }
  } catch (error) {
    console.error(error);
    setRulesStatus(error.message || "Could not save rule", "error");
  }
}

async function deleteCustomRuleById(ruleId) {
  if (!ruleId) return;
  const rule = (classifierRulesDraft?.custom_rules || []).find((item) => item.id === ruleId);
  const label = rule?.label || ruleId;
  if (!window.confirm(`Delete custom rule "${label}"?`)) return;
  setRulesStatus("Deleting…");
  try {
    const response = await fetch(`/api/rules/custom/${encodeURIComponent(ruleId)}`, {
      method: "DELETE",
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Delete failed (${response.status})`);
    document.getElementById("rule-editor-modal")?.close();
    renderClassifierRules(result, result.config_path);
    setRulesStatus(result.message || "Rule deleted.", "ok");
  } catch (error) {
    console.error(error);
    setRulesStatus(error.message || "Could not delete rule", "error");
  }
}

async function deleteRuleFromEditor() {
  if (!ruleEditorRuleId) return;
  await deleteCustomRuleById(ruleEditorRuleId);
}

function duplicateBuiltinFromEditor() {
  const rule = (classifierRulesDraft?.rules || []).find((item) => item.id === ruleEditorRuleId);
  if (!rule) return;
  openRuleEditor("custom-new", builtinRuleToCustomDraft(rule));
}

function renderCustomRulesTable(customRules) {
  const body = document.getElementById("custom-rules-body");
  if (!body) return;
  const rows = customRules || [];
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="4" class="empty">No custom rules yet. Click + Add rule.</td></tr>';
    return;
  }
  body.innerHTML = rows
    .map(
      (rule) => `
      <tr data-custom-rule-id="${rule.id}" class="rules-row-clickable">
        <td><span class="rule-status-dot ${rule.enabled ? "on" : "off"}" title="${rule.enabled ? "Enabled" : "Disabled"}"></span></td>
        <td class="rule-name-cell">
          <span class="rule-label">${escapeHtml(rule.label || rule.id)}</span>
        </td>
        <td class="mono">${formatTechniqueLabel(rule.technique)}</td>
        <td class="rules-row-actions">
          <button type="button" class="btn-mini" data-custom-rule-view="${rule.id}">View</button>
          <button type="button" class="btn-mini" data-custom-rule-edit="${rule.id}">Edit</button>
          <button type="button" class="btn-mini danger" data-custom-rule-delete="${rule.id}">Delete</button>
        </td>
      </tr>`,
    )
    .join("");
}

function renderClassifierRules(rulesPayload, configPath) {
  if (!rulesPayload) return;
  classifierTechniques = rulesPayload.techniques || classifierTechniques;
  populateTechniqueSelect(document.getElementById("rule-editor-technique"), classifierTechniques);
  classifierRulesDraft = {
    minimum_score: rulesPayload.minimum_score,
    minimum_operational_kinds: rulesPayload.minimum_operational_kinds,
    classification_enabled: rulesPayload.classification_enabled,
    require_cross_process_findings: rulesPayload.require_cross_process_findings,
    ignore_same_process_findings: rulesPayload.ignore_same_process_findings,
    rules: (rulesPayload.rules || []).map((rule) => ({ ...rule })),
    custom_rules: (rulesPayload.custom_rules || []).map((rule) => ({ ...rule })),
  };
  renderCustomRulesTable(classifierRulesDraft.custom_rules);
  const chip = document.getElementById("rules-config-chip");
  if (chip && configPath) {
    chip.textContent = configPath.split(/[\\/]/).pop() || ".classifier_rules.json";
    chip.title = configPath;
  }
  const scoreInput = document.getElementById("rules-minimum-score");
  if (scoreInput) {
    scoreInput.value = String(rulesPayload.minimum_score ?? 50);
  }
  const kindsInput = document.getElementById("rules-minimum-operational-kinds");
  if (kindsInput) {
    kindsInput.value = String(rulesPayload.minimum_operational_kinds ?? 2);
  }
  const enabledToggle = document.getElementById("rules-classification-enabled");
  if (enabledToggle) {
    enabledToggle.checked = Boolean(rulesPayload.classification_enabled);
  }
  const crossToggle = document.getElementById("rules-require-cross-process");
  if (crossToggle) {
    crossToggle.checked = Boolean(rulesPayload.require_cross_process_findings);
  }
  const sameToggle = document.getElementById("rules-ignore-same-process");
  if (sameToggle) {
    sameToggle.checked = Boolean(rulesPayload.ignore_same_process_findings);
  }
  const body = document.getElementById("rules-body");
  if (!body) return;
  const rows = (rulesPayload.rules || []).filter((rule) => rule.source !== "custom");
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="4" class="empty">No built-in rules.</td></tr>';
    return;
  }
  body.innerHTML = rows
    .map(
      (rule) => `
      <tr data-rule-row="${rule.id}" class="rules-row-clickable">
        <td><input type="checkbox" data-rule-id="${rule.id}" data-field="enabled" ${rule.enabled ? "checked" : ""} title="Toggle rule" /></td>
        <td class="rule-name-cell">
          <span class="rule-label">${escapeHtml(rule.label || rule.id)}</span>
        </td>
        <td class="mono">${formatTechniqueLabel(rule.technique)}</td>
        <td class="rules-row-actions">
          <button type="button" class="btn-mini" data-builtin-rule-view="${rule.id}">View</button>
        </td>
      </tr>`,
    )
    .join("");
  setRulesStatus("Toggle built-in rules with checkbox → Save settings. API details: click View.");
}

function setRulesStatus(message, kind = "") {
  const node = document.getElementById("rules-status");
  if (!node) return;
  node.textContent = message;
  node.classList.remove("ok", "error");
  if (kind) node.classList.add(kind);
}

function collectRuleRowSettings(row) {
  const ruleId = row.dataset.ruleRow;
  if (!ruleId) return null;
  const draft = (classifierRulesDraft?.rules || []).find((item) => item.id === ruleId);
  const enabled = Boolean(row.querySelector(`[data-rule-id="${ruleId}"][data-field="enabled"]`)?.checked);
  return {
    id: ruleId,
    enabled,
    min_primitive_kinds: draft?.min_primitive_kinds ?? 2,
    require_execution: Boolean(draft?.require_execution),
    require_cross_process: Boolean(draft?.require_cross_process),
    require_same_process: Boolean(draft?.require_same_process),
    min_finding_score: draft?.min_finding_score ?? 0,
    confidence: draft?.confidence || "",
  };
}

async function saveClassifierRules() {
  const scoreInput = document.getElementById("rules-minimum-score");
  const kindsInput = document.getElementById("rules-minimum-operational-kinds");
  const enabledToggle = document.getElementById("rules-classification-enabled");
  const crossToggle = document.getElementById("rules-require-cross-process");
  const sameToggle = document.getElementById("rules-ignore-same-process");
  const body = document.getElementById("rules-body");
  const rules = [];
  body?.querySelectorAll("tr[data-rule-row]").forEach((row) => {
    const item = collectRuleRowSettings(row);
    if (item) rules.push(item);
  });
  const payload = {
    minimum_score: Number(scoreInput?.value || 50),
    minimum_operational_kinds: Number(kindsInput?.value || 2),
    classification_enabled: Boolean(enabledToggle?.checked),
    require_cross_process_findings: Boolean(crossToggle?.checked),
    ignore_same_process_findings: Boolean(sameToggle?.checked),
    rules,
    custom_rules: classifierRulesDraft?.custom_rules || [],
  };
  setRulesStatus("Saving…");
  try {
    const response = await fetch("/api/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || `API error ${response.status}`);
    }
    renderClassifierRules(result, result.config_path);
    setRulesStatus(result.message || "Settings saved.", "ok");
  } catch (error) {
    console.error(error);
    setRulesStatus(error.message || "Could not save settings", "error");
  }
}

function renderSessionViews(session) {
  renderFindings(session.findings || []);
  renderNetwork(session.network || []);
  renderPrimitives(session.primitives || []);
  renderTriages(session.pending_file_drops || [], session.triages || []);
  renderEvents(session.events || []);
  renderInjectionChainsFromStats(session.stats);
}

function openFindingModal(finding) {
  const modal = document.getElementById("finding-modal");
  document.getElementById("modal-title").textContent = finding.title || finding.description || "Injection finding";
  const severity = String(finding.severity || "unknown").toLowerCase();
  const targetLabel = finding.target_image
    ? `${finding.target_image}${finding.target_pid != null ? ` (pid ${finding.target_pid})` : ""}`
    : finding.target_pid != null
      ? `pid ${finding.target_pid}`
      : "-";
  document.getElementById("modal-summary").innerHTML = `
    <div class="detail-row"><dt>Severity</dt><dd><span class="severity ${severity}">${severity}</span></dd></div>
    <div class="detail-row"><dt>Score</dt><dd>${finding.score ?? "-"}</dd></div>
    <div class="detail-row"><dt>Actor</dt><dd class="mono">${finding.actor_image || `pid ${finding.actor_pid ?? "-"}`}</dd></div>
    <div class="detail-row"><dt>Injection target</dt><dd class="mono">${targetLabel}</dd></div>
    <div class="detail-row"><dt>Technique</dt><dd class="mono">${finding.technique || "unclassified"}${finding.technique_confidence ? ` (${finding.technique_confidence})` : ""}</dd></div>
    <div class="detail-row"><dt>Payload</dt><dd class="mono">${finding.payload_kind || "unknown"}</dd></div>
    <div class="detail-row"><dt>Execution confirmed</dt><dd>${finding.execution_confirmed === false ? "no" : finding.execution_confirmed ? "yes" : "unknown"}</dd></div>
    <div class="detail-row"><dt>Execution evidence</dt><dd class="mono">${(finding.execution_evidence || []).join(", ") || "-"}</dd></div>
    <div class="detail-row"><dt>Context read</dt><dd class="mono">${(finding.context_read_evidence || []).join(", ") || "-"}</dd></div>
    <div class="detail-row"><dt>Time</dt><dd>${formatTime(finding.timestamp)}</dd></div>
  `;
  document.getElementById("modal-apis").innerHTML = (finding.apis || [])
    .map((api) => `<span class="tag">${api}</span>`)
    .join("");
  document.getElementById("modal-evidence").textContent = JSON.stringify(finding.evidence || {}, null, 2);

  const primitives = finding.primitives || [];
  document.getElementById("modal-primitives").innerHTML = primitives.length
    ? `<table>
        <thead><tr><th>Kind</th><th>API</th><th>Injection target</th><th>Address</th></tr></thead>
        <tbody>
          ${primitives
            .map(
              (row) => `
            <tr>
              <td>${row.kind || "-"}</td>
              <td class="mono">${row.api || "-"}</td>
              <td>${formatInjectionTarget(row)}</td>
              <td class="mono">${row.address ?? "-"}</td>
            </tr>`
            )
            .join("")}
        </tbody>
      </table>`
    : '<div class="empty">No primitive evidence attached.</div>';

  const network = finding.network || [];
  document.getElementById("modal-network").innerHTML = network.length
    ? `<table>
        <thead><tr><th>Endpoint</th><th>Protocol</th><th>Beacon?</th></tr></thead>
        <tbody>
          ${network
            .map(
              (row) => `
            <tr>
              <td class="mono">${row.endpoint || "-"}</td>
              <td>${row.protocol || "-"}</td>
              <td>${row.beacon_candidate ? "candidate" : "-"}</td>
            </tr>`
            )
            .join("")}
        </tbody>
      </table>`
    : '<div class="empty">No related network activity.</div>';

  modal.showModal();
  if (finding && finding._index !== undefined) {
    writeHash({ finding: String(finding._index) });
    modal.addEventListener(
      "close",
      () => writeHash({ finding: "" }),
      { once: true },
    );
  }
}

async function loadClassifierRules() {
  const response = await fetch("/api/rules");
  if (!response.ok) {
    setRulesStatus(`Could not load rules (${response.status})`, "error");
    return null;
  }
  const payload = await response.json();
  renderClassifierRules(payload, payload.config_path);
  return payload;
}

async function loadOverview(selectedLog, { includeRules = false } = {}) {
  const params = new URLSearchParams();
  if (selectedLog) params.set("log", selectedLog);
  if (includeRules) params.set("include_rules", "1");
  const query = params.toString();
  const response = await fetch(query ? `/api/overview?${query}` : "/api/overview");
  if (!response.ok) {
    showLoadError(t("error.api", { status: response.status }));
    return null;
  }
  return response.json();
}

async function loadSession(name, filters) {
  if (!name) return null;
  const response = await fetch(`/api/session/${encodeURIComponent(name)}${buildSessionQuery(filters)}`);
  if (!response.ok) {
    return null;
  }
  return response.json();
}

async function loadRuntimeConfig() {
  const response = await fetch("/api/runtime");
  if (!response.ok) {
    return null;
  }
  return response.json();
}

function renderRuntimeControls(runtime) {
  if (!runtime) return;
  state.runtime = runtime;

  const toggle = document.getElementById("file-drop-toggle");
  const autoApiToggle = document.getElementById("auto-api-toggle");
  const hint = document.getElementById("runtime-hint");
  const status = document.getElementById("collector-status-chip");

  toggle.checked = Boolean(runtime.file_drop_watch_enabled);
  toggle.disabled = Boolean(runtime.file_drop_watch_locked) || state.runtimeSaving;
  autoApiToggle.checked = Boolean(
    runtime.auto_api_analysis_enabled ?? runtime.auto_triage_enabled
  );
  autoApiToggle.disabled = Boolean(runtime.file_drop_watch_locked) || state.runtimeSaving;

  if (runtime.collector_online) {
    status.textContent = t("upload.collectorOnline");
    status.classList.add("online");
    status.classList.remove("offline");
  } else {
    status.textContent = t("upload.collectorOffline");
    status.classList.add("offline");
    status.classList.remove("online");
  }

  const paths = (runtime.watch_paths || []).join(", ");
  if (runtime.file_drop_watch_locked) {
    hint.textContent = t("files.hint.locked");
  } else if (!runtime.collector_online) {
    hint.textContent = t("files.hint.offline");
  } else if (runtime.auto_api_analysis_enabled || runtime.auto_triage_enabled) {
    hint.textContent = paths ? t("files.hint.autoOn", { paths }) : t("files.hint.autoOnNoPaths");
  } else if (runtime.file_drop_watch_enabled) {
    hint.textContent = paths ? t("files.hint.watchOn", { paths }) : t("files.hint.watchOnNoPaths");
  } else {
    hint.textContent = t("files.hint.paused");
  }
}

async function saveRuntimeConfig(patch) {
  state.runtimeSaving = true;
  renderRuntimeControls({ ...(state.runtime || {}), ...patch });
  try {
    const response = await fetch("/api/runtime", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || `API error ${response.status}`);
    }
    renderRuntimeControls(payload);
  } catch (error) {
    console.error(error);
    if (state.runtime) {
      renderRuntimeControls(state.runtime);
    }
    showLoadError(t("error.runtimeUpdate"));
  } finally {
    state.runtimeSaving = false;
    if (state.runtime) {
      renderRuntimeControls(state.runtime);
    }
  }
}

function shouldPauseRefresh() {
  const findingModal = document.getElementById("finding-modal");
  const ruleModal = document.getElementById("rule-editor-modal");
  return Boolean(findingModal?.open || ruleModal?.open || document.hidden);
}

let liveRefreshTimer = null;

function scheduleDashboardRefresh(selectedLog, { force = false } = {}) {
  if (force) {
    if (liveRefreshTimer) {
      clearTimeout(liveRefreshTimer);
      liveRefreshTimer = null;
    }
    return loadDashboard(selectedLog, { force: true });
  }
  if (shouldPauseRefresh()) {
    return;
  }
  if (liveRefreshTimer) {
    return;
  }
  liveRefreshTimer = setTimeout(() => {
    liveRefreshTimer = null;
    const selected = selectedLog || document.getElementById("log-select")?.value;
    loadDashboard(selected || undefined);
  }, LIVE_REFRESH_DEBOUNCE_MS);
}

async function loadDashboard(selectedLog, { force = false } = {}) {
  if (!force && shouldPauseRefresh()) {
    return;
  }

  setLoading(true);
  try {
    const filters = currentFilters();
    state.filters = filters;

    const overview = await loadOverview(selectedLog);
    if (!overview) return;

    state.overview = overview;
    state.activeLog = overview.active_log || selectedLog || "";

    document.getElementById("logs-dir").textContent = overview.logs_dir;
    document.getElementById("active-log-label").textContent =
      state.activeLog || t("status.noLogSelected");
    document.getElementById("file-count").textContent = t("status.files", {
      count: overview.files.length,
    });
    renderStatusBar(overview);

  populateLogSelect(overview.files, state.activeLog);

  if (state.activeTab === "chains" || force) {
    renderInjectionChainsFromStats(overview.stats);
  }

  if (state.activeTab === "overview" || state.activeTab === "sessions" || state.activeTab === "upload" || force) {
    if (state.activeTab === "overview" || force) {
      renderOverview(overview);
    }
    if (state.activeTab === "sessions" || force) {
      renderFiles(overview.files, state.activeLog);
    }
    if (state.activeTab === "upload" || force) {
      renderUploads(
        overview.uploads || [],
        overview.db_path || "",
        Boolean(overview.collector_online),
      );
    }
  }

  if ((state.activeTab === "files" || force) && !state.liveSocketConnected) {
    const runtime = await loadRuntimeConfig();
    if (runtime) {
      renderRuntimeControls(runtime);
    }
  }

  const needsSession = force || SESSION_TABS.has(state.activeTab);
  if (state.activeLog && needsSession) {
    const session = await loadSession(state.activeLog, filters);
    state.session = session;
    if (session) {
      if (state.activeTab === "findings" || force) {
        renderFindings(session.findings || []);
      }
      if (state.activeTab === "network" || force) {
        renderNetwork(session.network || []);
      }
      if (state.activeTab === "primitives" || force) {
        renderPrimitives(session.primitives || []);
      }
      if (state.activeTab === "events" || force) {
        renderEvents(session.events || []);
      }
      if (state.activeTab === "files" || force) {
        renderTriages(
          session.pending_file_drops || state.overview?.stats?.pending_file_drops || [],
          session.triages || state.overview?.stats?.recent_triages || []
        );
      }
      if (force) {
        renderSessionViews(session);
      }
    }
  } else if (force) {
    renderFindings([]);
    renderNetwork([]);
    renderPrimitives([]);
    renderEvents([]);
    renderInjectionChains([], 0);
  }
  } finally {
    setLoading(false);
  }
}

function switchTab(tabName) {
  state.activeTab = tabName;
  writeHash({ tab: tabName === "overview" ? "" : tabName });
  document.querySelectorAll(".tab").forEach((tab) => {
    const active = tab.dataset.tab === tabName;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", active ? "true" : "false");
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.panel === tabName);
  });

  if (state.overview) {
    if (tabName === "overview") {
      renderOverview(state.overview);
    }
    if (tabName === "upload") {
      renderUploads(
        state.overview.uploads || [],
        state.overview.db_path || "",
        Boolean(state.overview.collector_online),
      );
    }
    if (tabName === "sessions") {
      renderFiles(state.overview.files, state.activeLog);
    }
  }
  if (tabName === "files") {
    loadRuntimeConfig().then((runtime) => {
      if (runtime) renderRuntimeControls(runtime);
    });
  }
  if (tabName === "rules") {
    loadClassifierRules();
  }
  if (tabName === "chains") {
    renderInjectionChainsFromStats(chainsStatsSource());
  }
  if (tabName === "corpus" || tabName === "sessions") {
    loadCorpus({ force: !state.corpus });
  }
  if (state.session) {
    if (tabName === "findings") {
      renderFindings(state.session.findings || []);
    }
    if (tabName === "network") {
      renderNetwork(state.session.network || []);
    }
    if (tabName === "primitives") {
      renderPrimitives(state.session.primitives || []);
    }
    if (tabName === "events") {
      renderEvents(state.session.events || []);
    }
    if (tabName === "files") {
      renderTriages(
        state.session?.pending_file_drops || state.overview?.stats?.pending_file_drops || [],
        state.session?.triages || state.overview?.stats?.recent_triages || []
      );
    }
  }
}

function applyFilters() {
  const selected = document.getElementById("log-select").value;
  Object.keys(fingerprints).forEach((key) => delete fingerprints[key]);
  // Sync filter + log state to the URL hash so the view is deep-linkable.
  const f = currentFilters();
  writeHash({
    log: selected || "",
    query: f.query || "",
    severity: f.severity || "",
    pid: f.pid !== "" ? String(f.pid) : "",
    type: f.type || "",
  });
  loadDashboard(selected || undefined, { force: true });
}

function clearFilters() {
  document.getElementById("filter-query").value = "";
  document.getElementById("filter-severity").value = "";
  document.getElementById("filter-pid").value = "";
  document.getElementById("filter-type").value = "";
  applyFilters();
}

// Debounced version for live-as-you-type filtering (input event).
const applyFiltersDebounced = debounce(applyFilters, 220);

function setupDelegatedClicks() {
  document.getElementById("findings-body").addEventListener("click", (event) => {
    const row = event.target.closest("[data-finding-index]");
    if (!row || !state.session) return;
    const index = Number(row.dataset.findingIndex);
    const finding = (state.session.findings || [])[index];
    if (finding) {
      finding._index = index; // tag for deep-link sync
      openFindingModal(finding);
    }
  });

  document.getElementById("network-body").addEventListener("click", (event) => {
    const row = event.target.closest("[data-network-pid]");
    if (!row) return;
    const pid = row.dataset.networkPid;
    if (!pid) return;
    document.getElementById("filter-pid").value = pid;
    document.getElementById("filter-type").value = "network";
    applyFilters();
    switchTab("network");
  });

  document.getElementById("uploads-body")?.addEventListener("click", (event) => {
    const runButton = event.target.closest("[data-upload-run]");
    if (runButton && !runButton.disabled) {
      const uploadId = Number(runButton.dataset.uploadRun);
      if (uploadId) runUploadAnalysis(uploadId, runButton);
      return;
    }
    const deleteButton = event.target.closest("[data-upload-delete]");
    if (deleteButton) {
      const uploadId = Number(deleteButton.dataset.uploadDelete);
      if (uploadId) deleteUpload(uploadId);
      return;
    }
    const reportButton = event.target.closest("[data-upload-report]");
    if (reportButton) {
      const uploadId = Number(reportButton.dataset.uploadReport);
      if (uploadId) openUploadReport(uploadId);
    }
  });

  document.getElementById("triage-body").addEventListener("click", (event) => {
    const button = event.target.closest("[data-analyze-path]");
    if (!button || button.disabled) return;
    const path = decodeURIComponent(button.dataset.analyzePath || "");
    if (!path) return;
    requestFileAnalysis(path, button);
  });

  document.getElementById("files-body").addEventListener("click", (event) => {
    const row = event.target.closest("[data-session-name]");
    if (!row) return;
    document.getElementById("log-select").value = row.dataset.sessionName;
    applyFilters();
    switchTab("findings");
  });

  document.getElementById("corpus-sessions-body")?.addEventListener("click", (event) => {
    const row = event.target.closest("[data-session-name]");
    if (!row) return;
    document.getElementById("log-select").value = row.dataset.sessionName;
    applyFilters();
    switchTab("findings");
  });
}

document.getElementById("corpus-refresh-btn")?.addEventListener("click", () => {
  state.corpus = null;
  loadCorpus({ force: true });
});
document.getElementById("reclassify-btn")?.addEventListener("click", requestReclassify);

document.getElementById("refresh-btn").addEventListener("click", () => {
  const selected = document.getElementById("log-select").value;
  Object.keys(fingerprints).forEach((key) => delete fingerprints[key]);
  loadDashboard(selected || undefined, { force: true });
});
document.getElementById("clear-filters-btn").addEventListener("click", clearFilters);

document.getElementById("log-select").addEventListener("change", (event) => {
  Object.keys(fingerprints).forEach((key) => delete fingerprints[key]);
  writeHash({ log: event.target.value || "" });
  loadDashboard(event.target.value || undefined, { force: true });
});

document.getElementById("export-btn").addEventListener("click", () => {
  const selected = document.getElementById("log-select").value;
  if (!selected) return;
  window.location.href = `/api/export/${encodeURIComponent(selected)}`;
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => switchTab(tab.dataset.tab));
});

// Live filter — debounced for text inputs (so we don't refetch on every
// keystroke); immediate for selects (single-action change).
["filter-query", "filter-pid"].forEach((id) => {
  const el = document.getElementById(id);
  el.addEventListener("input", () => applyFiltersDebounced());
  el.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      applyFilters();
    }
  });
});
["filter-severity", "filter-type"].forEach((id) => {
  document.getElementById(id).addEventListener("change", () => applyFilters());
});

let refreshTimer = null;
let liveSocket = null;
let liveSocketRetry = 0;

function liveSocketUrl() {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/ws/dashboard/`;
}

function handleLiveSocketMessage(event) {
  let message;
  try {
    message = JSON.parse(event.data);
  } catch (error) {
    console.error("invalid websocket payload", error);
    return;
  }
  if (message.type === "runtime" && message.runtime) {
    state.runtime = message.runtime;
    renderRuntimeControls(message.runtime);
    return;
  }
  if (message.type === "refresh") {
    const selected = document.getElementById("log-select")?.value;
    scheduleDashboardRefresh(selected || undefined);
  }
}

let collectorStartRequested = false;

async function requestCollectorStart() {
  if (collectorStartRequested) return;
  collectorStartRequested = true;
  try {
    const response = await fetch("/api/collector/start", { method: "POST" });
    const payload = await response.json();
    if (!response.ok || payload.ok === false) {
      throw new Error(payload.message || payload.error || `API error ${response.status}`);
    }
    if (payload.message) {
      setUploadStatus(payload.message, payload.collector_online ? "ok" : "");
      showToast(payload.message, payload.collector_online ? "success" : "info");
    }
    const selected = document.getElementById("log-select")?.value;
    setTimeout(() => loadDashboard(selected || undefined, { force: true }), 1500);
  } catch (error) {
    console.error(error);
    collectorStartRequested = false;
    const collectorError = error.message || "Could not start collector. Approve UAC or run dashboard as admin.";
    setUploadStatus(collectorError, "error");
    showToast(collectorError, "error");
  }
}

function maybeAutoStartCollector() {
  if (DEMO_MODE) {
    return;
  }
  if (state.runtime?.collector_online || state.overview?.collector_online) {
    return;
  }
  requestCollectorStart();
}

function connectLiveSocket() {
  if (DEMO_MODE || liveSocket) {
    return;
  }
  const socket = new WebSocket(liveSocketUrl());
  liveSocket = socket;

  socket.addEventListener("open", () => {
    liveSocketRetry = 0;
    state.liveSocketConnected = true;
    setupAutoRefresh();
    updateAutoRefreshLabel();
    if (state.overview) {
      renderStatusBar(state.overview);
    }
    setTimeout(maybeAutoStartCollector, 1200);
  });

  socket.addEventListener("message", handleLiveSocketMessage);

  socket.addEventListener("close", () => {
    state.liveSocketConnected = false;
    if (liveSocket === socket) {
      liveSocket = null;
    }
    setupAutoRefresh();
    updateAutoRefreshLabel();
    if (state.overview) {
      renderStatusBar(state.overview);
    }
    const delay = Math.min(10000, 500 * 2 ** liveSocketRetry);
    liveSocketRetry += 1;
    setTimeout(connectLiveSocket, delay);
  });

  socket.addEventListener("error", () => {
    socket.close();
  });
}

function setupAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
  if (DEMO_MODE) {
    // Demo / thesis-screenshot mode: never auto-refresh so the rendered view
    // stays stable for screen capture.
    return;
  }
  if (state.liveSocketConnected) {
    // WebSocket pushes refresh when logs/runtime change.
    return;
  }
  if (document.getElementById("auto-refresh").checked) {
    refreshTimer = setInterval(() => {
      const selected = document.getElementById("log-select").value;
      loadDashboard(selected || undefined);
    }, REFRESH_MS);
  }
}

document.getElementById("auto-refresh").addEventListener("change", () => {
  setupAutoRefresh();
  updateAutoRefreshLabel();
});

document.getElementById("file-drop-toggle").addEventListener("change", (event) => {
  saveRuntimeConfig({ file_drop_watch_enabled: event.target.checked });
});

document.getElementById("auto-api-toggle").addEventListener("change", (event) => {
  const enabled = event.target.checked;
  saveRuntimeConfig({
    auto_api_analysis_enabled: enabled,
    auto_triage_enabled: enabled,
  });
});

async function requestFileAnalysis(path, button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = t("files.queued");
  try {
    const response = await fetch("/api/triage/request", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, mode: "api" }),
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || `API error ${response.status}`);
    }
    button.textContent = "Queued";
    const selected = document.getElementById("log-select").value;
    setTimeout(() => loadDashboard(selected || undefined, { force: true }), 1200);
  } catch (error) {
    console.error(error);
    button.disabled = false;
    button.textContent = original;
    showLoadError(t("error.queueAnalysis"));
  }
}

setupDelegatedClicks();
setupUploadDropzone();
document.getElementById("start-collector-btn")?.addEventListener("click", () => {
  collectorStartRequested = false;
  requestCollectorStart();
});
document.getElementById("rules-save-btn")?.addEventListener("click", saveClassifierRules);
document.getElementById("rules-add-custom-btn")?.addEventListener("click", () => openRuleEditor("custom-new", null));
document.getElementById("rule-editor-save-btn")?.addEventListener("click", (event) => {
  event.preventDefault();
  saveRuleEditor();
});
document.getElementById("rule-editor-edit-btn")?.addEventListener("click", (event) => {
  event.preventDefault();
  if (!ruleEditorRuleId) return;
  if (ruleEditorMode === "builtin-view") {
    const rule = (classifierRulesDraft?.rules || []).find((item) => item.id === ruleEditorRuleId);
    if (rule) openRuleEditor("builtin-edit", rule);
    return;
  }
  if (ruleEditorMode === "custom-view") {
    const rule = (classifierRulesDraft?.custom_rules || []).find((item) => item.id === ruleEditorRuleId);
    if (rule) openRuleEditor("custom-edit", rule);
  }
});
document.getElementById("rule-editor-delete-btn")?.addEventListener("click", (event) => {
  event.preventDefault();
  deleteRuleFromEditor();
});
document.getElementById("rule-editor-duplicate-btn")?.addEventListener("click", (event) => {
  event.preventDefault();
  duplicateBuiltinFromEditor();
});
document.getElementById("rule-editor-label")?.addEventListener("input", (event) => {
  const idInput = document.getElementById("rule-editor-id");
  if (!idInput || idInput.readOnly || idInput.value.trim()) return;
  idInput.value = slugifyRuleId(event.target.value);
});
document.getElementById("custom-rules-body")?.addEventListener("click", (event) => {
  const viewButton = event.target.closest("[data-custom-rule-view]");
  if (viewButton) {
    const rule = (classifierRulesDraft?.custom_rules || []).find((item) => item.id === viewButton.dataset.customRuleView);
    if (rule) openRuleEditor("custom-view", rule);
    return;
  }
  const editButton = event.target.closest("[data-custom-rule-edit]");
  if (editButton) {
    const rule = (classifierRulesDraft?.custom_rules || []).find((item) => item.id === editButton.dataset.customRuleEdit);
    if (rule) openRuleEditor("custom-edit", rule);
    return;
  }
  const row = event.target.closest("tr[data-custom-rule-id]");
  if (row && !event.target.closest("button")) {
    const rule = (classifierRulesDraft?.custom_rules || []).find((item) => item.id === row.dataset.customRuleId);
    if (rule) openRuleEditor("custom-view", rule);
  }
  const deleteButton = event.target.closest("[data-custom-rule-delete]");
  if (deleteButton) {
    deleteCustomRuleById(deleteButton.dataset.customRuleDelete);
    return;
  }
});
document.getElementById("rules-body")?.addEventListener("click", (event) => {
  const viewButton = event.target.closest("[data-builtin-rule-view]");
  if (viewButton) {
    const rule = (classifierRulesDraft?.rules || []).find((item) => item.id === viewButton.dataset.builtinRuleView);
    if (rule) openRuleEditor("builtin-view", rule);
    return;
  }
  const row = event.target.closest("tr[data-rule-row]");
  if (row && !event.target.closest("button,input")) {
    const rule = (classifierRulesDraft?.rules || []).find((item) => item.id === row.dataset.ruleRow);
    if (rule) openRuleEditor("builtin-view", rule);
  }
});

// ---------------------------------------------------------------------------
// Bootstrap: apply demo mode + restore deep-link state from URL hash.
// ---------------------------------------------------------------------------
if (DEMO_MODE) {
  document.body.classList.add("demo-mode");
  const refreshToggle = document.getElementById("auto-refresh");
  if (refreshToggle) {
    refreshToggle.checked = false;
    refreshToggle.disabled = true;
  }
}

function restoreFromHash() {
  const hash = readHash();
  suppressHashWrite = true;
  try {
    if (hash.query) document.getElementById("filter-query").value = hash.query;
    if (hash.severity) document.getElementById("filter-severity").value = hash.severity;
    if (hash.pid) document.getElementById("filter-pid").value = hash.pid;
    if (hash.type) document.getElementById("filter-type").value = hash.type;
    if (hash.tab) switchTab(hash.tab);
  } finally {
    suppressHashWrite = false;
  }
  return hash;
}

const initialHash = restoreFromHash();
const initialLog = initialHash.log || undefined;

window.onLocaleChange = rerenderDashboard;
NoirlycanI18n.applyI18n();
NoirlycanI18n.updateLangToggle();
document.querySelectorAll(".lang-toggle [data-locale]").forEach((button) => {
  button.addEventListener("click", () => NoirlycanI18n.setLocale(button.dataset.locale));
});

window.addEventListener("popstate", () => {
  restoreFromHash();
  applyFilters();
});

loadDashboard(initialLog, { force: true })
  .then(() => {
    // Defensive: if the URL hash named a log that no longer exists, clear it
    // so the next applyFilters/refresh doesn't re-request the stale name.
    if (initialLog && state.overview) {
      const known = (state.overview.files || []).some(
        (file) => file.name === initialLog,
      );
      if (!known) {
        writeHash({ log: state.activeLog || "" });
      }
    }
    // If the hash names a finding and it exists in the loaded session, open it.
    if (initialHash.finding !== undefined && state.session) {
      const idx = Number(initialHash.finding);
      const finding = (state.session.findings || [])[idx];
      if (finding) {
        finding._index = idx;
        openFindingModal(finding);
      }
    }
    maybeAutoStartCollector();
  })
  .catch((error) => {
    console.error(error);
    showLoadError(t("error.loadDashboard"));
  });
connectLiveSocket();
setupAutoRefresh();
updateAutoRefreshLabel();
