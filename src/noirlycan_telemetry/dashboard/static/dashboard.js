const charts = {};
const fingerprints = {};
const REFRESH_MS = 1000;

const state = {
  activeLog: "",
  activeTab: "overview",
  overview: null,
  session: null,
  runtime: null,
  runtimeSaving: false,
  filters: {
    query: "",
    severity: "",
    pid: "",
    type: "",
  },
};

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

function ensureMetricCards() {
  const root = document.getElementById("metric-cards");
  if (root.childElementCount) {
    return;
  }
  const cards = [
    { key: "events", label: "Total events", className: "" },
    { key: "findings", label: "Findings (deduped)", className: "findings" },
    { key: "network", label: "Network events", className: "sysmon" },
    { key: "primitives", label: "Primitives", className: "primitives" },
    { key: "sysmon", label: "Sysmon events", className: "sysmon" },
    { key: "frida_raw", label: "Frida events", className: "" },
    { key: "triage", label: "File triage", className: "findings" },
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
    return;
  }
  const values = labels.map((key) => severity[key]);
  const colors = labels.map((label) => palette[label] || "#60738f");

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
      plugins: { legend: { position: "bottom", labels: { color: "#d7e5fb" } } },
    },
  });
}

function renderPrimitiveChart(kinds) {
  if (!shouldRender("primitive", kinds)) {
    return;
  }
  const labels = Object.keys(kinds);
  if (!labels.length) {
    return;
  }
  const values = labels.map((key) => kinds[key]);
  const colors = labels.map((label) => palette[label] || "#4f8cff");

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
        x: { ticks: { color: "#9db3d1" }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: "#9db3d1" }, grid: { color: "rgba(255,255,255,0.05)" } },
      },
    },
  });
}

function renderTimelineChart(timeline) {
  if (!shouldRender("timeline", timeline)) {
    return;
  }
  if (!timeline.length) {
    return;
  }
  const labels = timeline.map(([bucket]) => bucket);
  const values = timeline.map(([, count]) => count);

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
        x: { ticks: { color: "#9db3d1", maxRotation: 0 }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: "#9db3d1" }, grid: { color: "rgba(255,255,255,0.05)" } },
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
    root.innerHTML = '<div class="empty">No data yet.</div>';
    return;
  }
  const max = Math.max(...rows.map(([, count]) => count));
  root.innerHTML = rows
    .map(
      ([name, count]) => `
      <div class="rank-item">
        <div class="name" title="${name}">${shortPath(name)}</div>
        <div>${count}</div>
        <div class="bar"><span style="width:${(count / max) * 100}%"></span></div>
      </div>`
    )
    .join("");
}

function renderNetworkSummary(networkRows) {
  const endpoints = (networkRows || [])
    .map((row) => row.endpoint)
    .filter(Boolean)
    .slice(0, 3);
  if (!endpoints.length) return "-";
  return endpoints.join(", ");
}

function renderFindings(rows) {
  if (!shouldRender("findings", rows)) {
    return;
  }
  const body = document.getElementById("findings-body");
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No findings in this session yet.</td></tr>';
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
        <td>${row.target_pid ?? "-"}</td>
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
    body.innerHTML =
      '<tr><td colspan="6" class="empty">No outbound network captured yet for watched PIDs.</td></tr>';
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

function renderTriages(rows) {
  if (!shouldRender("triages", rows)) {
    return;
  }
  const body = document.getElementById("triage-body");
  if (!rows.length) {
    body.innerHTML =
      '<tr><td colspan="8" class="empty">No file drops triaged yet. Start <code>run</code> (or <code>run --watch-sysmon</code>) then copy a NEW .exe to D:\\ or Downloads.</td></tr>';
    return;
  }
  body.innerHTML = rows
    .map((row) => {
      const reasons = (row.reasons || []).join(", ") || "-";
      const sha = row.sha256 ? `${row.sha256.slice(0, 12)}…` : "-";
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
    body.innerHTML = '<tr><td colspan="7" class="empty">No primitives captured yet.</td></tr>';
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
        <td>${row.target_pid ?? "-"}</td>
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
  document.getElementById("event-count-label").textContent = `${rows.length} events`;
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="3" class="empty">No events match the current filters.</td></tr>';
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
    body.innerHTML =
      '<tr><td colspan="6" class="empty">No JSONL files in logs/ yet. Run spawn or run with default logging.</td></tr>';
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
  document.getElementById("active-log-label").textContent = message;
  document.getElementById("file-count").textContent = "load failed";
}

function renderOverview(payload) {
  renderMetrics(payload.stats.totals);
  renderSeverityChart(payload.stats.severity);
  renderPrimitiveChart(payload.stats.primitive_kinds);
  renderTimelineChart(payload.stats.timeline);
  renderRankList("api-list", payload.stats.top_apis);
  renderRankList("actor-list", payload.stats.top_actors);
}

function renderSessionViews(session) {
  renderFindings(session.findings || []);
  renderNetwork(session.network || []);
  renderPrimitives(session.primitives || []);
  renderTriages(session.triages || []);
  renderEvents(session.events || []);
}

function openFindingModal(finding) {
  const modal = document.getElementById("finding-modal");
  document.getElementById("modal-title").textContent = finding.title || finding.description || "Injection finding";
  document.getElementById("modal-summary").innerHTML = `
    <div><dt>Severity</dt><dd>${finding.severity || "-"}</dd></div>
    <div><dt>Score</dt><dd>${finding.score ?? "-"}</dd></div>
    <div><dt>Actor PID</dt><dd>${finding.actor_pid ?? "-"}</dd></div>
    <div><dt>Target PID</dt><dd>${finding.target_pid ?? "-"}</dd></div>
    <div><dt>Target image</dt><dd class="mono">${finding.target_image || "-"}</dd></div>
    <div><dt>Time</dt><dd>${formatTime(finding.timestamp)}</dd></div>
  `;
  document.getElementById("modal-apis").innerHTML = (finding.apis || [])
    .map((api) => `<span class="tag">${api}</span>`)
    .join("");
  document.getElementById("modal-evidence").textContent = JSON.stringify(finding.evidence || {}, null, 2);

  const primitives = finding.primitives || [];
  document.getElementById("modal-primitives").innerHTML = primitives.length
    ? `<table>
        <thead><tr><th>Kind</th><th>API</th><th>Target PID</th><th>Address</th></tr></thead>
        <tbody>
          ${primitives
            .map(
              (row) => `
            <tr>
              <td>${row.kind || "-"}</td>
              <td class="mono">${row.api || "-"}</td>
              <td>${row.target_pid ?? "-"}</td>
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
}

async function loadOverview(selectedLog) {
  const query = selectedLog ? `?log=${encodeURIComponent(selectedLog)}` : "";
  const response = await fetch(`/api/overview${query}`);
  if (!response.ok) {
    showLoadError(`API error ${response.status}`);
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
  const hint = document.getElementById("runtime-hint");
  const status = document.getElementById("collector-status-chip");

  toggle.checked = Boolean(runtime.file_drop_watch_enabled);
  toggle.disabled = Boolean(runtime.file_drop_watch_locked) || state.runtimeSaving;

  if (runtime.collector_online) {
    status.textContent = "collector online";
    status.classList.add("online");
    status.classList.remove("offline");
  } else {
    status.textContent = "collector offline";
    status.classList.add("offline");
    status.classList.remove("online");
  }

  const paths = (runtime.watch_paths || []).join(", ");
  if (runtime.file_drop_watch_locked) {
    hint.textContent =
      "Locked off by CLI (--no-watch-files). Restart run without that flag to control from the dashboard.";
  } else if (!runtime.collector_online) {
    hint.textContent =
      "Start python -m noirlycan_telemetry run in a terminal, then toggle watch here. Changes apply within ~1s.";
  } else if (runtime.file_drop_watch_enabled) {
    hint.textContent = paths
      ? `Watching: ${paths}. Copy a new .exe to trigger auto-triage.`
      : "File drop watch is on. Copy a new .exe to a watched folder.";
  } else {
    hint.textContent = "File drop watch is paused. Enable the toggle to scan folders and auto-triage new files.";
  }
}

async function saveRuntimeConfig(enabled) {
  state.runtimeSaving = true;
  renderRuntimeControls(state.runtime || { file_drop_watch_enabled: enabled });
  try {
    const response = await fetch("/api/runtime", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file_drop_watch_enabled: enabled }),
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
    showLoadError("Could not update file-drop watch setting");
  } finally {
    state.runtimeSaving = false;
    if (state.runtime) {
      renderRuntimeControls(state.runtime);
    }
  }
}

function shouldPauseRefresh() {
  const modal = document.getElementById("finding-modal");
  return modal.open || document.hidden;
}

async function loadDashboard(selectedLog, { force = false } = {}) {
  if (!force && shouldPauseRefresh()) {
    return;
  }

  const filters = currentFilters();
  state.filters = filters;

  const overview = await loadOverview(selectedLog);
  if (!overview) return;

  state.overview = overview;
  state.activeLog = overview.active_log || selectedLog || "";

  document.getElementById("logs-dir").textContent = overview.logs_dir;
  document.getElementById("active-log-label").textContent = state.activeLog || "no log selected";
  document.getElementById("file-count").textContent = `${overview.files.length} files`;

  populateLogSelect(overview.files, state.activeLog);

  if (state.activeTab === "overview" || state.activeTab === "sessions" || force) {
    if (state.activeTab === "overview" || force) {
      renderOverview(overview);
    }
    if (state.activeTab === "sessions" || force) {
      renderFiles(overview.files, state.activeLog);
    }
  }

  if (state.activeTab === "files" || force) {
    const runtime = await loadRuntimeConfig();
    if (runtime) {
      renderRuntimeControls(runtime);
    }
  }

  if (state.activeLog) {
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
        renderTriages(session.triages || state.overview?.stats?.recent_triages || []);
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
  }
}

function switchTab(tabName) {
  state.activeTab = tabName;
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.tab === tabName);
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.panel === tabName);
  });

  if (state.overview) {
    if (tabName === "overview") {
      renderOverview(state.overview);
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
        state.session?.triages || state.overview?.stats?.recent_triages || []
      );
    }
  }
}

function applyFilters() {
  const selected = document.getElementById("log-select").value;
  Object.keys(fingerprints).forEach((key) => delete fingerprints[key]);
  loadDashboard(selected || undefined, { force: true });
}

function clearFilters() {
  document.getElementById("filter-query").value = "";
  document.getElementById("filter-severity").value = "";
  document.getElementById("filter-pid").value = "";
  document.getElementById("filter-type").value = "";
  applyFilters();
}

function setupDelegatedClicks() {
  document.getElementById("findings-body").addEventListener("click", (event) => {
    const row = event.target.closest("[data-finding-index]");
    if (!row || !state.session) return;
    const index = Number(row.dataset.findingIndex);
    openFindingModal((state.session.findings || [])[index]);
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

  document.getElementById("files-body").addEventListener("click", (event) => {
    const row = event.target.closest("[data-session-name]");
    if (!row) return;
    document.getElementById("log-select").value = row.dataset.sessionName;
    applyFilters();
    switchTab("overview");
  });
}

document.getElementById("refresh-btn").addEventListener("click", applyFilters);
document.getElementById("apply-filters-btn").addEventListener("click", applyFilters);
document.getElementById("clear-filters-btn").addEventListener("click", clearFilters);

document.getElementById("log-select").addEventListener("change", (event) => {
  Object.keys(fingerprints).forEach((key) => delete fingerprints[key]);
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

["filter-query", "filter-severity", "filter-pid", "filter-type"].forEach((id) => {
  document.getElementById(id).addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      applyFilters();
    }
  });
});

let refreshTimer = null;
function setupAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
  if (document.getElementById("auto-refresh").checked) {
    refreshTimer = setInterval(() => {
      const selected = document.getElementById("log-select").value;
      loadDashboard(selected || undefined);
    }, REFRESH_MS);
  }
}

document.getElementById("auto-refresh").addEventListener("change", setupAutoRefresh);

document.getElementById("file-drop-toggle").addEventListener("change", (event) => {
  saveRuntimeConfig(event.target.checked);
});

setupDelegatedClicks();
loadDashboard(undefined, { force: true }).catch((error) => {
  console.error(error);
  showLoadError("Could not load dashboard data");
});
setupAutoRefresh();
