const charts = {};

const palette = {
  critical: "#ff6b8a",
  high: "#ffb347",
  medium: "#4f8cff",
  low: "#3de0c5",
  allocate: "#4f8cff",
  write: "#9f7aea",
  execute: "#3de0c5",
};

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

function destroyChart(id) {
  if (charts[id]) {
    charts[id].destroy();
    delete charts[id];
  }
}

function renderMetrics(totals) {
  const cards = [
    { key: "events", label: "Total events", className: "" },
    { key: "findings", label: "Findings", className: "findings" },
    { key: "primitives", label: "Primitives", className: "primitives" },
    { key: "sysmon", label: "Sysmon events", className: "sysmon" },
    { key: "frida_raw", label: "Frida events", className: "" },
  ];
  document.getElementById("metric-cards").innerHTML = cards
    .map(
      (card) => `
      <article class="metric-card ${card.className}">
        <div class="label">${card.label}</div>
        <div class="value">${totals[card.key] ?? 0}</div>
      </article>`
    )
    .join("");
}

function renderSeverityChart(severity) {
  destroyChart("severity");
  const labels = Object.keys(severity);
  const values = labels.map((key) => severity[key]);
  const ctx = document.getElementById("severity-chart");
  charts.severity = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [
        {
          data: values,
          backgroundColor: labels.map((label) => palette[label] || "#60738f"),
          borderWidth: 0,
        },
      ],
    },
    options: {
      plugins: { legend: { position: "bottom", labels: { color: "#d7e5fb" } } },
    },
  });
}

function renderPrimitiveChart(kinds) {
  destroyChart("primitive");
  const labels = Object.keys(kinds);
  const values = labels.map((key) => kinds[key]);
  const ctx = document.getElementById("primitive-chart");
  charts.primitive = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          data: values,
          backgroundColor: labels.map((label) => palette[label] || "#4f8cff"),
          borderRadius: 10,
        },
      ],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#9db3d1" }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: "#9db3d1" }, grid: { color: "rgba(255,255,255,0.05)" } },
      },
    },
  });
}

function renderTimelineChart(timeline) {
  destroyChart("timeline");
  const labels = timeline.map(([bucket]) => bucket);
  const values = timeline.map(([, count]) => count);
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
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#9db3d1", maxRotation: 0 }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: "#9db3d1" }, grid: { color: "rgba(255,255,255,0.05)" } },
      },
    },
  });
}

function renderRankList(elementId, rows) {
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

function renderFindings(rows) {
  const body = document.getElementById("findings-body");
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">No findings in this session yet.</td></tr>';
    return;
  }
  body.innerHTML = rows
    .map((row) => {
      const severity = String(row.severity || "unknown").toLowerCase();
      return `
      <tr>
        <td>${formatTime(row.timestamp)}</td>
        <td><span class="severity ${severity}">${severity}</span></td>
        <td>${row.score ?? "-"}</td>
        <td>${row.target_pid ?? "-"}</td>
        <td class="mono">${(row.apis || []).join(", ")}</td>
        <td>${row.description || row.title || "-"}</td>
      </tr>`;
    })
    .join("");
}

function renderFiles(rows) {
  const body = document.getElementById("files-body");
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">No JSONL files in logs/ yet. Run spawn or run with default logging.</td></tr>';
    return;
  }
  body.innerHTML = rows
    .map(
      (row) => `
      <tr>
        <td class="mono">${row.name}</td>
        <td>${formatTime(row.modified_at)}</td>
        <td>${row.event_count}</td>
        <td>${row.finding_count}</td>
        <td>${row.critical_count}</td>
        <td>${formatBytes(row.size_bytes)}</td>
      </tr>`
    )
    .join("");
}

function populateLogSelect(files, activeLog) {
  const select = document.getElementById("log-select");
  select.innerHTML = files
    .map(
      (file) => `
      <option value="${file.name}" ${file.name === activeLog ? "selected" : ""}>
        ${file.name}
      </option>`
    )
    .join("");
  if (!files.length) {
    select.innerHTML = '<option value="">No logs found</option>';
  }
}

async function loadOverview(selectedLog) {
  const query = selectedLog ? `?log=${encodeURIComponent(selectedLog)}` : "";
  const response = await fetch(`/api/overview${query}`);
  const payload = await response.json();

  document.getElementById("logs-dir").textContent = payload.logs_dir;
  document.getElementById("active-log-label").textContent = payload.active_log || "no log selected";
  document.getElementById("file-count").textContent = `${payload.files.length} files`;

  populateLogSelect(payload.files, payload.active_log);
  renderMetrics(payload.stats.totals);
  renderSeverityChart(payload.stats.severity);
  renderPrimitiveChart(payload.stats.primitive_kinds);
  renderTimelineChart(payload.stats.timeline);
  renderRankList("api-list", payload.stats.top_apis);
  renderRankList("actor-list", payload.stats.top_actors);
  renderFindings(payload.stats.recent_findings);
  renderFiles(payload.files);
}

document.getElementById("refresh-btn").addEventListener("click", () => {
  const selected = document.getElementById("log-select").value;
  loadOverview(selected || undefined);
});

document.getElementById("log-select").addEventListener("change", (event) => {
  loadOverview(event.target.value || undefined);
});

loadOverview().catch((error) => {
  console.error(error);
});

setInterval(() => {
  const selected = document.getElementById("log-select").value;
  loadOverview(selected || undefined);
}, 5000);
