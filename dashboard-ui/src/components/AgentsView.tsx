import { useState } from "react";
import { api } from "../api/client";
import { agentLabel } from "./AgentBadge";

type AgentRow = Record<string, unknown>;

type Props = {
  data: {
    server: { host: string; port: number; token: string };
    agents: AgentRow[];
    commands: { run: string; spawn: string };
    toml: string;
    auto_kill_min_severity?: string;
  };
  onReload: () => void;
  onToast: (message: string) => void;
};

function agentName(agent: AgentRow) {
  return agentLabel(agent, String(agent.id || ""));
}

export function AgentsView({ data, onReload, onToast }: Props) {
  const [host, setHost] = useState(data.server.host);
  const [port, setPort] = useState(String(data.server.port));
  const [autoKillSev, setAutoKillSev] = useState(data.auto_kill_min_severity || "CRITICAL");
  const [copied, setCopied] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draftName, setDraftName] = useState("");
  const [newAgentId, setNewAgentId] = useState("");
  const [newDisplayName, setNewDisplayName] = useState("");

  async function copy(text: string, label: string) {
    await navigator.clipboard.writeText(text);
    setCopied(label);
    onToast(`Copied ${label}`);
    window.setTimeout(() => setCopied(""), 1500);
  }

  function startRename(agent: AgentRow) {
    const id = String(agent.id || "");
    setEditingId(id);
    setDraftName(agentName(agent));
  }

  async function saveRename(agentId: string) {
    const next = draftName.trim();
    if (!next) {
      onToast("Agent name cannot be empty");
      return;
    }
    await api.renameAgent(agentId, next);
    setEditingId(null);
    setDraftName("");
    onToast("Agent renamed");
    onReload();
  }

  async function removeAgent(agent: AgentRow) {
    const id = String(agent.id || "");
    const label = agentName(agent);
    if (!window.confirm(`Remove agent "${label}" from the console? Session logs are kept on disk.`)) {
      return;
    }
    await api.deleteAgent(id);
    onToast("Agent removed");
    onReload();
  }

  async function registerAgent() {
    const id = newAgentId.trim();
    if (!id) {
      onToast("Agent id is required");
      return;
    }
    await api.registerAgent(id, newDisplayName.trim());
    setNewAgentId("");
    setNewDisplayName("");
    onToast("Agent registered");
    onReload();
  }

  return (
    <div style={{ maxWidth: 1100, display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span
          className="mono"
          style={{
            fontSize: 11,
            color: "var(--accentText)",
            background: "var(--navActive)",
            border: "1px solid var(--navBorder)",
            padding: "4px 11px",
            borderRadius: 8,
          }}
        >
          ADMIN ONLY
        </span>
        <span style={{ fontSize: 13, color: "var(--muted)" }}>
          Register each workstation with its own agent id and enrollment token.
        </span>
      </div>

      <div className="card">
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16, marginBottom: 4 }}>Console endpoint</div>
        <div style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 18 }}>
          Agents connect back to this host and port. Each agent uses its own id + token from the table below.
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 140px", gap: 16, marginBottom: 16 }}>
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Host / IP</label>
            <input className="field-input mono" style={{ marginTop: 6 }} value={host} onChange={(e) => setHost(e.target.value)} />
          </div>
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Port</label>
            <input className="field-input mono" style={{ marginTop: 6 }} value={port} onChange={(e) => setPort(e.target.value)} />
          </div>
        </div>
        <button type="button" className="btn-brand" onClick={() => api.saveServer(host, Number(port)).then(onReload)}>
          Save server
        </button>
      </div>

      <div className="card">
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16, marginBottom: 4 }}>VM install (agent only)</div>
        <div style={{ fontSize: 12.5, color: "var(--dim)", lineHeight: 1.6 }}>
          Windows VM chỉ cần Python +{" "}
          <span className="mono">pip install -e &quot;.[agent]&quot;</span> — không cài backend, dashboard, npm.
          Copy <strong>config</strong> từ bảng dưới → lưu <span className="mono">noirlycan-agent.toml</span> → chạy{" "}
          <span className="mono">noirlycan-agent run --config noirlycan-agent.toml --watch-sysmon</span>.
        </div>
      </div>

      <div className="card">
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16, marginBottom: 4 }}>Register workstation</div>
        <div style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 14 }}>
          Create one enrollment row per VM. Copy that row&apos;s run command on the target machine.
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 12, alignItems: "end" }}>
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Agent id</label>
            <input
              className="field-input mono"
              style={{ marginTop: 6 }}
              placeholder="win10-lab-vm"
              value={newAgentId}
              onChange={(e) => setNewAgentId(e.target.value)}
            />
          </div>
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Display name (optional)</label>
            <input
              className="field-input"
              style={{ marginTop: 6 }}
              placeholder="Windows 10 lab VM"
              value={newDisplayName}
              onChange={(e) => setNewDisplayName(e.target.value)}
            />
          </div>
          <button type="button" className="btn-brand" onClick={() => registerAgent()}>
            Register
          </button>
        </div>
      </div>

      <div className="card">
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
          <span style={{ fontWeight: 600 }}>Auto-kill when severity ≥</span>
          <select
            value={autoKillSev}
            onChange={async (e) => {
              setAutoKillSev(e.target.value);
              await api.saveAutoKillPolicy(e.target.value);
              onReload();
            }}
          >
            {["CRITICAL", "HIGH", "MEDIUM"].map((sev) => (
              <option key={sev} value={sev}>
                {sev}
              </option>
            ))}
          </select>
        </div>
        <div
          className="table-row"
          style={{
            gridTemplateColumns: "1.3fr 1.1fr 0.7fr 0.7fr 0.9fr 64px 64px 56px 150px",
            fontSize: 11,
            color: "var(--dim)",
          }}
        >
          <span>AGENT</span>
          <span>TOKEN</span>
          <span>STATUS</span>
          <span>MODE</span>
          <span>WATCHING</span>
          <span>LAST</span>
          <span>KILL</span>
          <span>IP</span>
          <span>ACTIONS</span>
        </div>
        {data.agents.map((agent) => {
          const id = String(agent.id || "");
          const isEditing = editingId === id;
          const runCommand = String(agent.run_command || "");
          const enrollmentToken = String(agent.enrollment_token || "");
          return (
            <div
              key={id}
              className="table-row"
              style={{
                gridTemplateColumns: "1.3fr 1.1fr 0.7fr 0.7fr 0.9fr 64px 64px 56px 150px",
                alignItems: "center",
              }}
            >
              <span>
                {isEditing ? (
                  <input
                    className="field-input"
                    style={{ width: "100%", fontSize: 12 }}
                    value={draftName}
                    onChange={(e) => setDraftName(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void saveRename(id);
                      if (e.key === "Escape") setEditingId(null);
                    }}
                    autoFocus
                  />
                ) : (
                  <span title={id}>
                    <div style={{ fontWeight: 600 }}>{agentName(agent)}</div>
                    <div className="mono" style={{ fontSize: 10, color: "var(--dim)", marginTop: 2 }}>
                      {id}
                    </div>
                  </span>
                )}
              </span>
              <span>
                <div
                  className="mono"
                  style={{
                    fontSize: 10,
                    color: "var(--accentText)",
                    wordBreak: "break-all",
                    lineHeight: 1.4,
                  }}
                >
                  {enrollmentToken || "—"}
                </div>
                {enrollmentToken ? (
                  <button
                    type="button"
                    className="btn-ghost"
                    style={{ padding: "2px 0", fontSize: 10, marginTop: 4 }}
                    onClick={() => copy(enrollmentToken, `token ${id}`)}
                  >
                    Copy token {copied === `token ${id}` ? "✓" : ""}
                  </button>
                ) : null}
              </span>
              <span style={{ color: agent.status === "online" ? "var(--op-alloc)" : "#ec7b1a", textTransform: "capitalize" }}>
                {String(agent.status || "offline")}
              </span>
              <span className="mono">{String(agent.mode || "-")}</span>
              <span className="mono">{String(agent.watching || "-")}</span>
              <span className="mono">{String(agent.last_seen || "-").slice(11, 19)}</span>
              <label style={{ display: "flex", justifyContent: "center" }}>
                <input
                  type="checkbox"
                  checked={Boolean(agent.auto_kill)}
                  onChange={(e) => api.setAgentAutoKill(id, e.target.checked).then(onReload)}
                />
              </label>
              <span className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>
                {String(agent.ip_address || "—")}
              </span>
              <span style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: "flex-end" }}>
                {runCommand ? (
                  <button
                    type="button"
                    className="btn-ghost"
                    style={{ padding: "4px 8px", fontSize: 10 }}
                    onClick={() => copy(runCommand, `run ${id}`)}
                  >
                    Copy run {copied === `run ${id}` ? "✓" : ""}
                  </button>
                ) : null}
                {agent.config_toml ? (
                  <button
                    type="button"
                    className="btn-ghost"
                    style={{ padding: "4px 8px", fontSize: 10 }}
                    onClick={() => copy(String(agent.config_toml), `config ${id}`)}
                  >
                    Copy config {copied === `config ${id}` ? "✓" : ""}
                  </button>
                ) : null}
                {isEditing ? (
                  <span style={{ display: "flex", gap: 4 }}>
                    <button type="button" className="btn-ghost" style={{ padding: "4px 8px", fontSize: 10 }} onClick={() => saveRename(id)}>
                      Save
                    </button>
                    <button type="button" className="btn-ghost" style={{ padding: "4px 8px", fontSize: 10 }} onClick={() => setEditingId(null)}>
                      Cancel
                    </button>
                  </span>
                ) : (
                  <span style={{ display: "flex", gap: 4, flexWrap: "wrap", justifyContent: "flex-end" }}>
                    <button type="button" className="btn-ghost" style={{ padding: "4px 8px", fontSize: 10 }} onClick={() => startRename(agent)}>
                      Rename
                    </button>
                    <button
                      type="button"
                      className="btn-ghost"
                      style={{ padding: "4px 8px", fontSize: 10 }}
                      onClick={() => api.regenerateAgentToken(id).then(onReload)}
                    >
                      New token
                    </button>
                    <button
                      type="button"
                      className="btn-ghost"
                      style={{ padding: "4px 8px", fontSize: 10, color: "#e5484d" }}
                      onClick={() => removeAgent(agent)}
                    >
                      Delete
                    </button>
                  </span>
                )}
              </span>
            </div>
          );
        })}
        {!data.agents.length ? (
          <div style={{ color: "var(--dim)", paddingTop: 12 }}>
            No agents registered yet. Create one above, then run its command on the VM.
          </div>
        ) : null}
      </div>
    </div>
  );
}
