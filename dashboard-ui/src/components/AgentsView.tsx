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

  return (
    <div style={{ maxWidth: 1000, display: "flex", flexDirection: "column", gap: 16 }}>
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
          Web console configures here; agents run on VM/sandbox and connect back.
        </span>
      </div>

      <div className="card">
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16, marginBottom: 4 }}>This console</div>
        <div style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 18 }}>
          Agent connection endpoint and enrollment token.
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
        <label style={{ fontSize: 12, color: "var(--muted)" }}>Enrollment token</label>
        <div style={{ display: "flex", gap: 10, marginTop: 6 }}>
          <div
            className="mono"
            style={{
              flex: 1,
              background: "var(--panel2)",
              border: "1px solid var(--border)",
              borderRadius: 10,
              padding: "10px 12px",
              color: "var(--accentText)",
              wordBreak: "break-all",
            }}
          >
            {data.server.token}
          </div>
          <button type="button" className="btn-ghost" onClick={() => api.regenerateToken().then(onReload)}>
            Regenerate
          </button>
        </div>
        <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
          <button
            type="button"
            className="btn-brand"
            onClick={() => api.saveServer(host, Number(port)).then(onReload)}
          >
            Save server
          </button>
        </div>
      </div>

      <div className="card">
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16, marginBottom: 4 }}>Deploy an agent</div>
        <div style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 14 }}>Run mode keeps watching; spawn mode launches a sample under Frida.</div>
        <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
          <button type="button" className="btn-ghost" onClick={() => copy(data.commands.run, "run command")}>
            Copy run {copied === "run command" ? "✓" : ""}
          </button>
          <button type="button" className="btn-ghost" onClick={() => copy(data.commands.spawn, "spawn command")}>
            Copy spawn {copied === "spawn command" ? "✓" : ""}
          </button>
          <button
            type="button"
            className="btn-ghost"
            onClick={() => {
              const blob = new Blob([data.toml], { type: "text/plain" });
              const url = URL.createObjectURL(blob);
              const anchor = document.createElement("a");
              anchor.href = url;
              anchor.download = "noirlycan-agent.toml";
              anchor.click();
              URL.revokeObjectURL(url);
            }}
          >
            Export config (.toml)
          </button>
        </div>
        <pre className="mono" style={{ fontSize: 12, whiteSpace: "pre-wrap", margin: 0, color: "var(--dim)" }}>
          Run mode
        </pre>
        <pre className="mono" style={{ fontSize: 12, whiteSpace: "pre-wrap", margin: "4px 0 12px" }}>
          {data.commands.run}
        </pre>
        <pre className="mono" style={{ fontSize: 12, whiteSpace: "pre-wrap", margin: 0, color: "var(--dim)" }}>
          Spawn mode
        </pre>
        <pre className="mono" style={{ fontSize: 12, whiteSpace: "pre-wrap", marginTop: 4 }}>
          {data.commands.spawn}
        </pre>
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
            gridTemplateColumns: "1.5fr 1fr 0.8fr 1fr 80px 80px 70px 120px",
            fontSize: 11,
            color: "var(--dim)",
          }}
        >
          <span>AGENT</span>
          <span>IP</span>
          <span>OS</span>
          <span>MODE</span>
          <span>WATCHING</span>
          <span>LAST</span>
          <span>STATUS</span>
          <span>KILL</span>
          <span>ACTIONS</span>
        </div>
        {data.agents.map((agent) => {
          const id = String(agent.id || "");
          const isEditing = editingId === id;
          return (
            <div
              key={id}
              className="table-row"
              style={{
                gridTemplateColumns: "1.5fr 1fr 0.8fr 1fr 80px 80px 70px 120px",
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
                  <span title={id} style={{ fontWeight: 600 }}>
                    {agentName(agent)}
                  </span>
                )}
              </span>
              <span className="mono" style={{ fontSize: 11, color: "var(--dim)" }}>
                {String(agent.ip_address || "-")}
              </span>
              <span>{String(agent.os_name || "-")}</span>
              <span className="mono">{String(agent.mode || "-")}</span>
              <span className="mono">{String(agent.watching || "-")}</span>
              <span className="mono">{String(agent.last_seen || "-").slice(11, 19)}</span>
              <span style={{ color: agent.status === "online" ? "var(--op-alloc)" : "#ec7b1a" }}>
                {String(agent.status || "offline")}
              </span>
              <label style={{ display: "flex", justifyContent: "center" }}>
                <input
                  type="checkbox"
                  checked={Boolean(agent.auto_kill)}
                  onChange={(e) => api.setAgentAutoKill(id, e.target.checked).then(onReload)}
                />
              </label>
              <span style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                {isEditing ? (
                  <>
                    <button type="button" className="btn-ghost" style={{ padding: "4px 8px", fontSize: 11 }} onClick={() => saveRename(id)}>
                      Save
                    </button>
                    <button
                      type="button"
                      className="btn-ghost"
                      style={{ padding: "4px 8px", fontSize: 11 }}
                      onClick={() => setEditingId(null)}
                    >
                      Cancel
                    </button>
                  </>
                ) : (
                  <>
                    <button type="button" className="btn-ghost" style={{ padding: "4px 8px", fontSize: 11 }} onClick={() => startRename(agent)}>
                      Rename
                    </button>
                    <button
                      type="button"
                      className="btn-ghost"
                      style={{ padding: "4px 8px", fontSize: 11, color: "#e5484d" }}
                      onClick={() => removeAgent(agent)}
                    >
                      Delete
                    </button>
                  </>
                )}
              </span>
            </div>
          );
        })}
        {!data.agents.length ? <div style={{ color: "var(--dim)", paddingTop: 12 }}>No agents connected yet.</div> : null}
      </div>
    </div>
  );
}
