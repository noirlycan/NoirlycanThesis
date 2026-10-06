import { useState } from "react";
import { api, apiUrl } from "../api/client";
import { agentLabel } from "./AgentBadge";

type AgentRow = Record<string, unknown>;

type Props = {
  data: {
    server: { host: string; port: number; token: string };
    agents: AgentRow[];
    auto_kill_min_severity?: string;
    desktop_available?: boolean;
    installer_available?: boolean;
    can_publish_release?: boolean;
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
  const [uploadingRelease, setUploadingRelease] = useState<"portable" | "installer" | null>(null);

  async function uploadRelease(file: File, kind: "portable" | "installer") {
    if (!window.confirm(`Publish ${file.name} as the ${kind} release for clients to download? This will replace the current release.`)) return;
    setUploadingRelease(kind);
    try {
      const result = await api.uploadAgentRelease(file, kind);
      onToast(`Published ${result.filename} (${(result.size_bytes / 1024 / 1024).toFixed(1)} MB)`);
      onReload();
    } catch (error: unknown) {
      onToast(error instanceof Error ? error.message : "Upload failed");
    } finally {
      setUploadingRelease(null);
    }
  }

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
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16, marginBottom: 4 }}>Desktop Agent (Windows)</div>
        <div style={{ fontSize: 12.5, color: "var(--dim)", lineHeight: 1.6, marginBottom: 14 }}>
          Download <span className="mono">NoirlycanAgentSetup.exe</span>, accept the UAC prompt, and complete installation.
          Open Noirlycan Agent from the Start Menu, enter the server address and your workstation&apos;s token
          from the table below, then click Connect and start. The portable version runs directly without installation.
          Python is not required on the Agent machine. Install Sysmon separately to collect Sysmon events.
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10 }}>
        <button type="button" className="btn-brand" disabled={!data.installer_available}
          onClick={() => api.downloadAgentInstaller().catch((error: unknown) => onToast(error instanceof Error ? error.message : "Download failed"))}>
          Download Windows installer
        </button>
        <button type="button" className="btn-ghost" disabled={!data.desktop_available}
          onClick={() => api.downloadDesktopAgent().catch((error: unknown) => onToast(error instanceof Error ? error.message : "Download failed"))}>
          Download portable .exe
        </button>
        <button type="button" className="btn-ghost"
          onClick={() => copy(new URL(apiUrl("/api"), window.location.href).origin, "server")}>
          Copy server
        </button>
        </div>
        {!data.desktop_available && !data.installer_available ? (
          <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 12 }}>No Agent release is available on this server yet.</div>
        ) : null}
        {data.can_publish_release ? (
          <div style={{ marginTop: 16, display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10 }}>
            {(["installer", "portable"] as const).map((kind) => (
              <label key={kind} className="btn-ghost" style={{ cursor: uploadingRelease ? "wait" : "pointer" }}>
                {kind === "installer" ? "Publish installer" : "Publish portable release"}
                <input type="file" accept=".exe" disabled={uploadingRelease !== null} style={{ display: "none" }}
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    event.target.value = "";
                    if (file) void uploadRelease(file, kind);
                  }} />
              </label>
            ))}
            <span style={{ fontSize: 12, color: "var(--muted)" }}>
              {uploadingRelease ? "Uploading release to server…" : "Admins can publish verified .exe builds for clients to download here."}
            </span>
          </div>
        ) : null}
      </div>

      <div className="card">
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16, marginBottom: 4 }}>VM install (agent only)</div>
        <div style={{ fontSize: 12.5, color: "var(--dim)", lineHeight: 1.6 }}>
          For the source-based install, the VM needs Python 3.10+. Click <strong>Copy install</strong> in the Agent row
          and paste it into an Administrator PowerShell window on the VM. The command downloads the Agent package,
          creates a virtual environment, installs Frida/pywin32 and Sysmon with the lab configuration, writes{" "}
          <span className="mono">C:\Noirlycan\noirlycan-agent.toml</span>, and starts the Agent. For subsequent runs, use{" "}
          <span className="mono">C:\Noirlycan\run-agent.ps1</span>.
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
            gridTemplateColumns: "1.2fr 0.9fr 0.6fr 0.5fr 0.9fr 70px 44px 90px 1.6fr",
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
                gridTemplateColumns: "1.2fr 0.9fr 0.6fr 0.5fr 0.9fr 70px 44px 90px 1.6fr",
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
                {enrollmentToken ? (
                  <button
                    type="button"
                    className="chip chip-accent"
                    style={{ border: "none", cursor: "pointer" }}
                    title="Copy enrollment token"
                    onClick={() => copy(enrollmentToken, `token ${id}`)}
                  >
                    {enrollmentToken.slice(0, 4)}…{enrollmentToken.slice(-3)} {copied === `token ${id}` ? "✓" : "⧉"}
                  </button>
                ) : (
                  "—"
                )}
              </span>
              <span className={`chip ${agent.status === "online" ? "chip-LOW" : ""}`} style={{ justifySelf: "start", textTransform: "capitalize" }}>
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
              <span style={{ display: "flex", flexWrap: "wrap", gap: 4, justifyContent: "flex-end" }}>
                {agent.install_command ? (
                  <button
                    type="button"
                    className="btn-brand"
                    style={{ padding: "4px 8px", fontSize: 10 }}
                    title="Install the Agent package, Python dependencies and Sysmon, write configuration, and start the Agent"
                    onClick={() => copy(String(agent.install_command), `install ${id}`)}
                  >
                    Copy install {copied === `install ${id}` ? "✓" : ""}
                  </button>
                ) : null}
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
                  <>
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
                      style={{ padding: "4px 8px", fontSize: 10, color: "var(--sev-critical)" }}
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
        {!data.agents.length ? (
          <div style={{ color: "var(--dim)", paddingTop: 12 }}>
            No agents registered yet. Create one above, then run its command on the VM.
          </div>
        ) : null}
      </div>
    </div>
  );
}
