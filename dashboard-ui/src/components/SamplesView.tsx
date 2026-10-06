import { useCallback, useEffect, useState } from "react";
import { api, type Sample, type SampleReport } from "../api/client";

const COLUMNS = "1.6fr 0.8fr 0.9fr 1fr 1.1fr 220px";
const ACTIVE = new Set(["queued", "spawned", "running"]);

function statusColor(status: string): string {
  if (status === "failed") return "var(--sev-critical)";
  if (ACTIVE.has(status)) return "var(--sev-high)";
  if (status === "parsed" || status === "spawned") return "var(--sev-low)";
  return "var(--muted)";
}

export function SamplesView({
  agents,
  canRun,
  canDelete,
  onToast,
}: {
  agents: { id: string; label: string }[];
  canRun: boolean;
  canDelete: boolean;
  onToast: (message: string) => void;
}) {
  const [samples, setSamples] = useState<Sample[]>([]);
  const [agentId, setAgentId] = useState("");
  const [targetPid, setTargetPid] = useState("");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<{ sample: Sample; data: SampleReport } | null>(null);

  const reload = useCallback(() => api.samples().then((result) => setSamples(result.samples)), []);

  useEffect(() => {
    reload();
    const timer = window.setInterval(reload, 5000);
    return () => window.clearInterval(timer);
  }, [reload]);

  useEffect(() => {
    if (!agentId && agents.length) setAgentId(agents[0].id);
  }, [agents, agentId]);

  async function upload(file: File | undefined) {
    if (!file) return;
    setBusy(true);
    try {
      const result = await api.uploadSample(file);
      onToast(result.kind === "jsonl" ? "Session log imported" : "Sample uploaded — pick an agent and Run");
      await reload();
    } catch (error) {
      onToast(`Upload failed: ${(error as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  async function run(sample: Sample) {
    if (!agentId) {
      onToast("Register an agent first");
      return;
    }
    try {
      await api.runSample(sample.id, agentId, Number(targetPid) || undefined);
      onToast(`Sent ${sample.original_name} to ${agentId}`);
      await reload();
    } catch (error) {
      onToast(`Run failed: ${(error as Error).message}`);
    }
  }

  async function showReport(sample: Sample) {
    const result = await api.sampleReport(sample.id);
    if (result.pending || !result.report) {
      onToast("No telemetry for this sample yet");
      return;
    }
    setReport({ sample, data: result.report });
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div className="card">
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, marginBottom: 6 }}>Upload</div>
        <div style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 14 }}>
          .exe / .dll samples run on the chosen lab agent under Frida hooks (SHA-256 verified on the VM).
          .jsonl session logs are imported for offline analysis.
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
          <input
            type="file"
            accept=".exe,.dll,.jsonl"
            disabled={!canRun || busy}
            onChange={(event) => upload(event.target.files?.[0])}
          />
          <label style={{ fontSize: 12, color: "var(--muted)" }}>Agent</label>
          <select value={agentId} onChange={(event) => setAgentId(event.target.value)}>
            {agents.map((agent) => (
              <option key={agent.id} value={agent.id}>
                {agent.label}
              </option>
            ))}
          </select>
          <label style={{ fontSize: 12, color: "var(--muted)" }}>Target PID (optional)</label>
          <input
            className="field-input mono"
            style={{ width: 110, margin: 0 }}
            value={targetPid}
            onChange={(event) => setTargetPid(event.target.value.replace(/\D/g, ""))}
          />
        </div>
      </div>

      <div className="card">
        <div className="table-row" style={{ gridTemplateColumns: COLUMNS, fontSize: 11, color: "var(--dim)" }}>
          <span>SAMPLE</span>
          <span>KIND</span>
          <span>STATUS</span>
          <span>AGENT</span>
          <span>UPLOADED</span>
          <span>ACTIONS</span>
        </div>
        {samples.map((sample) => (
          <div key={sample.id} className="table-row" style={{ gridTemplateColumns: COLUMNS }}>
            <span>
              <div>{sample.original_name}</div>
              <div className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>
                {sample.sha256.slice(0, 16)}… · {(sample.size_bytes / 1024).toFixed(1)} KiB
              </div>
            </span>
            <span className="mono">{sample.content_kind}</span>
            <span className="mono" style={{ color: statusColor(sample.status) }} title={sample.error_message || ""}>
              {sample.status}
            </span>
            <span className="mono">{sample.agent_id || "-"}</span>
            <span className="mono">{sample.uploaded_at.slice(0, 19).replace("T", " ")}</span>
            <span style={{ display: "flex", gap: 6 }}>
              {sample.content_kind === "executable" && canRun ? (
                <button
                  type="button"
                  className="btn-ghost"
                  disabled={ACTIVE.has(sample.status)}
                  onClick={() => run(sample)}
                >
                  Run
                </button>
              ) : null}
              <button type="button" className="btn-ghost" onClick={() => showReport(sample)}>
                Report
              </button>
              {canDelete ? (
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={() => api.deleteSample(sample.id).then(reload)}
                >
                  Delete
                </button>
              ) : null}
            </span>
          </div>
        ))}
        {!samples.length ? <div style={{ color: "var(--dim)", paddingTop: 12 }}>No samples yet.</div> : null}
      </div>

      {report ? (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
            <span style={{ fontFamily: "Space Grotesk", fontWeight: 600 }}>Report · {report.sample.original_name}</span>
            <button type="button" className="btn-ghost" onClick={() => setReport(null)}>
              Close
            </button>
          </div>
          <div className="mono" style={{ fontSize: 12, color: "var(--muted)", marginBottom: 10 }}>
            {report.data.event_count} events · {report.data.primitive_count} primitives · {report.data.finding_count} findings
          </div>
          {report.data.findings.map((finding, index) => (
            <div key={index} className="table-row" style={{ gridTemplateColumns: "90px 1fr 1fr" }}>
              <span className="mono">{String(finding.severity || "").toUpperCase()}</span>
              <span>{String(finding.technique || finding.title || "")}</span>
              <span className="mono" style={{ fontSize: 11 }}>
                {String(finding.actor_image || finding.actor_pid || "")} → {String(finding.target_image || finding.target_pid || "")}
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
