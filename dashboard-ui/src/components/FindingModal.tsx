import type { FindingMember } from "../types";
import { api } from "../api/client";
import { AgentBadge } from "./AgentBadge";
import { ApiChainList, TagChips, findingTagsFromRecord } from "./FindingBits";
import { flowLabel } from "../lib/finding-ui";

function SevBadge({ severity }: { severity: string }) {
  const sev = severity.toUpperCase();
  return (
    <span className={`mono sev-${sev}`} style={{ fontSize: 11, fontWeight: 600, padding: "4px 11px", borderRadius: 8, border: "1px solid var(--border)" }}>
      {sev}
    </span>
  );
}

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 8, marginTop: 20, letterSpacing: ".08em", fontWeight: 600 }}>
      {children}
    </div>
  );
}

function InfoRow({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) {
  if (value === null || value === undefined || value === "" || value === "-") return null;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "150px minmax(0, 1fr)", gap: 10, fontSize: 12, padding: "4px 0", minWidth: 0 }}>
      <span style={{ color: "var(--dim)", fontSize: 11 }}>{label}</span>
      <span className="mono" style={{ color: color || "var(--text)", wordBreak: "break-all", minWidth: 0 }}>{value}</span>
    </div>
  );
}

function ProcessBox({ label, image, pid, badgeColor }: { label: string; image?: string; pid?: unknown; badgeColor: string }) {
  const name = image ? String(image).split(/[/\\]/).pop() : "unknown";
  const fullPath = image ? String(image) : null;
  return (
    <div style={{ flex: "1 1 240px", minWidth: 0 }}>
      <div style={{ fontSize: 10, color: "var(--dim)", marginBottom: 4, letterSpacing: ".06em" }}>{label}</div>
      <div
        style={{
          background: "var(--hole)",
          border: `1px solid ${badgeColor}33`,
          borderRadius: 10,
          padding: "10px 12px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: badgeColor, flexShrink: 0 }} />
          <span className="mono" style={{ fontSize: 13, fontWeight: 600, wordBreak: "break-all" }}>{name}</span>
          {pid != null ? (
            <span className="mono" style={{ fontSize: 11, color: "var(--dim)", flexShrink: 0 }}>PID {String(pid)}</span>
          ) : null}
        </div>
        {fullPath ? (
          <div className="mono" style={{ fontSize: 10, color: "var(--dim)", wordBreak: "break-all", paddingLeft: 16 }}>
            {fullPath}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function EvidenceGrid({ evidence }: { evidence: Record<string, unknown> }) {
  const entries = Object.entries(evidence).filter(
    ([, v]) => v !== null && v !== undefined && v !== "",
  );
  if (!entries.length) return null;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "4px 20px" }}>
      {entries.map(([key, val]) => {
        let display: string;
        let color = "var(--text)";
        if (typeof val === "boolean") {
          display = val ? "yes" : "no";
          color = val ? "#46c26a" : "#e5484d";
        } else if (Array.isArray(val)) {
          display = val.join(", ");
        } else {
          display = String(val);
        }
        return (
          <div key={key} style={{ display: "grid", gridTemplateColumns: "minmax(120px, .9fr) minmax(0, 1.1fr)", gap: 8, fontSize: 11, padding: "4px 0", minWidth: 0 }}>
            <span style={{ color: "var(--dim)", overflowWrap: "anywhere" }}>{key.replace(/_/g, " ")}</span>
            <span className="mono" style={{ color, textAlign: "left", wordBreak: "break-word", overflowWrap: "anywhere", minWidth: 0 }}>{display}</span>
          </div>
        );
      })}
    </div>
  );
}

function NetworkChain({ finding }: { finding: Record<string, unknown> }) {
  const conns = finding.network_connections as
    | { destination?: string; protocol?: string; succeeded?: boolean; source?: string; timestamp?: string }[]
    | undefined;
  if (!conns || conns.length === 0) return null;
  return (
    <>
      <SectionHeader>POST-INJECTION NETWORK ACTIVITY ({conns.length} observations)</SectionHeader>
      <div
        style={{
          background: "var(--hole)",
          border: "1px solid rgba(236,123,26,.3)",
          borderRadius: 12,
          padding: "8px 14px",
        }}
      >
        {conns.map((c, i) => {
          const ok = c.succeeded === true;
          const pendingHandshake =
            c.succeeded === false && String(c.protocol || "").toUpperCase().includes("SYN_SENT");
          return (
            <div
              key={i}
              className="mono"
              style={{
                fontSize: 12,
                padding: "5px 0",
                display: "grid",
                gridTemplateColumns: "72px minmax(180px, 1fr) 110px 90px",
                gap: 8,
                alignItems: "center",
                borderBottom: i < conns.length - 1 ? "1px solid var(--border)" : undefined,
              }}
            >
              <span style={{ color: ok ? "#46c26a" : pendingHandshake ? "#ec7b1a" : "#e5484d", fontWeight: 700, whiteSpace: "nowrap" }}>
                {ok ? "OK" : pendingHandshake ? "NOT EST." : "FAILED"}
              </span>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.destination || "?"}</span>
              <span style={{ color: "var(--dim)", fontSize: 10, whiteSpace: "nowrap" }}>{c.protocol || ""}</span>
              <span style={{ color: "var(--dim)", fontSize: 10, textAlign: "right", overflowWrap: "anywhere" }}>{c.source || ""}</span>
            </div>
          );
        })}
      </div>
    </>
  );
}

type Props = {
  member: FindingMember;
  canReport: boolean;
  canDel: boolean;
  canKill: boolean;
  killed: boolean;
  onClose: () => void;
  onDelete: () => void;
  onKill: () => void;
};

export function FindingModal({ member, canReport, canDel, canKill, killed, onClose, onDelete, onKill }: Props) {
  const finding = member.finding || {};
  const tags = findingTagsFromRecord(finding);
  const evidence = (finding.evidence as Record<string, unknown>) || {};
  const score = finding.score as number | undefined;
  const technique = finding.technique as string | undefined;
  const techniqueConfidence = finding.technique_confidence as string | undefined;
  const description = finding.description as string | undefined;
  const relatedFile = finding.related_file as Record<string, unknown> | undefined;
  const isRecursive = finding.is_recursive as boolean | undefined;
  const injectionChain = finding.injection_chain as number[] | undefined;
  const chainDepth = finding.chain_depth as number | undefined;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-card"
        onClick={(e) => e.stopPropagation()}
        style={{ width: "min(920px, calc(100vw - 40px))", maxWidth: 920 }}
      >
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8, flexWrap: "wrap" }}>
          <SevBadge severity={member.severity} />
          {score != null ? (
            <span className="mono" style={{ fontSize: 20, fontWeight: 700, color: "var(--text)" }}>{score}</span>
          ) : null}
          <AgentBadge agentId={String(member.agent_id || finding.agent_id || "")} hostname={member.hostname} />
          <button type="button" className="btn-ghost" style={{ marginLeft: "auto" }} onClick={onClose}>
            ×
          </button>
        </div>
        <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 4 }}>{member.title}</div>
        {description ? (
          <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 8, lineHeight: 1.5 }}>{description}</div>
        ) : null}
        <div className="mono" style={{ fontSize: 11, color: "var(--dim)", marginBottom: 16 }}>
          {String(member.time || "")}
        </div>

        {/* Flow diagram */}
        <div
          className="mono"
          style={{
            background: "var(--hole)",
            border: "1px solid var(--border)",
            borderRadius: 12,
            padding: "14px 16px",
            marginBottom: 16,
            fontSize: 12,
            lineHeight: 1.6,
            overflowWrap: "anywhere",
          }}
        >
          {flowLabel(finding)}
        </div>

        {/* Process boxes */}
        <div style={{ display: "flex", gap: 10, marginBottom: 4, flexWrap: "wrap", alignItems: "stretch" }}>
          <ProcessBox
            label="LOADER (actor)"
            image={finding.actor_image as string}
            pid={finding.actor_pid}
            badgeColor="#5b9df0"
          />
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", color: "var(--dim)", fontSize: 18, paddingTop: 14, flexShrink: 0 }}>
            ▸
          </div>
          <ProcessBox
            label="TARGET (victim)"
            image={finding.target_image as string}
            pid={finding.target_pid}
            badgeColor="#e5484d"
          />
        </div>

        {/* Tags */}
        <div style={{ marginTop: 16, marginBottom: 4 }}>
          <TagChips tags={tags} />
        </div>

        {/* Technique & Classification */}
        <SectionHeader>TECHNIQUE</SectionHeader>
        <div
          style={{
            background: "var(--hole)",
            border: "1px solid var(--border)",
            borderRadius: 12,
            padding: "10px 14px",
          }}
        >
          <InfoRow label="Technique" value={technique || "unclassified"} />
          <InfoRow label="Confidence" value={techniqueConfidence} color={techniqueConfidence === "high" ? "#46c26a" : "#ec7b1a"} />
          <InfoRow label="Payload" value={evidence.payload_kind as string} />
          <InfoRow
            label="Execution confirmed"
            value={
              evidence.execution_confirmed === true
                ? `yes (${(evidence.execution_evidence as string[] || []).join(", ")})`
                : evidence.execution_confirmed === false
                  ? "no"
                  : undefined
            }
            color={evidence.execution_confirmed ? "#46c26a" : "#e5484d"}
          />
          {evidence.missing_execution_transfer ? (
            <InfoRow label="Missing exec transfer" value="yes" color="#ec7b1a" />
          ) : null}
          {evidence.context_read_evidence ? (
            <InfoRow label="Context read APIs" value={(evidence.context_read_evidence as string[]).join(", ")} />
          ) : null}
          {relatedFile ? (
            <InfoRow label="Related file" value={relatedFile.path as string} />
          ) : null}
          {isRecursive && injectionChain ? (
            <InfoRow label="Recursive chain" value={`${chainDepth} hops: ${injectionChain.join(" → ")}`} color="#ec7b1a" />
          ) : null}
        </div>

        {/* Evidence */}
        {Object.keys(evidence).length > 0 ? (
          <>
            <SectionHeader>EVIDENCE</SectionHeader>
            <div
              style={{
                background: "var(--hole)",
                border: "1px solid var(--border)",
                borderRadius: 12,
                padding: "10px 14px",
              }}
            >
              <EvidenceGrid evidence={evidence} />
            </div>
          </>
        ) : null}

        {/* API Chain */}
        <SectionHeader>API CHAIN</SectionHeader>
        <ApiChainList finding={finding} />

        {/* Network */}
        <NetworkChain finding={finding} />

        {/* Actions */}
        <div style={{ borderTop: "1px solid var(--border)", paddingTop: 16, display: "flex", gap: 8, marginTop: 24, flexWrap: "wrap" }}>
          {canReport ? (
            <button type="button" className="btn-ghost" onClick={() => api.downloadReport(member.key)}>
              Export report (.md)
            </button>
          ) : null}
          {canKill && !killed ? (
            <button type="button" className="btn-brand" style={{ background: "#e5484d", boxShadow: "none" }} onClick={onKill}>
              Kill process
            </button>
          ) : null}
          {killed ? <span className="mono" style={{ color: "#e5484d", padding: "6px 0" }}>TERMINATED</span> : null}
          {canDel ? (
            <button type="button" className="btn-ghost" style={{ marginLeft: "auto", color: "#e5484d" }} onClick={onDelete}>
              Mark false positive & delete
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
