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

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
          <SevBadge severity={member.severity} />
          <strong style={{ fontSize: 16 }}>{member.title}</strong>
          <AgentBadge agentId={String(member.agent_id || finding.agent_id || "")} hostname={member.hostname} />
          <button type="button" className="btn-ghost" style={{ marginLeft: "auto" }} onClick={onClose}>
            ×
          </button>
        </div>
        <div className="mono" style={{ fontSize: 12, color: "var(--dim)", marginBottom: 12 }}>
          {String(member.time || "")}
        </div>
        <div
          className="mono"
          style={{
            background: "var(--hole)",
            border: "1px solid var(--border)",
            borderRadius: 12,
            padding: "12px 14px",
            marginBottom: 12,
            fontSize: 12,
          }}
        >
          {flowLabel(finding)}
        </div>
        <div style={{ marginBottom: 16 }}>
          <TagChips tags={tags} />
        </div>
        <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 8, letterSpacing: ".06em" }}>API CHAIN</div>
        <ApiChainList finding={finding} />
        <div style={{ borderTop: "1px solid var(--border)", paddingTop: 16, display: "flex", gap: 8, marginTop: 20 }}>
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
          {killed ? <span className="mono" style={{ color: "#e5484d" }}>TERMINATED</span> : null}
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
