type Props = {
  agentId?: string;
  hostname?: string;
};

export function AgentBadge({ agentId, hostname }: Props) {
  if (!agentId && !hostname) return null;
  return (
    <span
      className="mono"
      style={{
        fontSize: 10,
        color: "var(--accentText)",
        background: "var(--panel2)",
        border: "1px solid var(--navBorder)",
        borderRadius: 8,
        padding: "4px 9px",
        whiteSpace: "nowrap",
      }}
    >
      {hostname || agentId}
    </span>
  );
}

export function agentLabel(record: Record<string, unknown> | null | undefined, fallback?: string) {
  return String(record?.hostname || record?.agent_id || fallback || "");
}
