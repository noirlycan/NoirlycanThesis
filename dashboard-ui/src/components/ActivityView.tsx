import { eventKindColor } from "../lib/finding-ui";

function dropBadge(drop: Record<string, unknown>): { label: string; chip: string } {
  const flags = String(drop.flags || drop.verdict || drop.kind || "").toUpperCase();
  const path = String(drop.path || drop.filename || "").toLowerCase();
  if (drop.unsigned === true || drop.signed === false || flags.includes("UNSIGNED")) return { label: "UNSIGNED", chip: "chip chip-CRITICAL" };
  if (flags.includes("PE") || path.endsWith(".exe") || path.endsWith(".dll")) return { label: "PE", chip: "chip chip-HIGH" };
  if (flags.includes("SCRIPT") || /\.(ps1|js|vbs|bat)$/.test(path)) return { label: "SCRIPT", chip: "chip chip-MEDIUM" };
  return { label: "FILE", chip: "chip" };
}

function dropDetails(drop: Record<string, unknown>): string {
  const creator = String(drop.creator || drop.creator_image || "");
  const parts = [
    drop.sha256 ? `sha256 ${String(drop.sha256).slice(0, 16)}…` : "",
    drop.entropy != null ? `entropy ${Number(drop.entropy).toFixed(2)}` : "",
    drop.authenticode ? String(drop.authenticode) : drop.signed === false ? "unsigned" : "",
    creator ? `by ${creator.split(/[/\\]/).pop()}` : "",
    drop.api_status ? `api ${String(drop.api_status)}` : "",
    !drop.sha256 && drop.status === "pending" ? "triage pending" : "",
  ];
  return parts.filter(Boolean).join(" · ");
}

export function ActivityView({
  events,
  triages,
  searchQuery,
  canDel,
  onDelete,
}: {
  events: Record<string, unknown>[];
  triages: Record<string, unknown>[];
  searchQuery: string;
  canDel?: boolean;
  onDelete?: (path: string, dropKey?: string) => void | Promise<void>;
}) {
  return (
    <div className="grid-2">
      <div className="card">
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
          <span className="pulse-dot" />
          <span style={{ fontFamily: "Space Grotesk", fontWeight: 600 }}>Event stream</span>
        </div>
        {events.slice(0, 24).map((event, index) => {
          const kind = String(event.type || event.kind || "EVENT").toUpperCase();
          const highlighted = index === 0 && kind.includes("EXEC");
          return (
            <div
              key={`${String(event.timestamp)}-${index}`}
              className="mono"
              style={{
                fontSize: 12,
                padding: "8px 0",
                borderBottom: "1px solid var(--border)",
                color: highlighted ? "var(--sev-critical)" : undefined,
              }}
            >
              <span style={{ color: "var(--dim)" }}>{String(event.timestamp || "").slice(11, 19)}</span>
              {" · "}
              <span style={{ color: eventKindColor(kind) }}>{kind}</span>
              {" · "}
              {String(event.message || event.title || event.api || event.image || "")}
            </div>
          );
        })}
        {!events.length ? (
          <div style={{ color: "var(--dim)" }}>
            {searchQuery.trim() ? `No events match "${searchQuery.trim()}".` : "No events yet."}
          </div>
        ) : null}
      </div>

      <div className="card">
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, marginBottom: 14 }}>File drops</div>
        {triages.slice(0, 10).map((drop, index) => {
          const badge = dropBadge(drop);
          const name = String(drop.path || drop.filename || "file").split(/[/\\]/).pop();
          const path = String(drop.path || drop.filename || "");
          const dropKey = String(drop.drop_key || "");
          return (
            <div
              key={`${String(drop.drop_key || path || name)}-${index}`}
              style={{
                padding: "12px 14px",
                border: "1px solid var(--border)",
                borderRadius: 12,
                background: "var(--hole)",
                marginBottom: 10,
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                <span className={badge.chip}>{badge.label}</span>
                <span style={{ fontWeight: 600, flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" }} title={path}>{name}</span>
                {canDel && path ? (
                  <button
                    type="button"
                    className="btn-ghost"
                    style={{ padding: "2px 8px", fontSize: 14, lineHeight: 1, color: "var(--muted)" }}
                    title="Remove from history"
                    aria-label={`Remove ${name} from history`}
                    onClick={(event) => {
                      event.stopPropagation();
                      void onDelete?.(path, dropKey || undefined);
                    }}
                  >
                    ×
                  </button>
                ) : null}
              </div>
              <div className="mono" style={{ fontSize: 11, color: "var(--dim)", lineHeight: 1.6 }} title={path}>
                {dropDetails(drop)}
              </div>
            </div>
          );
        })}
        {!triages.length ? (
          <div style={{ color: "var(--dim)" }}>
            {searchQuery.trim() ? `No file drops match "${searchQuery.trim()}".` : "No file drops."}
          </div>
        ) : null}
      </div>
    </div>
  );
}
