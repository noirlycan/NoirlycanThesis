import { eventKindColor } from "../lib/finding-ui";

function dropBadge(drop: Record<string, unknown>): { label: string; color: string } {
  const flags = String(drop.flags || drop.verdict || drop.kind || "").toUpperCase();
  const unsigned = drop.unsigned === true || flags.includes("UNSIGNED");
  if (unsigned) return { label: "UNSIGNED", color: "#e5484d" };
  if (flags.includes("PE") || String(drop.path || drop.filename || "").toLowerCase().endsWith(".exe")) {
    return { label: "PE", color: "#ec7b1a" };
  }
  if (flags.includes("SCRIPT") || /\.(ps1|js|vbs|bat)$/i.test(String(drop.path || drop.filename || ""))) {
    return { label: "SCRIPT", color: "#e8c020" };
  }
  return { label: "FILE", color: "var(--muted)" };
}

export function ActivityView({
  events,
  triages,
  searchQuery,
}: {
  events: Record<string, unknown>[];
  triages: Record<string, unknown>[];
  searchQuery: string;
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
                color: highlighted ? "#e5484d" : undefined,
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
          return (
            <div
              key={`${name}-${index}`}
              style={{
                padding: "12px 14px",
                border: "1px solid var(--border)",
                borderRadius: 12,
                background: "var(--hole)",
                marginBottom: 10,
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                <span
                  className="mono"
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    padding: "3px 8px",
                    borderRadius: 6,
                    color: badge.color,
                    border: `1px solid ${badge.color}55`,
                    background: `${badge.color}14`,
                  }}
                >
                  {badge.label}
                </span>
                <span style={{ fontWeight: 600 }}>{name}</span>
              </div>
              <div className="mono" style={{ fontSize: 11, color: "var(--dim)", lineHeight: 1.6 }}>
                {drop.sha256 ? `sha256 ${String(drop.sha256).slice(0, 24)}…` : null}
                {drop.entropy != null ? ` · entropy ${drop.entropy}` : null}
                {drop.authenticode ? ` · ${drop.authenticode}` : drop.signed === false ? " · unsigned" : null}
                {drop.creator || drop.creator_image ? ` · creator ${String(drop.creator || drop.creator_image)}` : null}
                {drop.api_status ? ` · api ${String(drop.api_status)}` : null}
                {!drop.sha256 && drop.status === "pending" ? " · triage pending" : null}
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
