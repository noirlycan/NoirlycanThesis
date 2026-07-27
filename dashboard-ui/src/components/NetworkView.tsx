import { useState } from "react";

function SourceBadge({ source }: { source: string | undefined }) {
  const label = (source || "unknown").toUpperCase();
  const colors: Record<string, { bg: string; fg: string; border: string }> = {
    WFP: { bg: "rgba(91,157,240,.12)", fg: "#5b9df0", border: "rgba(91,157,240,.35)" },
    SYSMON: { bg: "rgba(70,194,106,.12)", fg: "#46c26a", border: "rgba(70,194,106,.35)" },
    TCP_TABLE: { bg: "rgba(232,192,32,.12)", fg: "#e8c020", border: "rgba(232,192,32,.35)" },
    FRIDA: { bg: "rgba(167,139,255,.12)", fg: "#a78bff", border: "rgba(167,139,255,.35)" },
  };
  const c = colors[label] || { bg: "var(--panel2)", fg: "var(--dim)", border: "var(--border)" };
  return (
    <span
      className="mono"
      style={{
        fontSize: 9,
        fontWeight: 700,
        padding: "3px 7px",
        borderRadius: 6,
        background: c.bg,
        color: c.fg,
        border: `1px solid ${c.border}`,
        letterSpacing: ".04em",
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

function ResultBadge({
  succeeded,
  protocol,
}: {
  succeeded: boolean | null | undefined;
  protocol?: unknown;
}) {
  if (succeeded === true) {
    return (
      <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: "#46c26a" }}>
        OK
      </span>
    );
  }
  if (succeeded === false) {
    const pendingHandshake = String(protocol || "").toUpperCase().includes("SYN_SENT");
    return (
      <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: "#e5484d" }}>
        {pendingHandshake ? "NOT EST." : "FAILED"}
      </span>
    );
  }
  return (
    <span className="mono" style={{ fontSize: 11, color: "var(--dim)" }}>
      --
    </span>
  );
}

function ConnDetail({ row, onClose }: { row: Record<string, unknown>; onClose: () => void }) {
  const skip = new Set(["beacon_candidate", "is_external"]);
  const entries = Object.entries(row).filter(
    ([k, v]) => v !== null && v !== undefined && v !== "" && !skip.has(k),
  );
  return (
    <div
      style={{
        background: "var(--hole)",
        border: "1px solid var(--border)",
        borderRadius: 12,
        padding: "14px 16px",
        marginBottom: 12,
        animation: "nlUp 0.15s ease",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", marginBottom: 10 }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: "var(--muted)", letterSpacing: ".06em" }}>
          CONNECTION DETAIL
        </span>
        <button
          type="button"
          className="btn-ghost"
          style={{ marginLeft: "auto", padding: "2px 8px", fontSize: 13 }}
          onClick={onClose}
        >
          x
        </button>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2px 20px" }}>
        {entries.map(([key, val]) => (
          <div key={key} style={{ display: "flex", gap: 8, fontSize: 11, padding: "3px 0", minWidth: 0 }}>
            <span style={{ color: "var(--dim)", minWidth: 120, flexShrink: 0 }}>
              {key.replace(/_/g, " ")}
            </span>
            <span className="mono" style={{ color: "var(--text)", wordBreak: "break-all", minWidth: 0 }}>
              {typeof val === "boolean" ? (val ? "yes" : "no") : String(val)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function NetworkView({
  network,
  beacons: _beacons,
  searchQuery,
}: {
  network: Record<string, unknown>[];
  beacons: Record<string, unknown>[];
  searchQuery: string;
}) {
  const [expanded, setExpanded] = useState<number | null>(null);

  const sources = new Set(network.map((row) => String(row.source || "unknown").toUpperCase()));
  const pids = new Set(network.map((row) => row.pid).filter(Boolean));
  const totalOk = network.filter((row) => row.succeeded === true).length;
  const totalFail = network.filter((row) => row.succeeded === false).length;
  const totalPending = network.length - totalOk - totalFail;

  const byPid = new Map<string, Record<string, unknown>[]>();
  for (const row of network) {
    const key = String(row.pid || "?");
    const list = byPid.get(key) || [];
    list.push(row);
    byPid.set(key, list);
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* KPI row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
        {[
          ["Connections", network.length, "var(--text)"],
          ["Unique PIDs", pids.size, "#ec7b1a"],
          ["Succeeded", totalOk, "#46c26a"],
          ["Not established", totalFail, "#e5484d"],
          ["Pending", totalPending, "var(--dim)"],
        ].map(([label, value, color]) => (
          <div key={String(label)} className="card" style={{ padding: "14px 16px" }}>
            <div style={{ fontSize: 11, color: "var(--dim)" }}>{label}</div>
            <div className="mono" style={{ fontSize: 22, fontWeight: 700, color: color as string, marginTop: 4 }}>
              {value as number}
            </div>
          </div>
        ))}
      </div>

      {/* Sources active */}
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <span style={{ fontSize: 11, color: "var(--dim)", letterSpacing: ".06em" }}>SOURCES:</span>
        {sources.size > 0 ? (
          [...sources].map((src) => <SourceBadge key={src} source={src} />)
        ) : (
          <span style={{ fontSize: 11, color: "var(--dim)" }}>none</span>
        )}
      </div>

      {/* Post-finding network activity grouped by PID */}
      {byPid.size > 0 ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {[...byPid.entries()].map(([pid, conns]) => {
            const first = conns[0];
            const image = String(first.image || first.process || "unknown");
            const name = image.split(/[/\\]/).pop() || image;
            const okCount = conns.filter((c) => c.succeeded === true).length;
            const failCount = conns.filter((c) => c.succeeded === false).length;
            return (
              <div
                key={pid}
                className="card"
                style={{
                  borderColor: "rgba(236,123,26,.35)",
                  background: "rgba(236,123,26,.06)",
                  padding: "14px 18px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
                  <span
                    className="mono"
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      padding: "3px 9px",
                      borderRadius: 7,
                      color: "#ec7b1a",
                      border: "1px solid rgba(236,123,26,.4)",
                      background: "rgba(236,123,26,.12)",
                    }}
                  >
                    POST-INJECTION
                  </span>
                  <span className="mono" style={{ fontSize: 13, fontWeight: 600 }}>{name}</span>
                  <span className="mono" style={{ fontSize: 11, color: "var(--dim)" }}>PID {pid}</span>
                  <span style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center", fontSize: 11, color: "var(--dim)" }}>
                    <span>{conns.length} observation{conns.length !== 1 ? "s" : ""}</span>
                    {okCount > 0 ? <span style={{ color: "#46c26a" }}>{okCount} established</span> : null}
                    {failCount > 0 ? <span style={{ color: "#e5484d" }}>{failCount} not established</span> : null}
                  </span>
                </div>
                <div className="mono" style={{ fontSize: 11, color: "var(--dim)", marginBottom: 8 }}>
                  Watched target PID network observations
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {conns.slice(0, 4).map((conn, i) => {
                    const dest = conn.endpoint || conn.destination || conn.remote_address ||
                      [conn.destination_hostname || conn.destination_ip, conn.destination_port].filter(Boolean).join(":") ||
                      "unknown";
                    return (
                      <div
                        key={i}
                        className="mono"
                        style={{
                          background: "var(--hole)",
                          border: "1px solid var(--border)",
                          borderRadius: 8,
                          padding: "6px 10px",
                          fontSize: 12,
                          display: "grid",
                          gridTemplateColumns: "minmax(180px,1fr) 110px 82px 70px",
                          gap: 8,
                          alignItems: "center",
                        }}
                      >
                        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(dest)}</span>
                        <span style={{ color: "var(--dim)", fontSize: 10, whiteSpace: "nowrap" }}>{String(conn.protocol || "")}</span>
                        <SourceBadge source={conn.source as string | undefined} />
                        <ResultBadge
                          succeeded={conn.succeeded as boolean | null | undefined}
                          protocol={conn.protocol}
                        />
                      </div>
                    );
                  })}
                  {conns.length > 4 ? (
                    <div className="mono" style={{ fontSize: 11, color: "var(--dim)", padding: "2px 0" }}>
                      +{conns.length - 4} more
                    </div>
                  ) : null}
                </div>
              </div>
            );
          })}
        </div>
      ) : null}

      {/* Connection detail panel */}
      {expanded !== null && network[expanded] ? (
        <ConnDetail row={network[expanded]} onClose={() => setExpanded(null)} />
      ) : null}

      {/* Full connection table */}
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "16px 20px 12px", borderBottom: "1px solid var(--border)" }}>
          <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 15 }}>
            All connections
          </div>
          <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 2 }}>
            All from injection target PIDs (post-finding network watch). Click a row for detail.
          </div>
        </div>
        <div style={{ overflowX: "auto" }}>
          {/* Table header */}
          <div
            className="mono"
            style={{
              display: "grid",
              gridTemplateColumns: "40px 64px 140px minmax(180px,1fr) 110px 64px 92px 90px 80px",
              gap: 8,
              padding: "10px 20px",
              fontSize: 10,
              color: "var(--dim)",
              letterSpacing: ".04em",
              borderBottom: "1px solid var(--border)",
              minWidth: 980,
            }}
          >
            <span>#</span>
            <span>PID</span>
            <span>PROCESS</span>
            <span>DESTINATION</span>
            <span>PROTO</span>
            <span>PORT</span>
            <span>RESULT</span>
            <span>SOURCE</span>
            <span>TIME</span>
          </div>
          {/* Table rows */}
          {network.slice(0, 50).map((row, index) => {
            const image = String(row.image || row.process || "-");
            const name = image !== "-" ? image.split(/[/\\]/).pop() || image : "-";
            const dest =
              row.destination_hostname ||
              row.destination_ip ||
              row.endpoint ||
              row.destination ||
              row.remote_address ||
              "-";
            const port = row.destination_port ?? "-";
            const proto = row.protocol || "-";
            const succeeded = row.succeeded as boolean | null | undefined;
            const ts = String(row.timestamp || "");
            const timeStr = ts.length >= 19 ? ts.slice(11, 19) : ts.slice(0, 8) || "-";

            return (
              <div
                key={index}
                style={{
                  display: "grid",
                  gridTemplateColumns: "40px 64px 140px minmax(180px,1fr) 110px 64px 92px 90px 80px",
                  gap: 8,
                  padding: "10px 20px",
                  fontSize: 12,
                  cursor: "pointer",
                  borderBottom: "1px solid var(--border)",
                  minWidth: 980,
                  alignItems: "center",
                }}
                onClick={() => setExpanded(expanded === index ? null : index)}
              >
                <span className="mono" style={{ color: "var(--dim)" }}>{index + 1}</span>
                <span className="mono">{String(row.pid || "-")}</span>
                <span
                  className="mono"
                  title={image}
                  style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                >
                  {name}
                </span>
                <span
                  className="mono"
                  style={{
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {String(dest)}
                </span>
                <span className="mono" style={{ color: "var(--dim)", whiteSpace: "nowrap" }}>{String(proto)}</span>
                <span className="mono">{String(port)}</span>
                <ResultBadge succeeded={succeeded} protocol={proto} />
                <SourceBadge source={row.source as string | undefined} />
                <span className="mono" style={{ color: "var(--dim)", fontSize: 11 }}>{timeStr}</span>
              </div>
            );
          })}
          {network.length > 50 ? (
            <div className="mono" style={{ padding: "12px 20px", fontSize: 11, color: "var(--dim)" }}>
              Showing 50 of {network.length} connections
            </div>
          ) : null}
        </div>
        {!network.length ? (
          <div style={{ color: "var(--dim)", padding: "20px" }}>
            {searchQuery.trim()
              ? `No connections match "${searchQuery.trim()}".`
              : "No network telemetry. Waiting for post-finding network activity (WFP audit + TCP table + Sysmon EID 3)."}
          </div>
        ) : null}
      </div>
    </div>
  );
}
