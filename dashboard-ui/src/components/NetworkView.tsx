export function NetworkView({
  network,
  beacons,
  searchQuery,
}: {
  network: Record<string, unknown>[];
  beacons: Record<string, unknown>[];
  searchQuery: string;
}) {
  const beacon = beacons[0] || network.find((row) => row.beacon_candidate || row.is_external);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {beacon ? (
        <div
          className="card"
          style={{
            borderColor: "rgba(236,123,26,.45)",
            background: "rgba(236,123,26,.08)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
            <span
              className="mono"
              style={{
                fontSize: 10,
                fontWeight: 700,
                padding: "4px 10px",
                borderRadius: 8,
                color: "#ec7b1a",
                border: "1px solid rgba(236,123,26,.45)",
                background: "rgba(236,123,26,.12)",
              }}
            >
              BEACON?
            </span>
            <strong>Outbound to non-private range</strong>
            <span className="mono" style={{ marginLeft: "auto", fontSize: 11, color: "var(--dim)" }}>
              post-finding watch · 5 min
            </span>
          </div>
          <div
            className="mono"
            style={{
              background: "var(--hole)",
              border: "1px solid var(--border)",
              borderRadius: 12,
              padding: "12px 14px",
              fontSize: 12,
            }}
          >
            {String(beacon.image || beacon.process || "process")} {String(beacon.pid || "")} ──▶{" "}
            {String(beacon.destination || beacon.endpoint || beacon.remote_address || "unknown")}{" "}
            {beacon.protocol ? `${beacon.protocol} · ` : ""}
            {beacon.connections || beacon.count ? `${beacon.connections || beacon.count} conns` : ""}
          </div>
        </div>
      ) : null}

      <div className="card">
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, marginBottom: 12 }}>Connections</div>
        <div className="table-row mono" style={{ gridTemplateColumns: "1.2fr 1fr 1fr 90px", fontSize: 10, color: "var(--dim)" }}>
          <span>PROCESS</span>
          <span>DESTINATION</span>
          <span>CLASS</span>
          <span>CONNS</span>
        </div>
        {network.slice(0, 24).map((row, index) => {
          const klass = String(row.classification || row.class || (row.is_external ? "PUBLIC" : "PRIVATE")).toUpperCase();
          const classColor = klass.includes("PUBLIC") || klass.includes("EXTERNAL") ? "#ec7b1a" : "#46c26a";
          return (
            <div key={index} className="table-row" style={{ gridTemplateColumns: "1.2fr 1fr 1fr 90px" }}>
              <span>{String(row.image || row.process || row.pid || "process")}</span>
              <span className="mono">{String(row.destination || row.endpoint || row.remote_address || "-")}</span>
              <span className="mono" style={{ color: classColor }}>
                {klass}
              </span>
              <span className="mono">{String(row.connections || row.count || 1)}</span>
            </div>
          );
        })}
        {!network.length ? (
          <div style={{ color: "var(--dim)", paddingTop: 8 }}>
            {searchQuery.trim() ? `No connections match "${searchQuery.trim()}".` : "No network telemetry."}
          </div>
        ) : null}
      </div>
    </div>
  );
}
