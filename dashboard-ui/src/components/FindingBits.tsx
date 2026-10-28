import { apiChainRows, collectTags, opColor, tagClass, visibleTags } from "../lib/finding-ui";

export function TagChips({ tags }: { tags: string[] }) {
  const labels = visibleTags(tags);
  if (!labels.length) return null;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
      {labels.map((label) => (
        <span key={label} className={tagClass(label)}>
          {label}
        </span>
      ))}
    </div>
  );
}

export function ApiChainList({ finding }: { finding: Record<string, unknown> | undefined }) {
  const rows = apiChainRows(finding);
  if (!rows.length) {
    return <div style={{ color: "var(--dim)", fontSize: 12 }}>No API chain recorded.</div>;
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {rows.map((row, index) => (
        <div
          key={`${row.api}-${index}`}
          className="mono"
          style={{
            display: "grid",
            gridTemplateColumns: "92px minmax(160px, 1fr) minmax(0, 1fr)",
            gap: "4px 12px",
            alignItems: "baseline",
            fontSize: 12,
          }}
        >
          <span style={{ color: opColor(row.op), fontWeight: 600, whiteSpace: "nowrap" }}>{row.op}</span>
          <span style={{ minWidth: 0, overflowWrap: "anywhere" }}>{row.api}</span>
          {row.detail ? (
            <span style={{ color: "var(--dim)", minWidth: 0, overflowWrap: "anywhere" }}>{row.detail}</span>
          ) : (
            <span />
          )}
        </div>
      ))}
    </div>
  );
}

export function findingTagsFromRecord(finding: Record<string, unknown> | undefined): string[] {
  return collectTags(finding);
}
