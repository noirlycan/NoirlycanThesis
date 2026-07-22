import { apiChainRows, collectTags, opColor, tagStyle } from "../lib/finding-ui";

export function TagChips({ tags }: { tags: string[] }) {
  if (!tags.length) return null;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
      {tags.map((tag) => {
        const style = tagStyle(tag);
        return (
          <span
            key={tag}
            className="mono"
            style={{
              fontSize: 10,
              padding: "3px 8px",
              borderRadius: 6,
              border: `1px solid ${style.border}`,
              background: style.background,
              color: style.color,
            }}
          >
            {tag}
          </span>
        );
      })}
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
        <div key={`${row.api}-${index}`} className="mono" style={{ display: "flex", gap: 12, alignItems: "baseline", fontSize: 12 }}>
          <span style={{ width: 52, color: opColor(row.op), fontWeight: 600 }}>{row.op}</span>
          <span style={{ minWidth: 180 }}>{row.api}</span>
          {row.detail ? <span style={{ color: "var(--dim)" }}>{row.detail}</span> : null}
        </div>
      ))}
    </div>
  );
}

export function findingTagsFromRecord(finding: Record<string, unknown> | undefined): string[] {
  return collectTags(finding);
}
