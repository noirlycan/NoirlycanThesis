const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#e5484d",
  HIGH: "#ec7b1a",
  MEDIUM: "#e8c020",
  LOW: "#46c26a",
  INFO: "#5b9df0",
};

const OP_COLORS: Record<string, string> = {
  alloc: "var(--op-alloc)",
  allocate: "var(--op-alloc)",
  write: "var(--op-write)",
  exec: "var(--op-exec)",
  execute: "var(--op-exec)",
};

export function sevColor(severity: string): string {
  return SEV_COLORS[severity.toUpperCase()] || SEV_COLORS.INFO;
}

export function opColor(kind: string): string {
  return OP_COLORS[kind.toLowerCase()] || "var(--muted)";
}

export function eventKindColor(kind: string): string {
  const upper = kind.toUpperCase();
  if (upper.includes("EXEC")) return "#e5484d";
  if (upper.includes("WRITE")) return "var(--op-write)";
  if (upper.includes("ALLOC")) return "var(--op-alloc)";
  if (upper.includes("PROC") || upper.includes("FILE")) return "var(--sev-info)";
  return "var(--muted)";
}

export function collectTags(finding: Record<string, unknown> | undefined): string[] {
  if (!finding) return [];
  const tags = new Set<string>();
  const evidence = (finding.evidence as Record<string, unknown> | undefined) || {};
  if (finding.section_mapping || evidence.section_mapping) tags.add("section_mapping=true");
  if (finding.cross_process || evidence.cross_process) tags.add("cross_process=true");
  const primitives = (finding.primitives as Record<string, unknown>[] | undefined) || [];
  const kinds = new Set(
    primitives.map((item) => String(item.kind || "").toLowerCase()).filter(Boolean),
  );
  if (kinds.size >= 2) tags.add(`${kinds.size} / 3 primitives`);
  if (kinds.size >= 3) tags.add("3 / 3 primitives");
  for (const [key, value] of Object.entries(evidence)) {
    if (value === true) tags.add(`${key}=true`);
  }
  return [...tags];
}

export function tagStyle(tag: string): { background: string; color: string; border: string } {
  if (tag.includes("section_mapping")) {
    return { background: "rgba(70,194,106,.12)", color: "#46c26a", border: "rgba(70,194,106,.35)" };
  }
  if (tag.includes("cross_process")) {
    return { background: "rgba(236,123,26,.12)", color: "#ec7b1a", border: "rgba(236,123,26,.35)" };
  }
  if (tag.includes("primitive")) {
    return { background: "var(--panel2)", color: "var(--text)", border: "var(--border)" };
  }
  return { background: "var(--panel2)", color: "var(--muted)", border: "var(--border)" };
}

export function groupTargetLabel(victim: string, vpid: number | string | null | undefined): string {
  if (vpid == null || vpid === "") return victim;
  if (victim.includes("(pid")) return victim;
  return `${victim} (pid ${vpid})`;
}

export function flowLabel(finding: Record<string, unknown> | undefined): string {
  if (!finding) return "";
  const actor = `${String(finding.actor_image || "unknown").split(/[/\\]/).pop()} ${finding.actor_pid || ""}`.trim();
  const targetPid = finding.target_pid;
  if (targetPid == null) {
    return `${actor} ──▶ disk drop`;
  }
  const targetName = finding.target_image
    ? String(finding.target_image).split(/[/\\]/).pop()
    : "unknown";
  const target = `${targetName} (pid ${targetPid})`;
  const suspended = finding.suspended_spawn || (finding.evidence as Record<string, unknown> | undefined)?.suspended_spawn;
  return `${actor} ──▶ ${target}${suspended ? "  SUSPENDED" : ""}`;
}

export function apiChainRows(finding: Record<string, unknown> | undefined): { op: string; api: string; detail: string }[] {
  const primitives = (finding?.primitives as Record<string, unknown>[] | undefined) || [];
  return primitives.map((item) => ({
    op: String(item.kind || item.op || "op").toLowerCase(),
    api: String(item.api || ""),
    detail: String(item.detail || item.summary || item.target || ""),
  }));
}

export function severityDonut(counts: Record<string, number> | undefined, total: number): string {
  const order = ["critical", "high", "medium", "low", "info"];
  const normalized: { key: string; count: number; color: string }[] = [];
  let sum = 0;
  for (const key of order) {
    const count = Number(counts?.[key] ?? counts?.[key.toUpperCase()] ?? 0);
    if (count > 0) {
      normalized.push({ key, count, color: sevColor(key) });
      sum += count;
    }
  }
  const denom = sum || total || 1;
  let cursor = 0;
  const stops: string[] = [];
  for (const item of normalized) {
    const start = (cursor / denom) * 100;
    cursor += item.count;
    const end = (cursor / denom) * 100;
    stops.push(`${item.color} ${start}% ${end}%`);
  }
  if (!stops.length) {
    return "conic-gradient(var(--border) 0% 100%)";
  }
  return `conic-gradient(${stops.join(", ")})`;
}

export function primitiveBarHeight(count: number, max: number): number {
  if (max <= 0) return 0;
  return Math.max(18, Math.round((count / max) * 104));
}
