const SEV_COLORS: Record<string, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
  INFO: "var(--sev-info)",
};

const PAPER_KINDS = new Set(["allocate", "write", "execute"]);
const KERNEL_FLAGS = ["direct_syscall", "unbacked_caller", "hook_bypass_suspected", "unbacked_thread_start"];

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
  if (upper.includes("EXEC")) return "var(--sev-critical)";
  if (upper.includes("WRITE")) return "var(--op-write)";
  if (upper.includes("ALLOC")) return "var(--op-alloc)";
  if (upper.includes("PROC") || upper.includes("FILE")) return "var(--sev-info)";
  return "var(--muted)";
}

export function collectTags(finding: Record<string, unknown> | undefined): string[] {
  if (!finding) return [];
  const tags = new Set<string>();
  const evidence = (finding.evidence as Record<string, unknown> | undefined) || {};
  const primitives = (finding.primitives as Record<string, unknown>[] | undefined) || [];
  const kinds = new Set(primitives.map((item) => String(item.kind || "").toLowerCase()).filter((kind) => PAPER_KINDS.has(kind)));
  if (kinds.size >= 2) tags.add(`${kinds.size}/3 primitives`);
  for (const [key, value] of Object.entries(evidence)) {
    if (value === true) tags.add(`${key}=true`);
  }
  return [...tags];
}

/** Only flags that are on, as readable labels: "cross_process=true" → "cross process". */
export function visibleTags(tags: string[]): string[] {
  return tags
    .filter((tag) => !tag.endsWith("=false"))
    .map((tag) => tag.replace(/=true$/, "").replace(/_/g, " "));
}

export function tagClass(label: string): string {
  const key = label.replace(/ /g, "_");
  if (KERNEL_FLAGS.includes(key)) return "chip chip-CRITICAL";
  if (key === "cross_process") return "chip chip-exec";
  if (key === "section_mapping") return "chip chip-alloc";
  if (key.includes("primitives") || key === "execution_confirmed") return "chip chip-accent";
  return "chip";
}

export function baseName(path: string): string {
  return path.split(/[/\\]/).pop() || path;
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
  const conns = finding.network_connections as
    | { destination?: string; succeeded?: boolean; protocol?: string }[]
    | undefined;
  if (conns && conns.length > 0) {
    const first = conns[0];
    const dest = first.destination || "unknown";
    const status =
      first.succeeded === true
        ? " ESTABLISHED"
        : first.succeeded === false && String(first.protocol || "").toUpperCase().includes("SYN_SENT")
          ? " NOT EST."
          : first.succeeded === false
            ? " FAILED"
            : "";
    const extra = conns.length > 1 ? ` (+${conns.length - 1})` : "";
    return `${actor} ──▶ ${target} ──▶ ${dest}${status}${extra}`;
  }
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
