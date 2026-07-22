import type { FindingGroup } from "../types";

export function normalizeSearch(query: string): string {
  return query.trim().toLowerCase();
}

function collectValues(value: unknown, depth = 0): string[] {
  if (depth > 8 || value == null) return [];
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return [String(value)];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => collectValues(item, depth + 1));
  }
  if (typeof value === "object") {
    return Object.values(value as Record<string, unknown>).flatMap((item) => collectValues(item, depth + 1));
  }
  return [];
}

export function matchesSearch(query: string, ...sources: unknown[]): boolean {
  const needle = normalizeSearch(query);
  if (!needle) return true;
  const blob = sources.flatMap((source) => collectValues(source)).join(" ").toLowerCase();
  return blob.includes(needle);
}

export function filterFindingGroups(groups: FindingGroup[], query: string): FindingGroup[] {
  if (!normalizeSearch(query)) return groups;
  return groups
    .map((group) => {
      const members = group.members.filter((member) => matchesSearch(query, group, member, member.finding));
      if (members.length) {
        return { ...group, members, count: members.length };
      }
      return matchesSearch(query, group) ? group : null;
    })
    .filter((group): group is FindingGroup => group !== null);
}

export function filterRecords<T extends Record<string, unknown>>(rows: T[], query: string): T[] {
  if (!normalizeSearch(query)) return rows;
  return rows.filter((row) => matchesSearch(query, row));
}
