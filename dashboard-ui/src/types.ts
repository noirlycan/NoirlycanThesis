export type TabId =
  | "overview"
  | "findings"
  | "activity"
  | "network"
  | "rules"
  | "agents"
  | "account"
  | "access";

export type Permissions = Record<string, boolean>;

export interface User {
  email: string;
  name: string;
  role: string;
  initial: string;
}

export interface FindingMember {
  key: string;
  step: number;
  severity: string;
  title: string;
  primitives?: unknown;
  time?: string;
  agent_id?: string;
  hostname?: string;
  finding?: Record<string, unknown>;
}

export interface FindingGroup {
  key: string;
  agent_id?: string;
  hostname?: string;
  top_severity: string;
  source: string;
  victim: string;
  vpid?: number | string | null;
  summary: string;
  tags: string[];
  count: number;
  members: FindingMember[];
}

export interface AgentStat {
  agent_id: string;
  hostname: string;
  ip_address?: string;
  session_rel?: string;
  status?: string;
  findings: number;
  critical: number;
  high?: number;
  medium?: number;
  low?: number;
  injection_chains: number;
  file_drops: number;
  beacons: number;
}

export interface OverviewData {
  session?: string;
  scope?: string;
  kpis?: {
    findings: number;
    critical: number;
    injection_chains: number;
    file_drops: number;
    beacons: number;
    agents?: number;
  };
  severity_counts?: Record<string, number>;
  primitive_kind_counts?: Record<string, number>;
  critical_finding?: Record<string, unknown> | null;
  groups?: FindingGroup[];
  agent_stats?: AgentStat[];
  recent_events?: Record<string, unknown>[];
  triages?: Record<string, unknown>[];
  network?: Record<string, unknown>[];
  beacons?: Record<string, unknown>[];
  collector_online?: boolean;
  min_primitives?: number;
  agents?: { id: string; hostname: string; ip_address?: string; status: string }[];
  active_agent_id?: string | null;
  session_rel?: string | null;
}

export interface Ruleset {
  alloc: string[];
  write: string[];
  exec: string[];
  min_primitives: number;
  congruence: boolean;
  temporal: boolean;
  capture: number;
  net_watch: number;
  auto_attach: boolean;
  beacon: boolean;
  folders: string[];
  allowlist: string[];
  sev: { cond: string; s: string }[];
  chains: Record<string, unknown>[];
  score: {
    weights: { label: string; pts: number }[];
    crit: number;
    high: number;
    med: number;
  };
  auto_kill?: boolean;
  auto_kill_min_severity?: string;
}
