import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, getToken, registerUnauthorizedHandler, setToken } from "./api/client";
import { AccessView } from "./components/AccessView";
import { AccountView } from "./components/AccountView";
import { ActivityView } from "./components/ActivityView";
import { AgentsView } from "./components/AgentsView";
import { AgentBadge, agentLabel } from "./components/AgentBadge";
import { ApiChainList, TagChips } from "./components/FindingBits";
import { FindingModal } from "./components/FindingModal";
import { NetworkView } from "./components/NetworkView";
import { RulesView } from "./components/RulesView";
import { useLiveSocket } from "./hooks/useLiveSocket";
import { collectTags, flowLabel, groupTargetLabel, primitiveBarHeight, severityDonut } from "./lib/finding-ui";
import { filterFindingGroups, filterRecords, matchesSearch, normalizeSearch } from "./lib/search";
import { applyTheme, readStoredTheme, type Theme } from "./lib/theme";
import type { FindingGroup, FindingMember, OverviewData, Permissions, Ruleset, TabId, User } from "./types";

const TAB_META: Record<TabId, { title: string; sub: string; perm?: string }> = {
  overview: { title: "Overview", sub: "Fleet KPIs across all connected agents" },
  findings: { title: "Findings", sub: "Grouped by target process / injection chain" },
  activity: { title: "Activity", sub: "Live event stream and file drops" },
  network: { title: "Network", sub: "Post-finding beacon watch and connections" },
  rules: { title: "Rules", sub: "Detection primitives, chains, and scoring", perm: "rules" },
  agents: { title: "Agents", sub: "Deploy commands and connected workstations", perm: "access" },
  account: { title: "Account", sub: "Profile and password" },
  access: { title: "Access", sub: "Team members and role permissions", perm: "access" },
};

function can(perms: Permissions, key?: string) {
  return !key || Boolean(perms[key]);
}

function SevBadge({ severity }: { severity: string }) {
  const sev = severity.toUpperCase();
  return (
    <span
      className={`mono sev-${sev}`}
      style={{
        fontSize: 11,
        fontWeight: 600,
        background: sev === "CRITICAL" ? "#e5484d" : "var(--panel2)",
        color: sev === "CRITICAL" ? "#fff" : undefined,
        padding: "4px 11px",
        borderRadius: 8,
        border: "1px solid var(--border)",
      }}
    >
      {sev}
    </span>
  );
}

function LoginScreen({ onLogin }: { onLogin: (user: User, perms: Permissions, token: string) => void }) {
  const [email, setEmail] = useState("admin@lab");
  const [password, setPassword] = useState("admin");
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    const result = await api.login(email.trim(), password);
    if (!result.ok || !result.token || !result.user) {
      setError(result.error || "Login failed");
      return;
    }
    onLogin(result.user as User, result.permissions || {}, result.token);
  }

  async function quick(role: "admin" | "analyst" | "viewer") {
    const creds = {
      admin: ["admin@lab", "admin"],
      analyst: ["analyst@lab", "analyst"],
      viewer: ["viewer@lab", "viewer"],
    }[role];
    setEmail(creds[0]);
    setPassword(creds[1]);
    const result = await api.login(creds[0], creds[1]);
    if (result.ok && result.token && result.user) {
      onLogin(result.user as User, result.permissions || {}, result.token);
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 26 }}>
          <div
            style={{
              width: 40,
              height: 40,
              borderRadius: 12,
              background: "var(--brand)",
              boxShadow: "var(--brandShadow)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontFamily: "Space Grotesk",
              fontWeight: 700,
              color: "#fff",
              fontSize: 20,
            }}
          >
            N
          </div>
          <div>
            <div style={{ fontFamily: "Space Grotesk", fontWeight: 700, fontSize: 18 }}>Noirlycan</div>
            <div className="mono" style={{ fontSize: 10, color: "var(--dim)", letterSpacing: ".1em" }}>
              TELEMETRY CONSOLE
            </div>
          </div>
        </div>
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16, marginBottom: 4 }}>Sign in</div>
        <div style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 20 }}>Đăng nhập để truy cập bảng điều khiển.</div>
        <label style={{ fontSize: 12, color: "var(--muted)" }}>Email</label>
        <input className="field-input" value={email} onChange={(e) => setEmail(e.target.value)} />
        <label style={{ fontSize: 12, color: "var(--muted)" }}>Password</label>
        <input
          className="field-input"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {error ? <div style={{ color: "#e5484d", fontSize: 12, marginBottom: 8 }}>{error}</div> : null}
        <button type="submit" className="btn-brand" style={{ width: "100%", marginTop: 6 }}>
          Sign in
        </button>
        <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "20px 0 14px", color: "var(--dim)", fontSize: 11, letterSpacing: ".08em" }}>
          <div style={{ flex: 1, height: 1, background: "var(--border)" }} />
          QUICK DEMO
          <div style={{ flex: 1, height: 1, background: "var(--border)" }} />
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {(["admin", "analyst", "viewer"] as const).map((role) => (
            <button key={role} type="button" className="btn-ghost" style={{ flex: 1 }} onClick={() => quick(role)}>
              {role[0].toUpperCase() + role.slice(1)}
            </button>
          ))}
        </div>
      </form>
    </div>
  );
}

function OverviewView({
  data,
  searchQuery,
  onNavigate,
  onOpenFinding,
  canKill,
  onKill,
  killed,
}: {
  data: OverviewData;
  searchQuery: string;
  onNavigate: (tab: TabId) => void;
  onOpenFinding: (member: FindingMember) => void;
  canKill: boolean;
  onKill: (pid: number, image?: string, killAgentId?: string, actorPid?: number) => void;
  killed: Set<number>;
}) {
  const kpis = data.kpis || { findings: 0, critical: 0, injection_chains: 0, file_drops: 0, beacons: 0, agents: 0 };
  const critical = data.critical_finding as Record<string, unknown> | null | undefined;
  const showCritical = !normalizeSearch(searchQuery) || matchesSearch(searchQuery, critical);
  const pid = critical?.target_pid as number | undefined;
  const criticalActorPid = Number(critical?.actor_pid || 0) || undefined;
  const isKilled = pid ? killed.has(pid) : false;
  const criticalAgentId = String(critical?.agent_id || "");
  const criticalHostname = agentLabel(critical);
  const severityCounts = data.severity_counts || {};
  const totalFindings = kpis.findings || Object.values(severityCounts).reduce((sum, n) => sum + Number(n), 0);
  const primitiveCounts = data.primitive_kind_counts || {};
  const agentStats = data.agent_stats || [];
  const maxAgentFindings = Math.max(...agentStats.map((row) => row.findings), 1);
  const recentMembers = (data.groups || [])
    .flatMap((group) => group.members.map((member) => ({ group, member })))
    .sort((a, b) => String(b.member.time || "").localeCompare(String(a.member.time || "")))
    .slice(0, 8);
  const primitiveRows = [
    { key: "allocate", label: "Allocate", color: "var(--op-alloc)" },
    { key: "write", label: "Write", color: "var(--op-write)" },
    { key: "execute", label: "Execute", color: "var(--op-exec)" },
  ].map((row) => ({
    ...row,
    count: Number(primitiveCounts[row.key] ?? primitiveCounts[row.label] ?? 0),
  }));
  const maxPrimitive = Math.max(...primitiveRows.map((row) => row.count), 1);

  return (
    <>
      <div className="kpi-grid">
        {[
          ["Agents", kpis.agents ?? agentStats.length, "agents", false],
          ["Findings", kpis.findings, "findings", false],
          ["Critical", kpis.critical, "findings", true],
          ["Injection chains", kpis.injection_chains, "findings", false],
          ["File drops", kpis.file_drops, "activity", false],
          ["Beacons", kpis.beacons, "network", false],
        ].map(([label, value, tab, crit]) => (
          <div
            key={String(label)}
            className={`card kpi-card ${crit ? "crit-banner" : ""}`}
            onClick={() => onNavigate(tab as TabId)}
          >
            <div style={{ fontSize: 12, color: crit ? "#e5484d" : "var(--muted)" }}>{label}</div>
            <div className="kpi-num" style={{ color: crit ? "#e5484d" : undefined }}>
              {value as number}
            </div>
          </div>
        ))}
      </div>

      <div className="grid-2">
        <div className={`card crit-banner`}>
          <div className="crit-sweep">
            <div />
          </div>
          {critical && showCritical ? (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
                <SevBadge severity="CRITICAL" />
                <AgentBadge agentId={criticalAgentId} hostname={criticalHostname} />
                <span style={{ fontWeight: 700, fontSize: 17 }}>
                  {(critical.title as string) || "Probable process injection chain"}
                </span>
                <div style={{ marginLeft: "auto", display: "flex", gap: 12, alignItems: "center" }}>
                  <span className="mono" style={{ fontSize: 11, color: "var(--dim)" }}>
                    {String(critical.timestamp || "").slice(11, 19)}
                  </span>
                  {isKilled ? (
                    <span className="mono" style={{ fontSize: 11, color: "#e5484d", border: "1px solid #e5484d55", borderRadius: 8, padding: "5px 10px" }}>
                      TERMINATED
                    </span>
                  ) : null}
                  {canKill && pid && !isKilled ? (
                    <button
                      type="button"
                      className="btn-brand"
                      style={{ background: "#e5484d", boxShadow: "none", padding: "6px 14px", fontSize: 12 }}
                      onClick={() => onKill(pid, String(critical.target_image || ""), criticalAgentId || undefined, criticalActorPid)}
                    >
                      Kill process
                    </button>
                  ) : null}
                </div>
              </div>
              <div className="mono" style={{ background: "var(--hole)", border: "1px solid var(--border)", borderRadius: 12, padding: "14px 16px", marginBottom: 12 }}>
                {flowLabel(critical)}
              </div>
              <div style={{ marginBottom: 14 }}>
                <TagChips tags={collectTags(critical)} />
              </div>
              <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 8, letterSpacing: ".06em" }}>API CHAIN</div>
              <ApiChainList finding={critical} />
            </>
          ) : (
            <div style={{ color: "var(--dim)" }}>
              {normalizeSearch(searchQuery) ? "No critical finding matches search." : "No critical finding in active session."}
            </div>
          )}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <div className="card">
            <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 18 }}>Severity mix</div>
            <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
              <div style={{ position: "relative", width: 104, height: 104, flex: "none" }}>
                <div
                  style={{
                    width: "100%",
                    height: "100%",
                    borderRadius: "50%",
                    background: severityDonut(severityCounts, totalFindings),
                  }}
                />
                <div
                  style={{
                    position: "absolute",
                    inset: 18,
                    borderRadius: "50%",
                    background: "var(--panel)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontFamily: "Space Grotesk",
                    fontWeight: 700,
                    fontSize: 14,
                  }}
                >
                  {totalFindings}
                </div>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 9, flex: 1 }}>
                {Object.entries(severityCounts).map(([sev, count]) => (
                  <div key={sev} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span className={`sev-${sev.toUpperCase()}`}>{sev.toUpperCase()}</span>
                    <span className="mono" style={{ marginLeft: "auto", color: "var(--muted)" }}>
                      {count}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="card">
            <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 4 }}>Injection primitives</div>
            <div style={{ fontSize: 11.5, color: "var(--dim)", marginBottom: 18 }}>
              ≥{data.min_primitives || 2} of 3 observed → injection
            </div>
            <div style={{ display: "flex", gap: 16, alignItems: "flex-end" }}>
              {primitiveRows.map((row) => (
                <div
                  key={row.key}
                  style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}
                >
                  <div
                    style={{
                      width: "100%",
                      height: 104,
                      display: "flex",
                      alignItems: "flex-end",
                    }}
                  >
                    <div
                      style={{
                        width: "100%",
                        height: primitiveBarHeight(row.count, maxPrimitive),
                        borderRadius: "9px 9px 4px 4px",
                        background: `linear-gradient(180deg, ${row.color}, transparent)`,
                      }}
                    />
                  </div>
                  <div style={{ fontSize: 11, color: "var(--muted)" }}>{row.label}</div>
                  <div className="mono" style={{ fontSize: 11, color: "var(--dim)" }}>
                    {row.count}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {agentStats.length ? (
        <div className="grid-2" style={{ marginTop: 20 }}>
          <div className="card">
            <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 4 }}>Findings by agent</div>
            <div style={{ fontSize: 11.5, color: "var(--dim)", marginBottom: 18 }}>
              Fleet-wide counts · click Findings tab and pick an agent to drill down
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {agentStats.map((row) => (
                <div key={row.agent_id}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                    <div>
                      <AgentBadge agentId={row.agent_id} hostname={row.hostname} />
                      {row.ip_address ? (
                        <div className="mono" style={{ fontSize: 10, color: "var(--dim)", marginTop: 4 }}>
                          {String(row.ip_address)}
                        </div>
                      ) : null}
                    </div>
                    <span className="mono" style={{ fontSize: 11, color: "var(--dim)", marginLeft: "auto" }}>
                      {row.findings} findings · {row.critical} critical
                    </span>
                  </div>
                  <div style={{ height: 10, background: "var(--hole)", borderRadius: 999, overflow: "hidden" }}>
                    <div
                      style={{
                        width: `${Math.max(8, Math.round((row.findings / maxAgentFindings) * 100))}%`,
                        height: "100%",
                        borderRadius: 999,
                        background: row.critical > 0
                          ? "linear-gradient(90deg, #e5484d, var(--accent))"
                          : "linear-gradient(90deg, var(--accent), var(--accent2))",
                      }}
                    />
                  </div>
                  <div style={{ display: "flex", gap: 12, marginTop: 6, fontSize: 11, color: "var(--dim)" }}>
                    <span>{row.injection_chains} chains</span>
                    <span>{row.file_drops} drops</span>
                    <span>{row.beacons} beacons</span>
                    <span style={{ marginLeft: "auto", textTransform: "capitalize" }}>{row.status || "offline"}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 4 }}>Recent findings · all agents</div>
            <div style={{ fontSize: 11.5, color: "var(--dim)", marginBottom: 14 }}>
              Click a row to inspect which agent raised it
            </div>
            {recentMembers.length ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {recentMembers.map(({ group, member }) => (
                  <div
                    key={member.key}
                    className="finding-row"
                    style={{ gridTemplateColumns: "auto auto 1fr auto auto", cursor: "pointer" }}
                    onClick={() => onOpenFinding(member)}
                  >
                    <AgentBadge agentId={member.agent_id || group.agent_id} hostname={member.hostname || group.hostname} />
                    <SevBadge severity={member.severity} />
                    <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {member.title}
                    </span>
                    <span className="mono" style={{ fontSize: 11, color: "var(--dim)" }}>
                      {group.source} → {group.victim}
                    </span>
                    <span className="mono" style={{ fontSize: 11, color: "var(--dim)" }}>
                      {String(member.time || "").slice(11, 19)}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ color: "var(--dim)" }}>No findings across connected agents.</div>
            )}
          </div>
        </div>
      ) : null}
    </>
  );
}

function FindingsView({
  groups,
  searchQuery,
  canDel,
  canReport,
  canKill,
  killed,
  agentScope,
  onOpen,
  onDelete,
  onKill,
}: {
  groups: FindingGroup[];
  searchQuery: string;
  canDel: boolean;
  canReport: boolean;
  canKill: boolean;
  killed: Set<number>;
  agentScope?: { id: string; hostname: string } | null;
  onOpen: (member: FindingMember) => void;
  onDelete: (key: string) => void;
  onKill: (pid: number, image?: string, killAgentId?: string, actorPid?: number) => void;
}) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ fontSize: 13, color: "var(--dim)" }}>
          Gộp theo process đích · xếp theo thứ tự chain
          {agentScope ? (
            <span className="mono" style={{ marginLeft: 10, color: "var(--muted)" }}>
              · {agentScope.hostname}
            </span>
          ) : null}
        </div>
        {canReport ? (
          <button type="button" className="btn-ghost" style={{ marginLeft: "auto" }} onClick={() => api.downloadAllReport()}>
            Export report (.md)
          </button>
        ) : null}
      </div>
      {groups.map((group) => {
        const groupPid = group.vpid != null ? Number(group.vpid) : 0;
        const groupKilled = groupPid > 0 && killed.has(groupPid);
        const groupActorPid = Number(group.members?.[0]?.finding?.actor_pid || 0) || undefined;
        return (
        <div key={group.key} className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="group-header">
            <div className="group-header-top">
              <SevBadge severity={group.top_severity} />
              <div className="group-header-body">
                <div className="mono" style={{ fontSize: 13.5, fontWeight: 600, lineHeight: 1.45 }}>
                  <span style={{ color: "var(--muted)" }}>{group.source}</span> ──▶{" "}
                  <span style={{ color: "#ec7b1a" }}>{groupTargetLabel(group.victim, group.vpid)}</span>
                </div>
                <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 4, lineHeight: 1.45 }}>{group.summary}</div>
              </div>
              <div className="group-header-actions">
                {groupKilled ? (
                  <span className="mono" style={{ fontSize: 11, color: "#e5484d", whiteSpace: "nowrap" }}>
                    TERMINATED
                  </span>
                ) : null}
                {canKill && groupPid > 0 && !groupKilled ? (
                  <button
                    type="button"
                    className="btn-brand"
                    style={{ background: "#e5484d", boxShadow: "none", padding: "6px 12px", fontSize: 12, whiteSpace: "nowrap" }}
                    onClick={() => onKill(groupPid, group.victim, group.agent_id, groupActorPid)}
                  >
                    Kill process
                  </button>
                ) : null}
                <span className="badge">{group.count}</span>
              </div>
            </div>
            {(group.tags || []).length ? (
              <div className="group-header-tags">
                <TagChips tags={group.tags || []} />
              </div>
            ) : null}
          </div>
          {group.members.map((member) => (
            <div
              key={member.key}
              className="finding-row"
              onClick={() => onOpen(member)}
            >
              <span className="mono" style={{ color: "var(--dim)" }}>
                #{member.step}
              </span>
              <SevBadge severity={member.severity} />
              <span style={{ fontWeight: 600, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {member.title}
              </span>
              <span className="mono" style={{ color: "var(--muted)", fontSize: 12 }}>{String(member.primitives ?? "—")}</span>
              <span className="mono" style={{ fontSize: 11, color: "var(--dim)" }}>
                {String(member.time || "").slice(11, 19)}
              </span>
              {canDel ? (
                <button
                  type="button"
                  className="btn-ghost"
                  style={{ padding: "2px 8px" }}
                  onClick={(e) => {
                    e.stopPropagation();
                    onDelete(member.key);
                  }}
                >
                  ×
                </button>
              ) : (
                <span />
              )}
            </div>
          ))}
        </div>
        );
      })}
      {!groups.length ? (
        <div className="card">
          {normalizeSearch(searchQuery) ? `No findings match "${searchQuery.trim()}".` : "No findings in active session."}
        </div>
      ) : null}
    </div>
  );
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(() => readStoredTheme());
  const [user, setUser] = useState<User | null>(null);
  const [perms, setPerms] = useState<Permissions>({});
  const [tab, setTab] = useState<TabId>("overview");
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [agentOverview, setAgentOverview] = useState<OverviewData | null>(null);
  const [groups, setGroups] = useState<FindingGroup[]>([]);
  const [rules, setRules] = useState<Ruleset | null>(null);
  const [agentsData, setAgentsData] = useState<Awaited<ReturnType<typeof api.agents>> | null>(null);
  const [modal, setModal] = useState<FindingMember | null>(null);
  const [toast, setToast] = useState("");
  const [killed, setKilled] = useState<Set<number>>(new Set());
  const [searchQuery, setSearchQuery] = useState("");
  const [agentId, setAgentId] = useState("");
  const [authReady, setAuthReady] = useState(() => !getToken());

  const scopedOverview = agentOverview || overview;

  const filteredGroups = useMemo(
    () => filterFindingGroups(groups, searchQuery),
    [groups, searchQuery],
  );
  const filteredEvents = useMemo(
    () => filterRecords((scopedOverview?.recent_events as Record<string, unknown>[] | undefined) || [], searchQuery),
    [scopedOverview?.recent_events, searchQuery],
  );
  const filteredTriages = useMemo(
    () => filterRecords((scopedOverview?.triages as Record<string, unknown>[] | undefined) || [], searchQuery),
    [scopedOverview?.triages, searchQuery],
  );
  const filteredNetwork = useMemo(
    () => filterRecords((scopedOverview?.network as Record<string, unknown>[] | undefined) || [], searchQuery),
    [scopedOverview?.network, searchQuery],
  );
  const searchActive = normalizeSearch(searchQuery).length > 0;

  const navItems = useMemo(
    () =>
      (Object.keys(TAB_META) as TabId[]).filter((id) => can(perms, TAB_META[id].perm)),
    [perms],
  );

  const permsRef = useRef(perms);
  permsRef.current = perms;
  const refreshBusy = useRef(false);

  const refresh = useCallback(async () => {
    if (!getToken() || refreshBusy.current) return;
    refreshBusy.current = true;
    try {
      const selectedAgent = agentId || undefined;
      const [globalOv, agentOv, fd] = await Promise.all([
        api.overview(),
        selectedAgent ? api.overview(undefined, selectedAgent) : Promise.resolve(null),
        api.findings(undefined, selectedAgent),
      ]);
      if (!agentId && globalOv.agents?.[0]?.id) {
        setAgentId(String(globalOv.agents[0].id));
      }
      setOverview(globalOv);
      setAgentOverview(agentOv);
      setGroups(fd.groups || []);
      if (can(permsRef.current, "access")) {
        const agents = await api.agents();
        setAgentsData(agents);
      }
    } catch (err) {
      setToast(String(err));
    } finally {
      refreshBusy.current = false;
    }
  }, [agentId]);

  const live = useLiveSocket(refresh, Boolean(user));

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      setAuthReady(true);
      return;
    }
    let cancelled = false;
    const startedToken = token;
    api
      .me()
      .then((payload) => {
        if (cancelled) return;
        setUser(payload.user as User);
        setPerms(payload.permissions || {});
      })
      .catch(() => {
        if (!cancelled && getToken() === startedToken) {
          setToken(null);
        }
      })
      .finally(() => {
        if (!cancelled) setAuthReady(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!authReady || !user || !getToken()) return;
    void refresh();
  }, [authReady, user, refresh, agentId]);

  useEffect(() => {
    if (!user || !getToken()) return;
    if (tab === "rules" && can(perms, "rules") && rules === null) {
      api.rules()
        .then((payload) => setRules(payload.rules))
        .catch((err) => setToast(String(err)));
    }
  }, [tab, user, perms, rules]);

  useEffect(() => {
    if (!user || live) return;
    const timer = window.setInterval(() => {
      void refresh();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [user, live, refresh]);

  function logout() {
    setToken(null);
    setUser(null);
    setPerms({});
    setOverview(null);
    setAgentOverview(null);
    setGroups([]);
    setRules(null);
    setAgentsData(null);
    setTab("overview");
  }

  useEffect(() => {
    registerUnauthorizedHandler(() => {
      setToast("Session expired — please sign in again.");
      logout();
    });
    return () => registerUnauthorizedHandler(null);
  }, []);

  async function handleKill(pid: number, image?: string, killAgentId?: string, actorPid?: number) {
    try {
      const selectedAgent = killAgentId || agentId || String(agentsData?.agents?.[0]?.id || "local-agent");
      const result = await api.kill(selectedAgent, pid, image, actorPid);
      setKilled((prev) => {
        const next = new Set(prev).add(pid);
        if (actorPid) next.add(actorPid);
        return next;
      });
      setToast(result.message);
    } catch (err) {
      setToast(String(err));
    }
  }

  if (!authReady) {
    return (
      <div className="app-root" style={{ display: "grid", placeItems: "center", minHeight: "100vh", color: "var(--muted)" }}>
        Restoring session…
      </div>
    );
  }

  if (!user) {
    return (
      <div className="app-root">
        <LoginScreen
          onLogin={(nextUser, nextPerms, token) => {
            setToken(token);
            setUser(nextUser);
            setPerms(nextPerms);
            setAuthReady(true);
          }}
        />
      </div>
    );
  }

  const meta = TAB_META[tab];

  return (
    <div className="app-root">
      <div className="shell">
        <aside className="sidebar">
          <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "4px 6px 26px" }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 11,
                background: "var(--brand)",
                boxShadow: "var(--brandShadow)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontFamily: "Space Grotesk",
                fontWeight: 700,
                color: "#fff",
              }}
            >
              N
            </div>
            <div>
              <div style={{ fontFamily: "Space Grotesk", fontWeight: 700, fontSize: 16 }}>Noirlycan</div>
              <div className="mono" style={{ fontSize: 10, color: "var(--dim)", letterSpacing: ".1em" }}>
                TELEMETRY
              </div>
            </div>
          </div>
          <div className="mono" style={{ fontSize: 10, color: "var(--dim)", letterSpacing: ".16em", padding: "0 8px 8px" }}>
            MENU
          </div>
          <nav style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {navItems.map((id) => (
              <div key={id} className={`nav-item ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>
                <span className="nav-dot" />
                {TAB_META[id].title}
                {id === "findings" && overview?.kpis?.findings ? <span className="badge">{overview.kpis.findings}</span> : null}
                {id === "network" && overview?.kpis?.beacons ? <span className="badge">{overview.kpis.beacons}</span> : null}
              </div>
            ))}
          </nav>
          <div className="card" style={{ marginTop: "auto", padding: 16 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5, color: "var(--muted)" }}>
              <span className="pulse-dot" />
              Live capture
            </div>
            <div className="mono" style={{ fontSize: 11, color: "var(--dim)", marginTop: 6 }}>
              Frida + Sysmon · {overview?.collector_online ? "online" : "offline"}
              {overview?.collector_remote && !overview?.collector_local ? " · remote agent" : null}
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "14px 6px 2px" }}>
            <span
              style={{
                width: 30,
                height: 30,
                borderRadius: "50%",
                background: "var(--brand)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#fff",
                fontSize: 12,
                fontWeight: 700,
              }}
            >
              {user.initial}
            </span>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 12.5, fontWeight: 600 }}>{user.name}</div>
              <div className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>
                {user.role}
              </div>
            </div>
            <button type="button" className="btn-ghost" style={{ marginLeft: "auto", fontSize: 11 }} onClick={logout}>
              Log out
            </button>
          </div>
        </aside>

        <main className="main">
          <div className="topbar">
            <div>
              <div className="page-title">{meta.title}</div>
              <div className="page-sub">{meta.sub}</div>
            </div>
            <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
              {tab !== "overview" && (overview?.agents?.length || agentsData?.agents?.length) ? (
                <label className="mono" style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "var(--muted)" }}>
                  Agent
                  <select
                    value={agentId}
                    onChange={(e) => setAgentId(e.target.value)}
                    style={{ minWidth: 160 }}
                  >
                    {(overview?.agents || agentsData?.agents || []).map((agent) => (
                      <option key={String(agent.id)} value={String(agent.id)}>
                        {agentLabel(agent, String(agent.id))}
                      </option>
                    ))}
                  </select>
                </label>
              ) : null}
              {tab === "overview" && overview?.kpis?.agents ? (
                <span className="mono" style={{ fontSize: 12, color: "var(--dim)" }}>
                  {overview.kpis.agents} agents · fleet view
                </span>
              ) : null}
              <label
                className="mono"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  background: "var(--panel2)",
                  border: "1px solid var(--border)",
                  borderRadius: 11,
                  padding: "7px 12px",
                  color: "var(--text)",
                  minWidth: 240,
                }}
              >
                <span style={{ color: "var(--dim)", fontSize: 12 }}>⌕</span>
                <input
                  type="search"
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  placeholder="search pid, api, hash…"
                  style={{
                    border: "none",
                    outline: "none",
                    background: "transparent",
                    color: "inherit",
                    width: "100%",
                    fontSize: 12,
                    fontFamily: "JetBrains Mono, monospace",
                  }}
                />
                {searchActive ? (
                  <button
                    type="button"
                    className="btn-ghost"
                    style={{ padding: "0 4px", fontSize: 14, lineHeight: 1 }}
                    onClick={() => setSearchQuery("")}
                    aria-label="Clear search"
                  >
                    ×
                  </button>
                ) : null}
              </label>
              <div style={{ display: "flex", alignItems: "center", gap: 7, background: "var(--panel2)", border: "1px solid var(--border)", borderRadius: 11, padding: "9px 14px", fontSize: 12.5, color: "var(--muted)" }}>
                <span className="pulse-dot" />
                {live ? "Live WS" : "Auto 5s"}
              </div>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}
              >
                {theme === "dark" ? "☾" : "☀"}
              </button>
              {can(perms, "export") ? (
                <button
                  type="button"
                  className="btn-brand"
                  onClick={() => overview?.session && api.exportSession(overview.session)}
                >
                  Export JSONL
                </button>
              ) : null}
            </div>
          </div>

          <div className="content">
            {searchActive ? (
              <div className="mono" style={{ fontSize: 11, color: "var(--dim)", marginBottom: 12 }}>
                Filter: "{searchQuery.trim()}" · findings {filteredGroups.length}/{groups.length} · events{" "}
                {filteredEvents.length} · drops {filteredTriages.length} · network {filteredNetwork.length}
              </div>
            ) : null}
            {tab === "overview" && overview ? (
              <OverviewView
                data={overview}
                searchQuery={searchQuery}
                onNavigate={setTab}
                onOpenFinding={setModal}
                canKill={can(perms, "kill")}
                onKill={handleKill}
                killed={killed}
              />
            ) : null}
            {tab === "findings" ? (
              <FindingsView
                groups={filteredGroups}
                searchQuery={searchQuery}
                canDel={can(perms, "del")}
                canReport={can(perms, "report")}
                canKill={can(perms, "kill")}
                killed={killed}
                agentScope={
                  agentId
                    ? {
                        id: agentId,
                        hostname: String(
                          (overview?.agents || agentsData?.agents || []).find((a) => String(a.id) === agentId)
                            ?.hostname || agentId,
                        ),
                      }
                    : null
                }
                onOpen={setModal}
                onDelete={async (key) => {
                  await api.deleteFinding(key);
                  refresh();
                }}
                onKill={handleKill}
              />
            ) : null}
            {tab === "activity" ? (
              <ActivityView
                events={(searchActive ? filteredEvents : (scopedOverview?.recent_events as Record<string, unknown>[] | undefined) || [])}
                triages={(searchActive ? filteredTriages : (scopedOverview?.triages as Record<string, unknown>[] | undefined) || [])}
                searchQuery={searchQuery}
                canDel={can(perms, "del")}
                onDelete={async (path, dropKey) => {
                  try {
                    await api.deleteFileDrop(path, dropKey);
                    setToast("File drop removed from history");
                    refresh();
                  } catch (err) {
                    setToast(String(err));
                  }
                }}
              />
            ) : null}
            {tab === "network" ? (
              <NetworkView
                network={(searchActive ? filteredNetwork : (scopedOverview?.network as Record<string, unknown>[] | undefined) || [])}
                beacons={(scopedOverview?.beacons as Record<string, unknown>[] | undefined) || []}
                searchQuery={searchQuery}
              />
            ) : null}
            {tab === "rules" && rules ? (
              <RulesView
                rules={rules}
                onChange={setRules}
                onSave={async () => {
                  const saved = await api.saveRules(rules);
                  setRules(saved.rules);
                  setToast("Rules saved");
                }}
                onReset={async () => {
                  const saved = await api.resetRules();
                  setRules(saved.rules);
                  setToast("Rules reset to defaults");
                }}
              />
            ) : null}
            {tab === "agents" && agentsData ? (
              <AgentsView
                data={{ ...agentsData, auto_kill_min_severity: agentsData.auto_kill_min_severity }}
                onReload={() => api.agents().then(setAgentsData)}
                onToast={setToast}
              />
            ) : null}
            {tab === "account" ? (
              <AccountView
                user={user}
                onUserChange={setUser}
                onToast={setToast}
              />
            ) : null}
            {tab === "access" ? <AccessView currentEmail={user.email} onToast={setToast} /> : null}
          </div>
        </main>
      </div>

      {modal ? (
        <FindingModal
          member={modal}
          canReport={can(perms, "report")}
          canDel={can(perms, "del")}
          canKill={can(perms, "kill")}
          killed={Boolean(modal.finding?.target_pid && killed.has(Number(modal.finding.target_pid)))}
          onClose={() => setModal(null)}
          onDelete={async () => {
            await api.deleteFinding(modal.key);
            setModal(null);
            refresh();
          }}
          onKill={async () => {
            const pid = Number(modal.finding?.target_pid || 0);
            const killAgentId = String(modal.agent_id || modal.finding?.agent_id || "");
            const actorPid = Number(modal.finding?.actor_pid || 0) || undefined;
            if (pid > 0) await handleKill(pid, String(modal.finding?.target_image || ""), killAgentId || undefined, actorPid);
          }}
        />
      ) : null}

      {toast ? (
        <div className="toast" onAnimationEnd={() => window.setTimeout(() => setToast(""), 2500)}>
          {toast}
        </div>
      ) : null}
    </div>
  );
}
