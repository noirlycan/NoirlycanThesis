import type { FindingGroup, OverviewData, Ruleset, User } from "../types";

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");
const TOKEN_KEY = "noirlycan.console.token";

let memoryToken: string | null = null;
let onUnauthorized: (() => void) | null = null;

export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

export function getToken(): string | null {
  if (memoryToken) return memoryToken;
  const stored = localStorage.getItem(TOKEN_KEY);
  memoryToken = stored;
  return stored;
}

export function setToken(token: string | null) {
  memoryToken = token;
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export function registerUnauthorizedHandler(handler: (() => void) | null) {
  onUnauthorized = handler;
}

export class AuthError extends Error {
  constructor(message = "Not authenticated") {
    super(message);
    this.name = "AuthError";
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const response = await fetch(apiUrl(path), { ...init, headers });

  if (response.status === 401) {
    // Only clear the session if this response matches the token we sent (avoids stale me() races).
    if (token && getToken() === token) {
      setToken(null);
      if (!path.startsWith("/api/auth/login")) {
        onUnauthorized?.();
      }
    }
    throw new AuthError(await response.text());
  }

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || response.statusText);
  }

  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json() as Promise<T>;
  }
  return response.text() as Promise<T>;
}

export const api = {
  async login(email: string, password: string) {
    const result = await request<{ ok: boolean; token?: string; user?: unknown; permissions?: Record<string, boolean>; error?: string }>(
      "/api/auth/login",
      { method: "POST", body: JSON.stringify({ email, password }) },
    );
    if (result.ok && result.token) {
      setToken(result.token);
    }
    return result;
  },
  me() {
    return request<{ user: unknown; permissions: Record<string, boolean> }>("/api/auth/me");
  },
  overview(session?: string, agentId?: string) {
    const params = new URLSearchParams();
    if (session) params.set("session", session);
    if (agentId) params.set("agent_id", agentId);
    const q = params.toString() ? `?${params.toString()}` : "";
    return request<OverviewData>(`/api/overview${q}`);
  },
  findings(session?: string, agentId?: string) {
    const params = new URLSearchParams();
    if (session) params.set("session", session);
    if (agentId) params.set("agent_id", agentId);
    const q = params.toString() ? `?${params.toString()}` : "";
    return request<{ groups: FindingGroup[] }>(`/api/findings${q}`);
  },
  deleteFinding(key: string) {
    return request<{ ok: boolean }>(`/api/findings/${encodeURIComponent(key)}`, { method: "DELETE" });
  },
  rules() {
    return request<{ rules: Ruleset }>("/api/rules");
  },
  saveRules(rules: Ruleset) {
    return request<{ ok: boolean; rules: Ruleset }>("/api/rules", {
      method: "PUT",
      body: JSON.stringify({ rules }),
    });
  },
  resetRules() {
    return request<{ rules: Ruleset }>("/api/rules/reset", { method: "POST" });
  },
  agents() {
    return request<{
      server: { host: string; port: number; token: string };
      agents: Record<string, unknown>[];
      commands: { run: string; spawn: string };
      toml: string;
      auto_kill_min_severity?: string;
    }>("/api/agents");
  },
  saveServer(host: string, port: number) {
    return request("/api/agents/server", { method: "PUT", body: JSON.stringify({ host, port }) });
  },
  regenerateToken() {
    return request<{ token: string }>("/api/agents/server/regenerate-token", { method: "POST" });
  },
  kill(agentId: string, pid: number, image?: string) {
    return request<{ ok: boolean; message: string }>(`/api/agents/${encodeURIComponent(agentId)}/kill`, {
      method: "POST",
      body: JSON.stringify({ pid, image }),
    });
  },
  team() {
    return request<{ team: { email: string; name: string; role: string; initial: string }[] }>("/api/users/team");
  },
  permissions() {
    return request<{ matrix: Record<string, Record<string, boolean>> }>("/api/users/permissions");
  },
  savePermissions(matrix: Record<string, Record<string, boolean>>) {
    return request("/api/users/permissions", { method: "PUT", body: JSON.stringify({ matrix }) });
  },
  updateProfile(body: { display_name?: string; current_password?: string; new_password?: string }) {
    return request<{ ok: boolean; user: User }>("/api/users/profile", { method: "PUT", body: JSON.stringify(body) });
  },
  exportSession(name: string) {
    return downloadBlob(`/api/sessions/${encodeURIComponent(name)}/export`, `${name}`);
  },
  downloadReport(findingKey: string) {
    return downloadBlob(`/api/reports/finding/${encodeURIComponent(findingKey)}.md`, `finding-${findingKey}.md`);
  },
  downloadAllReport(session?: string) {
    const q = session ? `?session=${encodeURIComponent(session)}` : "";
    return downloadBlob(`/api/reports/findings.md${q}`, "noirlycan-report.md");
  },
  saveAutoKillPolicy(min_severity: string) {
    return request("/api/agents/policy/auto-kill", {
      method: "PUT",
      body: JSON.stringify({ min_severity }),
    });
  },
  setAgentAutoKill(agentId: string, enabled: boolean) {
    return request(`/api/agents/${encodeURIComponent(agentId)}/auto-kill`, {
      method: "POST",
      body: JSON.stringify({ enabled }),
    });
  },
  renameAgent(agentId: string, displayName: string) {
    return request<{ ok: boolean; display_name: string }>(`/api/agents/${encodeURIComponent(agentId)}`, {
      method: "PATCH",
      body: JSON.stringify({ display_name: displayName }),
    });
  },
  deleteAgent(agentId: string) {
    return request<{ ok: boolean }>(`/api/agents/${encodeURIComponent(agentId)}`, { method: "DELETE" });
  },
  registerAgent(agentId: string, displayName = "") {
    return request<{ ok: boolean; agent: Record<string, unknown> }>("/api/agents/register", {
      method: "POST",
      body: JSON.stringify({ agent_id: agentId, display_name: displayName }),
    });
  },
  regenerateAgentToken(agentId: string) {
    return request<{ ok: boolean; token: string; agent: Record<string, unknown> }>(
      `/api/agents/${encodeURIComponent(agentId)}/regenerate-token`,
      { method: "POST" },
    );
  },
  addMember(body: { name: string; email: string; role: string; password: string }) {
    return request("/api/users/team", { method: "POST", body: JSON.stringify(body) });
  },
  removeMember(email: string) {
    return request(`/api/users/team/${encodeURIComponent(email)}`, { method: "DELETE" });
  },
  updateMemberRole(email: string, role: string) {
    return request(`/api/users/team/${encodeURIComponent(email)}/role`, {
      method: "PUT",
      body: JSON.stringify({ role }),
    });
  },
};

async function downloadBlob(path: string, filename: string) {
  const token = getToken();
  const response = await fetch(apiUrl(path), {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (response.status === 401) {
    if (token && getToken() === token) {
      setToken(null);
      onUnauthorized?.();
    }
    throw new AuthError(await response.text());
  }
  if (!response.ok) throw new Error(await response.text());
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
