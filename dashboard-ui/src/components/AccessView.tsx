import { FormEvent, useEffect, useState } from "react";
import { api } from "../api/client";

const ROLES = ["Admin", "Analyst", "Viewer"];
const PERMS = ["dashboards", "triage", "export", "report", "del", "rules", "access", "kill"];

type NewMember = {
  name: string;
  email: string;
  role: string;
  password: string;
  confirmPassword: string;
};

const EMPTY_MEMBER: NewMember = {
  name: "",
  email: "",
  role: "Analyst",
  password: "",
  confirmPassword: "",
};

function parseError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  try {
    const payload = JSON.parse(raw) as { detail?: unknown };
    if (typeof payload.detail === "string") return payload.detail;
    if (Array.isArray(payload.detail)) {
      return payload.detail.map((item) => String((item as { msg?: string }).msg || item)).join(", ");
    }
  } catch {
    // keep raw message
  }
  return raw || "Request failed";
}

export function AccessView({
  currentEmail,
  onToast,
}: {
  currentEmail: string;
  onToast: (message: string) => void;
}) {
  const [team, setTeam] = useState<{ email: string; name: string; role: string; initial: string }[]>([]);
  const [matrix, setMatrix] = useState<Record<string, Record<string, boolean>>>({});
  const [newMember, setNewMember] = useState<NewMember>(EMPTY_MEMBER);
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  async function load() {
    const [teamPayload, permPayload] = await Promise.all([api.team(), api.permissions()]);
    setTeam(teamPayload.team || []);
    setMatrix(permPayload.matrix || {});
  }

  useEffect(() => {
    load().catch((err) => onToast(parseError(err)));
  }, [onToast]);

  async function toggle(role: string, perm: string) {
    const next = { ...matrix, [role]: { ...matrix[role], [perm]: !matrix[role]?.[perm] } };
    setMatrix(next);
    try {
      await api.savePermissions(next);
      onToast("Permissions updated");
    } catch (err) {
      onToast(parseError(err));
      load().catch(() => undefined);
    }
  }

  async function handleCreate(event: FormEvent) {
    event.preventDefault();
    setFormError("");

    const name = newMember.name.trim();
    const email = newMember.email.trim().toLowerCase();
    const password = newMember.password;
    const confirmPassword = newMember.confirmPassword;

    if (!name || !email) {
      setFormError("Name and email are required.");
      return;
    }
    if (password.length < 4) {
      setFormError("Password must be at least 4 characters.");
      return;
    }
    if (password !== confirmPassword) {
      setFormError("Password confirmation does not match.");
      return;
    }

    setSaving(true);
    try {
      await api.addMember({
        name,
        email,
        role: newMember.role,
        password,
      });
      setNewMember(EMPTY_MEMBER);
      await load();
      onToast(`Created account ${email}`);
    } catch (err) {
      setFormError(parseError(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div style={{ maxWidth: 940, display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span
          className="mono"
          style={{
            fontSize: 11,
            color: "var(--accentText)",
            background: "var(--navActive)",
            border: "1px solid var(--navBorder)",
            padding: "4px 11px",
            borderRadius: 8,
          }}
        >
          ADMIN ONLY
        </span>
        <span style={{ fontSize: 13, color: "var(--muted)" }}>Create accounts and manage role permissions.</span>
      </div>

      <div className="card">
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16, marginBottom: 4 }}>Team members</div>
        <div style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 14 }}>
          New users sign in with the email and password you set here.
        </div>

        {team.map((member) => {
          const isSelf = member.email.toLowerCase() === currentEmail.toLowerCase();
          return (
            <div
              key={member.email}
              className="table-row"
              style={{
                gridTemplateColumns: "34px 1fr 1.2fr 120px 40px",
                alignItems: "center",
                gap: 12,
                marginBottom: 8,
              }}
            >
              <span
                style={{
                  width: 34,
                  height: 34,
                  borderRadius: 10,
                  background: "var(--brand)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#fff",
                  fontWeight: 700,
                  fontSize: 13,
                }}
              >
                {member.initial}
              </span>
              <span>{member.name}</span>
              <span className="mono">{member.email}</span>
              <select
                value={member.role}
                disabled={isSelf}
                onChange={async (e) => {
                  try {
                    await api.updateMemberRole(member.email, e.target.value);
                    await load();
                    onToast(`Updated role for ${member.email}`);
                  } catch (err) {
                    onToast(parseError(err));
                  }
                }}
              >
                {ROLES.map((role) => (
                  <option key={role} value={role}>
                    {role}
                  </option>
                ))}
              </select>
              <button
                type="button"
                className="btn-ghost"
                disabled={isSelf}
                title={isSelf ? "Cannot remove your own account" : "Remove member"}
                onClick={async () => {
                  try {
                    await api.removeMember(member.email);
                    await load();
                    onToast(`Removed ${member.email}`);
                  } catch (err) {
                    onToast(parseError(err));
                  }
                }}
              >
                ×
              </button>
            </div>
          );
        })}

        <form
          onSubmit={handleCreate}
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
            gap: 10,
            marginTop: 16,
            paddingTop: 16,
            borderTop: "1px solid var(--border)",
          }}
        >
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Full name</label>
            <input
              className="field-input"
              style={{ margin: "6px 0 0" }}
              placeholder="Lab Analyst"
              value={newMember.name}
              onChange={(e) => setNewMember({ ...newMember, name: e.target.value })}
            />
          </div>
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Email</label>
            <input
              className="field-input mono"
              style={{ margin: "6px 0 0" }}
              placeholder="analyst@lab"
              value={newMember.email}
              onChange={(e) => setNewMember({ ...newMember, email: e.target.value })}
            />
          </div>
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Role</label>
            <select
              style={{ width: "100%", marginTop: 6 }}
              value={newMember.role}
              onChange={(e) => setNewMember({ ...newMember, role: e.target.value })}
            >
              {ROLES.map((role) => (
                <option key={role} value={role}>
                  {role}
                </option>
              ))}
            </select>
          </div>
          <div />
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Password</label>
            <input
              className="field-input"
              style={{ margin: "6px 0 0" }}
              type="password"
              placeholder="Initial password"
              value={newMember.password}
              onChange={(e) => setNewMember({ ...newMember, password: e.target.value })}
            />
          </div>
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Confirm password</label>
            <input
              className="field-input"
              style={{ margin: "6px 0 0" }}
              type="password"
              placeholder="Repeat password"
              value={newMember.confirmPassword}
              onChange={(e) => setNewMember({ ...newMember, confirmPassword: e.target.value })}
            />
          </div>
          {formError ? (
            <div style={{ gridColumn: "1 / -1", color: "var(--sev-critical)", fontSize: 13 }}>{formError}</div>
          ) : null}
          <div style={{ gridColumn: "1 / -1", display: "flex", justifyContent: "flex-end" }}>
            <button type="submit" className="btn-brand" disabled={saving}>
              {saving ? "Creating…" : "Create account"}
            </button>
          </div>
        </form>
      </div>

      <div className="card">
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Role permissions</div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
            <thead>
              <tr>
                <th style={{ textAlign: "left", padding: 8 }}>Capability</th>
                {ROLES.map((role) => (
                  <th key={role} style={{ padding: 8 }}>
                    {role}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {PERMS.map((perm) => (
                <tr key={perm}>
                  <td style={{ padding: 8, color: "var(--muted)" }}>{perm}</td>
                  {ROLES.map((role) => {
                    const allowed = Boolean(matrix[role]?.[perm]);
                    return (
                      <td key={role} style={{ textAlign: "center", padding: 8 }}>
                        <button
                          type="button"
                          className="btn-ghost"
                          style={{
                            color: allowed ? "var(--op-alloc)" : "var(--dim)",
                            minWidth: 42,
                          }}
                          onClick={() => toggle(role, perm)}
                        >
                          {allowed ? "✓" : "—"}
                        </button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
