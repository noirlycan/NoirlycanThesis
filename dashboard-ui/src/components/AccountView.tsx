import { FormEvent, useState } from "react";
import { api } from "../api/client";
import type { User } from "../types";

function parseError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  try {
    const payload = JSON.parse(raw) as { detail?: unknown };
    if (typeof payload.detail === "string") return payload.detail;
  } catch {
    // ignore
  }
  return raw || "Save failed";
}

export function AccountView({
  user,
  onUserChange,
  onToast,
}: {
  user: User;
  onUserChange: (user: User) => void;
  onToast: (message: string) => void;
}) {
  const [displayName, setDisplayName] = useState(user.name);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [savedFlash, setSavedFlash] = useState(false);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  async function saveProfile(event: FormEvent) {
    event.preventDefault();
    setError("");
    if (newPassword && newPassword !== confirmPassword) {
      setError("Password confirmation does not match.");
      return;
    }
    if (newPassword && newPassword.length < 4) {
      setError("New password must be at least 4 characters.");
      return;
    }

    setSaving(true);
    try {
      const payload = await api.updateProfile({
        display_name: displayName.trim() || user.name,
        current_password: newPassword ? currentPassword : undefined,
        new_password: newPassword || undefined,
      });
      const updated = payload.user as User;
      onUserChange({
        ...user,
        name: String(updated.name || displayName),
        initial: String(updated.initial || displayName[0]?.toUpperCase() || user.initial),
      });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setSavedFlash(true);
      onToast("Profile saved");
      window.setTimeout(() => setSavedFlash(false), 1800);
    } catch (err) {
      setError(parseError(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div style={{ maxWidth: 720, display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="card">
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16, marginBottom: 20 }}>Profile</div>
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 22 }}>
          <div
            style={{
              width: 60,
              height: 60,
              borderRadius: 16,
              background: "var(--brand)",
              boxShadow: "var(--brandShadow)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "#fff",
              fontFamily: "Space Grotesk",
              fontWeight: 700,
              fontSize: 26,
              flex: "none",
            }}
          >
            {user.initial}
          </div>
          <div style={{ fontSize: 12.5, color: "var(--dim)" }}>
            Avatar uses your display-name initial.
            <br />
            Role is granted by an admin in Access.
          </div>
          <span
            className="mono"
            style={{
              marginLeft: "auto",
              fontSize: 11,
              color: "var(--accentText)",
              background: "var(--navActive)",
              border: "1px solid var(--navBorder)",
              padding: "5px 12px",
              borderRadius: 8,
            }}
          >
            {user.role}
          </span>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Display name</label>
            <input
              className="field-input"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </div>
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Email</label>
            <input className="field-input mono" value={user.email} readOnly style={{ opacity: 0.75 }} />
          </div>
        </div>
      </div>

      <form className="card" onSubmit={saveProfile}>
        <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16, marginBottom: 20 }}>Change password</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Current</label>
            <input
              className="field-input"
              type="password"
              placeholder="••••••"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
            />
          </div>
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>New</label>
            <input
              className="field-input"
              type="password"
              placeholder="••••••"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </div>
          <div>
            <label style={{ fontSize: 12, color: "var(--muted)" }}>Confirm</label>
            <input
              className="field-input"
              type="password"
              placeholder="••••••"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>
        </div>
        {error ? <div style={{ color: "var(--sev-critical)", fontSize: 13, marginTop: 4 }}>{error}</div> : null}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 14,
            marginTop: 20,
            paddingTop: 16,
            borderTop: "1px solid var(--border)",
          }}
        >
          {savedFlash ? (
            <span style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "var(--sev-low)" }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--sev-low)" }} />
              Profile saved
            </span>
          ) : null}
          <button type="submit" className="btn-brand" style={{ marginLeft: "auto" }} disabled={saving}>
            {saving ? "Saving…" : "Save changes"}
          </button>
        </div>
      </form>
    </div>
  );
}
