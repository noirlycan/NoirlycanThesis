import type { KillState } from "../types";

/** Kill button that reflects what the agent actually reported, not what was requested. */
export function KillControl({
  state,
  canKill,
  onKill,
}: {
  state: KillState | undefined;
  canKill: boolean;
  onKill: () => void;
}) {
  if (state?.status === "terminated") {
    return <span className="chip chip-CRITICAL" title={state.detail || undefined}>TERMINATED</span>;
  }
  if (state?.status === "pending") {
    return <span className="chip chip-accent" title="Waiting for the agent to confirm">Killing…</span>;
  }
  const failed = state?.status === "failed" || state?.status === "expired";
  return (
    <>
      {failed ? (
        <span className="chip chip-HIGH" title={state?.detail || undefined}>
          {state?.status === "expired" ? "Kill expired (agent offline)" : "Kill failed"}
        </span>
      ) : null}
      {canKill ? (
        <button type="button" className="btn-danger" onClick={onKill}>
          {failed ? "Retry kill" : "Kill process"}
        </button>
      ) : null}
    </>
  );
}
