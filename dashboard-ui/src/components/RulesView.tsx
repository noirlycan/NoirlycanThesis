import { useState } from "react";
import type { Ruleset } from "../types";

const TECHNIQUES = [
  "Process Hollowing (no-unmap)",
  "Process Hollowing",
  "PE Injection",
  "Shellcode Injection",
  "DLL Injection from Disk",
  "APC Injection",
  "Thread Execution Hijacking",
  "Early Bird",
  "Hook Injection",
  "Custom",
];

type ChainStep = { op: string; api: string };

function stepOptions(rules: Ruleset) {
  return [
    ...rules.alloc.map((api) => ({ value: `alloc::${api}`, label: `alloc · ${api}`, group: "Allocate" })),
    ...rules.write.map((api) => ({ value: `write::${api}`, label: `write · ${api}`, group: "Write" })),
    ...rules.exec.map((api) => ({ value: `exec::${api}`, label: `exec · ${api}`, group: "Execute" })),
  ];
}

function updateChain(rules: Ruleset, index: number, patch: Record<string, unknown>) {
  const chains = [...(rules.chains || [])];
  chains[index] = { ...chains[index], ...patch };
  return chains;
}

const BUCKETS = [
  { key: "alloc" as const, label: "Allocate", color: "var(--op-alloc)" },
  { key: "write" as const, label: "Write", color: "var(--op-write)" },
  { key: "exec" as const, label: "Execute", color: "var(--op-exec)" },
];

function ChainStepSelect({
  rules,
  onAdd,
}: {
  rules: Ruleset;
  onAdd: (op: string, api: string) => void;
}) {
  const [value, setValue] = useState("");
  const options = stepOptions(rules);
  const groups = ["Allocate", "Write", "Execute"];

  return (
    <select
      className="mono"
      value={value}
      onChange={(e) => {
        const picked = e.target.value;
        if (!picked) return;
        const [op, api] = picked.split("::");
        if (op && api) onAdd(op, api);
        setValue("");
      }}
      style={{
        background: "var(--panel)",
        border: "1px dashed var(--border)",
        borderRadius: 7,
        padding: "5px 8px",
        fontSize: 11,
        color: "var(--muted)",
        cursor: "pointer",
      }}
    >
      <option value="">+ step…</option>
      {groups.map((group) => (
        <optgroup key={group} label={group}>
          {options
            .filter((item) => item.group === group)
            .map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
        </optgroup>
      ))}
    </select>
  );
}

type Props = {
  rules: Ruleset;
  onChange: (rules: Ruleset) => void;
  onSave: () => void;
  onReset: () => void;
};

export function RulesView({ rules, onChange, onSave, onReset }: Props) {
  const [savedFlash, setSavedFlash] = useState(false);
  const [buf, setBuf] = useState<Record<string, string>>({ alloc: "", write: "", exec: "", folder: "", allow: "" });

  function addApi(bucket: "alloc" | "write" | "exec") {
    const api = buf[bucket]?.trim();
    if (!api || rules[bucket].includes(api)) return;
    onChange({ ...rules, [bucket]: [...rules[bucket], api] });
    setBuf({ ...buf, [bucket]: "" });
  }

  function removeApi(bucket: "alloc" | "write" | "exec", api: string) {
    onChange({ ...rules, [bucket]: rules[bucket].filter((item) => item !== api) });
  }

  function addFolder() {
    const folder = buf.folder?.trim();
    if (!folder || rules.folders.includes(folder)) return;
    onChange({ ...rules, folders: [...rules.folders, folder] });
    setBuf({ ...buf, folder: "" });
  }

  function addAllow() {
    const cidr = buf.allow?.trim();
    if (!cidr || rules.allowlist.includes(cidr)) return;
    onChange({ ...rules, allowlist: [...rules.allowlist, cidr] });
    setBuf({ ...buf, allow: "" });
  }

  function save() {
    onSave();
    setSavedFlash(true);
    window.setTimeout(() => setSavedFlash(false), 1800);
  }

  return (
    <div style={{ maxWidth: 1080, display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span className="badge">ADMIN ONLY</span>
        <span style={{ color: "var(--dim)", fontSize: 12 }}>applied live, no rebuild</span>
        {savedFlash ? <span style={{ marginLeft: "auto", color: "var(--op-alloc)" }}>saved</span> : null}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
        {BUCKETS.map(({ key, label, color }) => (
          <div key={key} className="card">
            <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, color, marginBottom: 12 }}>{label}</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 12 }}>
              {rules[key].map((api) => (
                <span key={api} className="chip">
                  {api}
                  <button type="button" className="chip-x" onClick={() => removeApi(key, api)}>
                    ×
                  </button>
                </span>
              ))}
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                className="field-input"
                style={{ margin: 0, flex: 1 }}
                placeholder="Add API…"
                value={buf[key]}
                onChange={(e) => setBuf({ ...buf, [key]: e.target.value })}
              />
              <button type="button" className="btn-brand" onClick={() => addApi(key)}>
                +
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className="card">
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
          <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16 }}>Named detection chains</div>
          <button
            type="button"
            className="btn-ghost"
            style={{ marginLeft: "auto", fontSize: 12.5, fontWeight: 600, color: "var(--accentText)" }}
            onClick={() =>
              onChange({
                ...rules,
                chains: [...(rules.chains || []), { name: "New chain", tech: "Custom", steps: [] }],
              })
            }
          >
            + Add chain
          </button>
        </div>
        <div style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 18 }}>
          Đặt tên cho từng chuỗi primitive và gán kỹ thuật — tên này hiện trên finding.
        </div>
        <div
          className="mono"
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 210px 32px",
            gap: "10px 12px",
            fontSize: 10,
            letterSpacing: ".06em",
            color: "var(--dim)",
            padding: "0 2px 8px",
          }}
        >
          <div>CHAIN NAME · MATCH</div>
          <div>TECHNIQUE</div>
          <div />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {(rules.chains || []).map((chain, index) => {
            const steps = ((chain.steps as ChainStep[]) || []);
            return (
              <div
                key={index}
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 210px 32px",
                  gap: 12,
                  alignItems: "start",
                  padding: "12px 14px",
                  border: "1px solid var(--border)",
                  borderRadius: 12,
                  background: "var(--hole)",
                }}
              >
                <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                  <input
                    className="field-input"
                    style={{ margin: 0, fontWeight: 600 }}
                    placeholder="Chain name"
                    value={String(chain.name || "")}
                    onChange={(e) => onChange({ ...rules, chains: updateChain(rules, index, { name: e.target.value }) })}
                  />
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center" }}>
                    {steps.map((step, stepIndex) => (
                      <span key={`${step.op}-${step.api}-${stepIndex}`} className={`chip chip-${step.op}`}>
                        {step.op} · {step.api}
                        <button
                          type="button"
                          className="btn-ghost"
                          style={{ padding: 0, minWidth: 0, border: "none", color: "inherit", opacity: 0.6, fontSize: 13 }}
                          onClick={() => {
                            const nextSteps = steps.filter((_, i) => i !== stepIndex);
                            onChange({ ...rules, chains: updateChain(rules, index, { steps: nextSteps }) });
                          }}
                        >
                          ×
                        </button>
                      </span>
                    ))}
                    <ChainStepSelect
                      rules={rules}
                      onAdd={(op, api) => {
                        onChange({
                          ...rules,
                          chains: updateChain(rules, index, { steps: [...steps, { op, api }] }),
                        });
                      }}
                    />
                  </div>
                </div>
                <select
                  className="field-input mono"
                  style={{ margin: 0, fontSize: 11, fontWeight: 600, color: "var(--accentText)" }}
                  value={String(chain.tech || TECHNIQUES[0])}
                  onChange={(e) => onChange({ ...rules, chains: updateChain(rules, index, { tech: e.target.value }) })}
                >
                  {TECHNIQUES.map((tech) => (
                    <option key={tech} value={tech}>
                      {tech}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  className="btn-ghost"
                  style={{ padding: "2px 0", fontSize: 16, color: "var(--dim)" }}
                  onClick={() => onChange({ ...rules, chains: (rules.chains || []).filter((_, i) => i !== index) })}
                >
                  ×
                </button>
              </div>
            );
          })}
          {!rules.chains?.length ? (
            <div style={{ color: "var(--dim)", fontSize: 12.5, padding: "8px 2px" }}>
              Chưa có chain — bấm <strong>+ Add chain</strong> để thêm chuỗi primitive.
            </div>
          ) : null}
        </div>
      </div>

      <div className="card" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div>
          <div style={{ fontFamily: "Space Grotesk", fontWeight: 600, fontSize: 16, marginBottom: 20 }}>Correlation logic</div>
          <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 18 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="toggle-title">Minimum primitives to flag</div>
              <div className="toggle-desc">Số thao tác allocate / write / execute cùng chain để coi là injection.</div>
            </div>
            <div className="segmented" role="group" aria-label="Minimum primitives">
              {[2, 3].map((value) => (
                <button
                  key={value}
                  type="button"
                  className={`segmented-btn${Number(rules.min_primitives) === value ? " active" : ""}`}
                  onClick={() => onChange({ ...rules, min_primitives: value })}
                >
                  {value} of 3
                </button>
              ))}
            </div>
          </div>
          <div style={{ fontSize: 12, color: "var(--dim)", marginBottom: 4 }}>
            Thay đổi có hiệu lực sau khi bấm <strong>Save ruleset</strong> (agent nhận policy mới ở lần ingest tiếp theo).
          </div>
          <div className="toggle-row">
            <div className="toggle-copy">
              <div className="toggle-title">Memory-range congruence</div>
              <div className="toggle-desc">Chỉ nối các thao tác trên cùng khoảng địa chỉ [α, α+β].</div>
            </div>
            <button
              type="button"
              className={`toggle-switch${rules.congruence ? " on" : ""}`}
              aria-pressed={rules.congruence}
              onClick={() => onChange({ ...rules, congruence: !rules.congruence })}
            >
              <span className="toggle-knob" />
            </button>
          </div>
          <div className="toggle-row">
            <div className="toggle-copy">
              <div className="toggle-title">Temporal ordering</div>
              <div className="toggle-desc">alloc → write → execute (cho phép hoán vị hợp lệ).</div>
            </div>
            <button
              type="button"
              className={`toggle-switch${rules.temporal ? " on" : ""}`}
              aria-pressed={rules.temporal}
              onClick={() => onChange({ ...rules, temporal: !rules.temporal })}
            >
              <span className="toggle-knob" />
            </button>
          </div>
        </div>
        <div>
          <div style={{ marginBottom: 8 }}>Monitoring</div>
          <label style={{ display: "block", marginBottom: 8 }}>
            Capture window ({rules.capture} min)
            <input
              type="range"
              min={1}
              max={8}
              value={rules.capture}
              onChange={(e) => onChange({ ...rules, capture: Number(e.target.value) })}
              style={{ width: "100%" }}
            />
          </label>
          <label style={{ display: "block", marginBottom: 8 }}>
            Post-finding network watch ({rules.net_watch} min)
            <input
              type="range"
              min={1}
              max={15}
              value={rules.net_watch}
              onChange={(e) => onChange({ ...rules, net_watch: Number(e.target.value) })}
              style={{ width: "100%" }}
            />
          </label>
          <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input type="checkbox" checked={rules.auto_attach} onChange={(e) => onChange({ ...rules, auto_attach: e.target.checked })} />
            Auto-attach new processes
          </label>
        </div>
      </div>

      <div className="card">
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Severity mapping</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {rules.sev.map((row, index) => (
            <div key={index} style={{ display: "grid", gridTemplateColumns: "1fr 140px", gap: 12, alignItems: "center" }}>
              <input
                className="field-input mono"
                style={{ margin: 0, fontSize: 12 }}
                value={row.cond}
                onChange={(e) => {
                  const sev = [...rules.sev];
                  sev[index] = { ...row, cond: e.target.value };
                  onChange({ ...rules, sev });
                }}
              />
              <select
                value={row.s}
                onChange={(e) => {
                  const sev = [...rules.sev];
                  sev[index] = { ...row, s: e.target.value };
                  onChange({ ...rules, sev });
                }}
              >
                {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </select>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Scoring</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
          {rules.score.weights.map((row, index) => (
            <label key={row.label} style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span className="mono" style={{ flex: 1 }}>
                {row.label}
              </span>
              <input
                type="number"
                value={row.pts}
                style={{ width: 72 }}
                onChange={(e) => {
                  const weights = [...rules.score.weights];
                  weights[index] = { ...row, pts: Number(e.target.value) };
                  onChange({ ...rules, score: { ...rules.score, weights } });
                }}
              />
            </label>
          ))}
        </div>
        <div style={{ display: "flex", gap: 16, marginTop: 16 }}>
          {(["crit", "high", "med"] as const).map((key) => (
            <label key={key} style={{ display: "flex", gap: 8, alignItems: "center" }}>
              {key.toUpperCase()} ≥
              <input
                type="number"
                value={rules.score[key]}
                onChange={(e) => onChange({ ...rules, score: { ...rules.score, [key]: Number(e.target.value) } })}
                style={{ width: 72 }}
              />
            </label>
          ))}
        </div>
      </div>

      <div className="card" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Watched folders</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 12 }}>
            {rules.folders.map((folder) => (
              <span key={folder} className="chip">
                {folder}
                <button
                  type="button"
                  className="btn-ghost"
                  style={{ padding: "0 6px" }}
                  onClick={() => onChange({ ...rules, folders: rules.folders.filter((item) => item !== folder) })}
                >
                  ×
                </button>
              </span>
            ))}
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              className="field-input mono"
              style={{ margin: 0, flex: 1 }}
              placeholder="C:\\Users\\lab\\Downloads"
              value={buf.folder}
              onChange={(e) => setBuf({ ...buf, folder: e.target.value })}
            />
            <button type="button" className="btn-brand" onClick={addFolder}>
              +
            </button>
          </div>
        </div>
        <div>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Network / beacon</div>
          <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 12 }}>
            <input type="checkbox" checked={rules.beacon} onChange={(e) => onChange({ ...rules, beacon: e.target.checked })} />
            Flag non-private destinations
          </label>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 12 }}>
            {rules.allowlist.map((cidr) => (
              <span key={cidr} className="chip">
                {cidr}
                <button
                  type="button"
                  className="btn-ghost"
                  style={{ padding: "0 6px" }}
                  onClick={() => onChange({ ...rules, allowlist: rules.allowlist.filter((item) => item !== cidr) })}
                >
                  ×
                </button>
              </span>
            ))}
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              className="field-input mono"
              style={{ margin: 0, flex: 1 }}
              placeholder="10.0.0.0/8"
              value={buf.allow}
              onChange={(e) => setBuf({ ...buf, allow: e.target.value })}
            />
            <button type="button" className="btn-brand" onClick={addAllow}>
              +
            </button>
          </div>
        </div>
      </div>

      <div style={{ position: "sticky", bottom: 0, display: "flex", gap: 12, paddingTop: 8 }}>
        <button type="button" className="btn-ghost" onClick={onReset}>
          Reset defaults
        </button>
        <button type="button" className="btn-brand" onClick={save}>
          Save ruleset
        </button>
      </div>
    </div>
  );
}
