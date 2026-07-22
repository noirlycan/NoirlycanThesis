# Handoff: Noirlycan Telemetry Console

## Overview
A web console for a process-injection detection lab (thesis project based on the ASIA CCS '25 paper *"Can You Run My Code?"* and the `noirlycan/NoirlycanThesis` repo). Architecture: **one machine runs this web console** (configuration + analysis UI); **agents run on VMs / sandboxes** (Python + Frida + Sysmon, from the thesis repo) and connect back to the console. The console configures detection rules at runtime, shows findings grouped by target process, and generates the command / `.toml` config used to deploy agents.

## About the Design Files
The single file `Noirlycan.dc.html` in this bundle is a **design reference created in HTML** — a working prototype showing the intended look, layout, and interactions. It is **not** production code to ship. The task is to **recreate this UI in your target stack** (the thesis backend is Python + a JS/CSS dashboard, per the repo `src/noirlycan_telemetry` with a Flask/HTTP dashboard on `127.0.0.1:8765`). Reuse your existing framework and patterns; if starting fresh, React + a light component layer is a good fit. The prototype's own runtime (a small custom "DC" component runtime) is an artifact of the design tool — **do not port it**; reimplement the state model described below.

## Fidelity
**High-fidelity.** Final colors, typography, spacing, radii, and interactions are all specified. Recreate pixel-close using your codebase's component library. Two themes (dark + light) are driven by CSS custom properties — implement as a theme toggle.

## Design Tokens

Themes are applied by setting CSS custom properties on a root element. Every component reads `var(--token)`; only the root's variable values change between themes.

### Dark theme (default: `Aurora`)
```
--bg: radial-gradient(900px 500px at 78% -8%, #241a4a 0%, #0e0b1e 55%), linear-gradient(180deg,#0e0b1e,#0b0917)
--panel: rgba(255,255,255,.045)      --panel2: rgba(255,255,255,.06)
--border: rgba(255,255,255,.09)      --hole: rgba(0,0,0,.28)
--text: #d7d3ec   --muted: #948dbb   --dim: #6b6390   --solid: #12102a
--accent: #a78bff   --accent2/brand-end: #6b46ff   --accentText: #c4b6ff
--navActive: linear-gradient(120deg,rgba(139,124,255,.22),rgba(139,124,255,.06))
--navBorder: rgba(167,139,255,.35)
--brand: linear-gradient(140deg,#a78bff,#6b46ff)
--brandShadow: 0 8px 22px -6px rgba(139,124,255,.6)
--cardShadow: none
--critBg: linear-gradient(160deg,rgba(229,72,77,.18),rgba(255,255,255,.03))   --critBorder: rgba(229,72,77,.4)
```

### Light theme (`Daylight`)
```
--bg: #f6f7f9
--panel: #ffffff   --panel2: #f2f4f6   --border: #e8eaee   --hole: #f6f7f9
--text: #1c2230    --muted: #8a93a2    --dim: #a8afba    --solid: #ffffff
--accent/accent2: #6b46ff (brand accent)   --accentText: #4a2fd6
--navActive: #f0edff   --navBorder: #d9d0ff
--brand: linear-gradient(140deg,#a78bff,#6b46ff)
--brandShadow: 0 6px 16px -6px rgba(107,70,255,.45)
--cardShadow: 0 1px 3px rgba(20,25,34,.05)
--critBg: #fef4f4   --critBorder: #f6cccd
```
The **brand accent** (`#6b46ff`) is themeable (prototype exposes it as a prop with swatches `#6b46ff`, `#2f8f4e`, `#c9282d`, `#0f74d1`).

### Severity ramp (fixed, both themes)
```
CRITICAL #e5484d   HIGH #ec7b1a   MEDIUM #e8c020   LOW #46c26a   INFO #5b9df0
```
Primitive colors: allocate = `#46c26a`, write = `#e8c020`, execute = `#ec7b1a`.

### Typography
- **Space Grotesk** (600/700): logo, page titles, card titles, big stat numbers.
- **Manrope** (400–800): all UI/body text.
- **JetBrains Mono** (400–600): API names, PIDs, hashes, timestamps, tokens, code/commands, table meta labels.
- Sizes: page title 20px/600; card title 16px Space Grotesk/600; stat number 32px/700; body 13–13.5px; labels 12px; mono meta 11–12.5px; micro/eyebrow 10–11px uppercase, letter-spacing .06–.1em.

### Spacing / shape
- Card radius 16–18px; inputs/buttons 10–11px; chips/badges 6–8px; pills 20px.
- Card padding 22–24px; screen padding 26–28px; grid/flex `gap` 12–20px.
- Sidebar width 246px. Content max-widths: Rules 1080px, Account 720px, Access 940px, Agents 1000px.
- Min app width 1180px (desktop-first).

### Animations (`@keyframes`)
- `nlPulse` 1.6–1.8s — live status dots (opacity 1↔.35).
- `nlSweep` 3.2s — accent line sweeping across the critical finding banner.
- `nlUp` .2–.3s — modal / toast entrance (translateY 8px + fade).

## App Shell / Layout
Flex row: **sidebar (246px, fixed)** + **main (flex column)**.

**Sidebar** (top→bottom): logo (36px rounded-11 brand-gradient square with "N" + wordmark "Noirlycan" / mono "TELEMETRY"); `MENU` eyebrow; nav items; a "Live capture" status card (green pulse dot + "Frida + Sysmon · 3 hooks"); current-user row (avatar initial, name, role, **Log out** button).

**Nav items** — dot + label, optional right-aligned count badge. Active item: `--navActive` bg, `--navBorder` border, `--accentText` text, glowing accent dot. Nav is **role-filtered** (see Permissions). Full set: Overview, Findings (badge 12), Activity, Network (badge 1), Rules*, Agents*, Account, Access* (`*` = admin/permission-gated).

**Topbar**: page title + subtitle (left); right cluster = search pill (`search pid, api, hash…`), "Auto 5s" live pill, theme toggle (☾/☀, 38px), **Export JSONL** button (hidden without `export` permission).

## Screens / Views

### 1. Login (shown when logged out)
Centered 404px card on themed bg. Logo, "Sign in", email + password inputs, error line, **Sign in** button (brand). Divider "QUICK DEMO", three role buttons (Admin / Analyst / Viewer) for instant demo login. Demo accounts: `admin@lab`/`admin`, `analyst@lab`/`analyst`, `viewer@lab`/`viewer`.

### 2. Overview
- **KPI row** (5 cards, `grid repeat(5,1fr)`): Findings (12, +3 last minute), **Critical** (1, uses `--critBg/--critBorder`, red number), Injection chains (2), File drops (4), Beacons (1, orange). **Each card is clickable** → navigates: Findings/Critical/Injection→Findings tab, File drops→Activity, Beacons→Network. `cursor:pointer`.
- **Active critical finding** (left, ~1.55fr): red-bordered card with `nlSweep` accent line; CRITICAL badge + title "Probable process injection chain" + timestamp; flow chip `loader.exe 4821 ──▶ msedge.exe 6120  SUSPENDED`; tag chips `section_mapping=true` (green), `cross_process=true` (orange), `3 / 3 primitives`; **API CHAIN** list (op-colored label + api + detail):
  `alloc NtCreateSection RWX` / `write NtMapViewOfSection local view` / `write NtMapViewOfSection remote → msedge.exe` / `exec SetThreadContext entry = 0x2000` / `exec ResumeThread payload runs`.
- **Right column (1fr)**: *Severity mix* donut (`conic-gradient` CRITICAL/HIGH/MEDIUM/LOW/INFO, hollow center showing "12 findings") + legend with counts 1/2/3/4/2. *Injection primitives* — three bars in fixed-height (104px) tracks, bottom-aligned: Allocate 2 (52px, green grad), Write 4 (104px, amber grad), Execute 2 (52px, orange grad); caption "≥{minPrimitives} of 3 observed → injection".

### 3. Findings (grouped by target process / chain)
Toolbar: caption + **Export report (.md)** button (needs `report` permission). Then one **group card per victim process**:
- Header (bg `--hole`): top-severity badge, `source ──▶ victim vpid` mono flow, summary line, right side = tag chips + count pill (`N detections`).
- Member rows (`grid 44px 96px 1fr 90px 84px 32px`): step index (`#1`, `#2`… = chain order), severity chip, title, primitives (`2 / 3`), time, and a **× delete** cell (only if `del` permission — marks false positive, removes from view; `stopPropagation` so it doesn't open the modal). Clicking a row opens the **Finding modal**.

Groups in the prototype:
- `loader.exe · 4821 ──▶ msedge.exe · 6120` — "Injection chain into a suspended browser process", tags section_mapping/cross_process. Members in chain order: #1 Suspended process spawn (HIGH), #2 RWX memory in remote process (MEDIUM), #3 Probable process injection chain (CRITICAL, 3/3), #4 ntdll.dll image load (LOW).
- `loader.exe · 4821 ──▶ disk drop` — "Payload staged on disk", member: Unsigned PE dropped to disk (MEDIUM).

### 4. Finding modal
Overlay (`rgba(4,3,14,.55)` + blur, `nlUp` in), 640px card (`--solid` bg): severity badge + title + × close; flow chip; tag chips; **API CHAIN** list. Footer (top-border): **Export report (.md)** (if `report`) and **Mark false positive & delete** (red outline, if `del`). Clicking backdrop or × closes.

### 5. Activity
Two columns. Left (1.3fr) — **Event stream** (live dot), mono rows `time · KIND · message`, KIND colored by op (EXEC red/orange, WRITE amber, ALLOC green, PROC/FILE blue); the top EXEC row highlighted red. Right (1fr) — **File drops** cards: badge (UNSIGNED red / PE orange / SCRIPT amber) + filename + meta (sha256, entropy, Authenticode, creator).

### 6. Network
- Beacon card (orange border): `BEACON?` badge + "Outbound to non-private range" + "post-finding watch · 5 min"; connection chip `msedge.exe 6120 ──▶ 185.12.44.9:443  TLS · 3 conns`.
- Connections table (`grid 1.2fr 1fr 1fr 90px`): PROCESS / DESTINATION / CLASS (PUBLIC orange, PRIVATE green) / CONNS.

### 7. Rules (admin — `rules` permission)
"ADMIN ONLY" badge + note "applied live, no rebuild". Cards:
- **Detection primitives** — 3 columns (Allocate/Write/Execute). Each: colored header, removable API chips (× per chip), "Add API…" input + **+** button. Defaults: alloc = VirtualAllocEx, VirtualAllocExNuma, NtAllocateVirtualMemory, NtCreateSection; write = WriteProcessMemory, NtWriteVirtualMemory, NtMapViewOfSection; exec = CreateRemoteThread, NtCreateThreadEx, QueueUserAPC, SetThreadContext, ResumeThread. (Matches Appendix B API classes in the paper.)
- **Named detection chains** — rows with editable name input, a **step builder** (chips `op · api` colored by op, × to remove; a "+ step…" `<select>` whose options are all currently-defined primitive APIs grouped alloc/write/exec), and a **technique** `<select>` (Process Hollowing (no-unmap), Process Hollowing, PE Injection, Shellcode Injection, DLL Injection from Disk, APC Injection, Thread Execution Hijacking, Early Bird, Hook Injection, Custom). **+ Add chain** button; × removes a chain.
- **Correlation logic** — segmented "2 of 3 / 3 of 3" (min primitives); toggles for Memory-range congruence and Temporal ordering.
- **Severity mapping** — condition rows each with a severity `<select>`.
- **Scoring** — weighted signal list with numeric point inputs (cross_process 30, section_mapping 25, primitive-each 15, suspended-spawn 20, unsigned-PE 15, beacon 20); threshold number inputs CRITICAL ≥80 / HIGH ≥55 / MEDIUM ≥30.
- **Monitoring** — Capture window slider (1–8 min), Post-finding network watch slider (1–15 min), Auto-attach toggle, Watched folders list (removable + add).
- **Network / beacon** — Flag-non-private toggle, allowlist CIDR list (removable + add: 10.0.0.0/8, 192.168.0.0/16, 127.0.0.1/32).
- **Sticky footer** — "saved" flash + **Reset defaults** / **Save ruleset**.

### 8. Agents (admin — `access` permission)
Web-console-configures-here / agent-runs-on-VM.
- **This console** — Host/IP + Port inputs (agent connects back here), enrollment token field + **Regenerate**.
- **Deploy an agent** — generated **Run mode** command (with **Copy**) and **Spawn mode** command; **Export config (.toml)** button. Commands/config regenerate live from host/port/token + ruleset.
  - Run: `noirlycan-telemetry run --server <host>:<port> --token <token> --watch-sysmon --auto-attach-new-processes`
  - Spawn: `noirlycan-telemetry spawn --server <host>:<port> --token <token> --watch-sysmon -- C:\Lab\loader.exe`
  - `.toml` sections: `[server]` endpoint/token, `[capture]` window_minutes/network_watch_minutes/auto_attach/min_primitives, `[watch]` folders, `[network]` flag_non_private/allowlist.
- **Connected agents** table (`grid 1.3fr 1.3fr 1fr 1.3fr 90px 90px`): AGENT / OS / MODE (spawn/attach/auto-attach) / WATCHING / LAST / STATUS (online green pulse / stale orange).

### 9. Account
- **Profile** — avatar (initial), role chip (read-only; role granted in Access), Display name + Email inputs.
- **Change password** — Current / New / Confirm.
- Footer — "Profile saved" flash + **Save changes**.

### 10. Access (admin — `access` permission)
- **Team members** — rows (avatar, name, email, role `<select>` Admin/Analyst/Viewer, × remove); add-member row (name + email + role + **Add**). Seed: admin@lab (Admin), analyst@lab (Analyst), viewer@lab (Viewer).
- **Role permissions** — editable matrix; **click a cell to grant/revoke** (✓ green / — dim). Rows = capabilities; columns = Admin/Analyst/Viewer.

## Interactions & Behavior
- **Auth gate**: logged-out → Login only; logged-in → full shell. Login validates against demo accounts; quick-login buttons set a role instantly. Logout clears session.
- **Navigation**: sidebar items and Overview KPI cards call `setTab`. Only the active screen renders.
- **Theme toggle**: swaps the root CSS-variable set; icon ☾↔☀.
- **Live edits everywhere in Rules/Agents**: every add/remove/toggle/slider/select updates state immediately; saving flips a "saved" flash. No hardcoded rules.
- **Delete finding**: `del`-permitted users get × on rows + delete in modal → adds finding key to a `removed` list; empty groups disappear.
- **Export .md report**: builds Markdown (session header + per-finding severity, flow, time, primitives, tags, API chain) and downloads via Blob. Modal exports the one finding; Findings toolbar exports all non-removed.
- **Export .toml / Copy command**: build strings from server + ruleset; download via Blob / `navigator.clipboard`.
- **Permission changes are reactive**: toggling a matrix cell instantly re-filters the nav and buttons (e.g. granting `report` to Analyst reveals the .md buttons; `rules`/`access` control Rules/Agents/Access tabs; `export` controls Export JSONL).
- Hover/press affordances: `cursor:pointer` on all actionable elements; buttons carry `--brandShadow`.

## State Management
Single top-level state object:
- `theme` (`dark`|`light`), `tab` (current screen), `modal` (open finding or null).
- `user` (`{name,email,role,initial}` or null), `loginEmail/loginPw/loginErr`, `profileSaved`.
- `rolePerms`: `{ Admin|Analyst|Viewer: { dashboards, triage, export, report, del, rules, access } }` — the editable permission matrix; `perms(role)` just reads this. Defaults: Admin all true; Analyst = dashboards/triage/export true; Viewer = dashboards only.
- `team` (array of members), `newMember` buffer.
- `rules`: `{ alloc[], write[], exec[], minPrimitives(2|3), congruence, temporal, capture, netWatch, autoAttach, beacon, folders[], allowlist[], sev[{cond,s}], chains[{name,tech,steps:[{op,api}]}], score:{weights:[{label,pts}],crit,high,med} }`, plus `buf` (add-input buffers), `saved` flag.
- `removed[]` (deleted finding keys — keyed by timestamp).
- `server` `{host,port,token}`, `copied` (copy flash), `agents[]`.

Data fetching (for the real build): findings, events, drops, connections, and agent status should come from the analysis backend (JSONL sessions in `logs/`, Sysmon + Frida events); the prototype ships representative fixtures. Ruleset + server config should persist to the backend and be pushed to agents.

## Assets
No raster/image assets. The "N" logo is a CSS gradient square with a text glyph. Icons are simple CSS shapes (dots, squares) — replace with your icon set if desired. Fonts load from Google Fonts (Space Grotesk, Manrope, JetBrains Mono) — self-host or map to your stack.

## Response actions — Kill & Auto-kill (added)
The console can send a **terminate** command to the agent on the workstation.
- **Manual kill**: a red **Kill process** button appears on (a) the Overview critical finding, (b) the Finding modal footer, and (c) each Findings group header (only for groups that have a victim PID). Requires the `kill` permission. After firing, a red toast confirms `Kill command sent → <name> (PID <pid>) on workstation`, and the target flips to a `TERMINATED` chip. Killed PIDs are tracked in `state.killed`.
- **Auto-kill (per agent)**: the Agents → *Connected agents* table has an **AUTO-KILL** toggle per agent, plus a global policy strip **"Auto-kill when severity ≥ [CRITICAL|HIGH|MEDIUM]"** (`state.autoKillSev`). When an agent has auto-kill on and a finding on its host meets the threshold, the agent terminates the process automatically.
- **Permission**: `kill` ("Kill process on workstation") is a row in the Access permission matrix — Admin + Analyst on by default, Viewer off, and grantable like the others.
- **Backend contract**: kill = an authenticated command from console → agent, e.g. `POST /agents/{id}/kill { pid, token }`; the agent executes it (`taskkill` / `NtTerminateProcess`) and reports back. Auto-kill is evaluated **on the agent** from the pushed ruleset (`auto_kill = true`, `auto_kill_min_severity = "CRITICAL"`) so it fires even if the console is offline.

## Recommended stack & data flow
**Chosen stack: FastAPI + SQLite + React.**
- **Backend — FastAPI (Python)**: agent ingest endpoint (`POST /ingest`, Bearer enrollment token), WebSocket for the live event stream, REST for findings/rules/agents/users. Auth = JWT (or session cookie) with bcrypt/argon2 password hashing; RBAC from the permission matrix. Agent auth via per-agent enrollment token, separate from user accounts.
- **DB — SQLite** via SQLAlchemy + Alembic. Single-file DB, zero setup, ideal for the single-machine lab console. Store raw events/findings as JSON in `TEXT`/`JSON` columns (Frida/Sysmon payloads vary); index by session, target PID, severity, timestamp. Because it's SQLAlchemy, you can later point at Postgres/TimescaleDB with almost no code change if volume grows — but SQLite is the target here. Enable WAL mode for concurrent agent writes.
- **Frontend — React + Vite + TypeScript**: the `state` model above maps directly to React state; TanStack Query for fetch/cache + WebSocket for the stream; theme via CSS variables (dark/light) exactly as in the prototype.
- **Suggested tables**: `users`, `agents`, `sessions`, `events`, `findings`, `finding_groups`, `rulesets` (versioned), `role_permissions`, `audit_log` (kills, rule changes, logins).
- **Data flow**:
  ```
  agent (VM) --token--> POST /ingest --> SQLite (events, JSON columns)
                              |
                     correlation engine --> findings/groups (2-of-3 primitives, congruence, scoring)
  console  --JWT--> REST (findings, rules, agents, users) + WS (live events)
  console  --> save ruleset/server config --> DB --> pushed to agents (.toml / API)
  console  --> POST /agents/{id}/kill --> agent terminates process
  agent    --> auto-kill locally when finding.severity >= policy
  ```

## Files
- `Noirlycan.dc.html` — the full high-fidelity prototype (all screens, both themes, all interactions incl. kill / auto-kill). Open in a browser to explore. Ignore the `support.js` runtime reference and `<x-dc>` wrapper — those belong to the design tool, not the target implementation.
