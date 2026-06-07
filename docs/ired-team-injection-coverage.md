# iRed.team Process Injection — Coverage Map for Noirlycan

**Source index:** [Code & Process Injection | Red Team Notes](https://www.ired.team/offensive-security/code-injection-process-injection)

This document maps iRed.team injection labs to Noirlycan hooks, correlator rules, and technique classifier output. It complements `docs/report-asiaccs25-comparison.md` (ASIA CCS 2025 paper alignment).

---

## 1. Coverage legend

| Level | Meaning |
|-------|---------|
| **full** | Frida hooks + 2/3 primitive correlation + dedicated `technique_classifier` rule |
| **partial** | Hooks and/or heuristics; may lack payload parsing or full API chain reconstruction |
| **planned** | Documented in taxonomy; not yet implemented |
| **none** | Out of current scope |

---

## 2. Technique matrix (iRed.team → Noirlycan)

| iRed.team lab | Key APIs | Noirlycan technique | Coverage | Module / notes |
|---------------|----------|---------------------|----------|----------------|
| CreateRemoteThread shellcode | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | `shellcode_injection` | full | `technique_classifier.py` |
| DLL injection | `LoadLibrary*`, `LdrLoadDll`, remote thread | `dll_injection` | full | `injection_api_manifest.py` |
| Reflective DLL | `VirtualAlloc`, `memcpy`, `NtCreateThreadEx` (no DLL path) | `reflective_dll_injection` | partial | Heuristic only — no in-memory PE loader parse |
| Process hollowing + relocations | `CREATE_SUSPENDED`, `NtUnmapViewOfSection`, `NtMapViewOfSection`, context/resume | `process_hollowing_section` | full | `correlation.py` evidence flags |
| NtCreateSection + NtMapViewOfSection | Section RW local / RX remote, `RtlCreateUserThread` | `section_mapping_injection` / `process_hollowing_section` | full | Staging vs `execution_confirmed` split |
| APC queue injection | `QueueUserAPC`, `OpenThread`, spray threads | `apc_injection` | full | APC = execution transfer API |
| Early Bird APC | `NtQueueApcThreadEx` + suspended victim | `early_bird_apc_injection` | full | Requires `create_suspended` evidence |
| Thread hijacking | `SuspendThread`, `GetThreadContext`, `SetThreadContext`, `ResumeThread` | `thread_hijack` | full | Context **read** ≠ execute (`context_read` primitive) |
| SetWindowHookEx | `SetWindowsHookExA/W` | `hook_injection` | full | user32 hooks |
| Module stomping | `NtUnmapViewOfSection` + remote write | `module_stomping` | partial | No module name / export stomp target |
| PE injection (remote PE) | Remote write + thread start | `pe_injection` | partial | Uses static triage `pe=True` on related file |
| EntryPoint patching (no RWX alloc) | `WriteProcessMemory`, `VirtualProtectEx`, resume | `entrypoint_patching` | partial | Protect + write heuristic |
| Fibers | `ConvertThreadToFiber`, `CreateFiber`, `SwitchToFiber` | `fiber_injection` | partial | `installIredTeamHooks()` |
| CreateThreadpoolWait | `CreateThreadpoolWait`, `SetThreadpoolWait` | `threadpool_wait_injection` | partial | Callback address captured |
| QueueUserAPC + NtTestAlert | `QueueUserAPC`, `NtTestAlert`, alertable `SleepEx` | `local_apc_injection` | partial | `NtTestAlert` hooked; `SleepEx` observation |
| Atom bombing | `GlobalAddAtom*`, `NtQueueApcThread` | `atom_injection` | partial | Atom table chain not rebuilt |
| Extra window memory | `SetWindowLongPtr*`, `SendMessage*` | `extra_window_memory_injection` | partial | No GWLP index validation |
| Process doppelganging | `NtCreateTransaction`, `RtlCreateProcessReflection` | `process_doppelganging` | partial | TxF flags in evidence; no transacted file graph |
| **Process ghosting** | `NtSetInformationFile` (delete-pending) + section + spawn | `process_ghosting` | **full** | Detected via `process_ghosting_precursor` note |
| **Process herpaderping** | `NtCreateSection` + `WriteFile` overwrite + spawn | `process_herpaderping` | full | Section captured, file overwritten before process create |
| **Phantom DLL hollowing** | TxF + `CreateFileTransacted` + section map | `phantom_dll_hollowing` | partial | TxF + section evidence; transacted content not parsed |
| **IAT hooking** | `VirtualProtectEx` + small remote `WriteProcessMemory` | `iat_hooking` | full | Size ≤ 16 B pointer-overwrite heuristic |
| **PROPagate** | `SetPropA/W` + `SendNotifyMessageA/W` | `propagate_injection` | full | Window property pointer triggered via SendNotifyMessage |
| **Manual PE mapping** | `VirtualAllocEx` + multi-write + `VirtualProtectEx` + thread | `manual_mapping` | full | ≥ 3 remote writes + protect + no LoadLibrary |
| **EnumXxx callback** | `EnumSystemLocalesA/W`, `EnumWindows`, `EnumChildWindows`, `EnumDateFormatsA/W`, `EnumUILanguagesW`, `EnumResourceTypesA/W`, `EnumDesktopWindows`, `EnumThreadWindows` | `enum_callback_injection` | full | Callback ptr to fresh exec buffer |
| **InstrumentationCallback** | `NtSetInformationProcess` w/ `ProcessInstrumentationCallback` | `instrumentation_callback` | full | Class 40; callback addr extracted from info struct |
| **KernelCallbackTable** | `NtQueryInformationProcess` + remote PEB write | `kernel_callback_table` | partial | No PEB-offset reasoning yet |
| **ETW patching** | local `VirtualProtect` + write to ntdll | `etw_patching` | partial | No module-range tracking yet |
| **AMSI patching** | local `VirtualProtect` + write to amsi.dll | `amsi_patching` | partial | Same caveat as ETW |
| **Mockingjay** | `NtMapViewOfSection` of existing RWX DLL | `mockingjay` | partial | No allocate primitive; needs DLL RWX-section scanner |
| **PoolParty** | `TpAllocWork`, `TpPostWork`, `NtSetInformationWorkerFactory`, `RtlQueueWorkItem` | `poolparty` | partial | 8 SafeBreach variants overlap |
| **Threadless inject** | Remote `VirtualProtectEx` + `WriteProcessMemory` w/o thread API | `threadless_inject` | full | No remote thread = trampoline pattern |
| **GhostWriting** | `OpenThread` + `SetThreadContext` (no remote write) | `thread_hijack` | full | Now detectable via D1 Rip extraction |
| .NET unmanaged injection | CLR hosting APIs | `dotnet_clr_hosting` | none | CLR APIs not instrumented |
| AppInit_DLLs / IFEO / COM hijack | Registry-based | — | none | Out of API-hook scope; requires registry telemetry |
| DLL Search Order Hijacking | File-drop + LoadLibrary | — | partial | File watcher catches planted DLL; no path-precedence reasoning |

---

## 3. Payload classification (PE vs shellcode)

`payload_classifier.py` adds evidence fields on each finding:

| `payload_kind` | When assigned |
|----------------|---------------|
| `dll_path` | Remote `LoadLibrary` / `LdrLoadDll` with module path |
| `pe_hollowing` | Related PE + suspended spawn or `NtUnmapViewOfSection` |
| `pe_image` | Related PE + remote write |
| `reflective_dll` | Cross-process write + execute, no DLL path, memcpy/alloc signals |
| `shellcode` | Classic alloc/write/thread or section mapping without PE file |
| `unknown` | Insufficient evidence |

Static triage (`triage.py`) supplies PE, entropy, signature — combined at correlation time via `related_file`.

---

## 4. New Frida hooks

`installIredTeamHooks()` in `frida_hooks/windows_injection_hooks.js`:

- **Fibers:** `ConvertThreadToFiber`, `CreateFiber`, `SwitchToFiber`
- **Threadpool wait:** `CreateThreadpoolWait`, `SetThreadpoolWait`, `SubmitThreadpoolWait`, `CreateThreadpoolWork`, `SubmitThreadpoolWork`
- **Alertable local APC:** `NtTestAlert`, alertable `SleepEx` (observation)
- **Window memory:** `SetWindowLongPtr*`, `SetWindowLong*`, `SendMessage*`, `SendMessageCallback*`
- **TxF / doppelganging:** `NtCreateTransaction`, `NtCommitTransaction`, `NtRollbackTransaction`, `RtlCreateProcessReflection`
- **Local protect:** `VirtualProtect`

`installAdvancedInjectionHooks()` (new):

- **Process Ghosting / Herpaderping:** `NtSetInformationFile` (FileDispositionInformation / Ex) → emits `process_ghosting_precursor` note
- **InstrumentationCallback:** `NtSetInformationProcess` (ProcessInstrumentationCallback class) → extracts callback address
- **PROPagate:** `SetPropA/W`, `SendNotifyMessageA/W`
- **EnumXxx callback family:** `EnumSystemLocalesA/W`, `EnumDateFormatsA/W`, `EnumUILanguagesW`, `EnumResourceTypesA/W`, `EnumWindows`, `EnumChildWindows`, `EnumDesktopWindows`, `EnumThreadWindows`
- **PoolParty:** `TpAllocWork`, `TpPostWork`, `RtlQueueWorkItem`, `NtSetInformationWorkerFactory`

API manifest: `PAPER_API_CLASSES` (core) + `IRED_TEAM_API_CLASSES` (iRed.team + advanced) in `injection_api_manifest.py`.

Verification: `tests/test_api_coverage.py` enforces that **every** API listed in `REPO_REQUIRED_APIS` has a corresponding hook entry. As of this version that union has **121 APIs** all hooked.

---

## 5. Gaps that remain (honest limits)

| iRed / offensive topic | Why not full coverage |
|------------------------|----------------------|
| Direct syscalls / unhooked ntdll | Frida hooks exports; stub syscall may bypass — see [audit O1](audit-and-threat-model.md) |
| Manual shellcode encoders / PE resource loading | No bytecode / resource-section analysis |
| Kernel callback table injection | User-mode reads PEB but no PEB-offset bookkeeping |
| Mockingjay (existing RWX DLL) | Needs scanner of legit DLL RWX sections — not implemented |
| .NET CLR hosting injection | CLR APIs (`CLRCreateInstance`, `CorBindToRuntime`) not hooked |
| Registry-based persistence (AppInit_DLLs, IFEO, COM hijack) | Requires registry telemetry — out of API hook scope |
| Full handle / object manager graph | Paper-level depth not replicated |
| Anti-evasion bypass (timing checks, debugger detection) | Frida-based lab; signals only via `evasion.py` |

---

## 6. Suggested lab validation (thesis)

Run known iRed samples or self-built PoCs per technique, expect classifier output:

```powershell
python -m noirlycan_telemetry spawn --watch-sysmon -- .\apcqueue.exe
python -m noirlycan_telemetry batch --input D:\corpus\ired-labs --output reports\ired-batch.json --watch-sysmon
```

Compare `technique`, `payload_kind`, and `execution_confirmed` in JSONL findings against the table in §2.

---

## 7. Code references

| File | Role |
|------|------|
| `ired_team_taxonomy.py` | Machine-readable catalog + coverage enums |
| `technique_classifier.py` | Rule engine (ASIA CCS + iRed rules) |
| `payload_classifier.py` | PE / shellcode / DLL inference |
| `injection_api_manifest.py` | `PAPER_API_CLASSES` + `IRED_TEAM_API_CLASSES` |
| `tests/test_ired_team_classifier.py` | Unit tests for new rules |

---

*Last updated for Noirlycan thesis repo — cross-check iRed.team if pages move or new labs are added.*
