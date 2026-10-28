"""Evidence from kernel-sourced telemetry (repo extension, not part of the paper).

The paper filters API calls by return address and notes that a gadget could
fool that filter unless "the legitimacy of the return address" is verified
(§3.3). Sysmon EID 10 records the call stack of every cross-process handle
open, captured in the kernel, which lets us do that check:

* the innermost frame must be ``ntdll.dll`` or ``win32u.dll`` — otherwise the
  syscall was issued from somewhere else (direct syscall);
* a frame Sysmon cannot map to a module (``UNKNOWN``) is code running from
  unbacked memory, typically shellcode or a reflectively loaded image.

Observer effect: Frida's Interceptor runs hooked prologues from trampolines
in unbacked memory, so while Frida is attached to the actor its own frames
show up as ``UNKNOWN``. Unbacked frames therefore only count when the actor
was *not* instrumented — exactly the case where the hooks were bypassed.
The innermost-frame check is unaffected (the stub is still in ntdll).

It also compares sensors: if Frida saw the actor's other primitives but not a
remote thread that the kernel did see, the user-mode hook was bypassed.

None of this decides *whether* a chain is an injection — that stays with the
paper's rules. It only adds evidence and score to chains that already passed.
"""

from __future__ import annotations

from dataclasses import dataclass

from noirlycan_core.models import MemoryPrimitive, PrimitiveKind, ProcessAccessEvent

_SYSCALL_STUB_MODULES = ("\\ntdll.dll", "\\win32u.dll")
_REMOTE_THREAD_APIS = frozenset(
    {"createremotethread", "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread", "zwcreatethreadex"}
)
# PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD
INJECTION_ACCESS_MASK = 0x0008 | 0x0020 | 0x0002

UNBACKED_CALLER_BONUS = 10
DIRECT_SYSCALL_BONUS = 10
HOOK_BYPASS_BONUS = 10


@dataclass(frozen=True)
class CallTraceVerdict:
    direct_syscall: bool
    unbacked_frames: int


def read_call_trace(call_trace: str) -> CallTraceVerdict | None:
    frames = [frame.strip() for frame in call_trace.split("|") if frame.strip()]
    if not frames:
        return None
    innermost = frames[0].lower()
    return CallTraceVerdict(
        direct_syscall=not any(module in innermost for module in _SYSCALL_STUB_MODULES),
        unbacked_frames=sum(frame.upper().startswith("UNKNOWN") for frame in frames),
    )


def kernel_evidence(
    primitives: list[MemoryPrimitive],
    accesses: list[ProcessAccessEvent],
) -> tuple[int, dict[str, object]]:
    """Score bonus and evidence for one (actor, victim) chain."""
    bonus = 0
    evidence: dict[str, object] = {}
    sources = sorted({primitive.source for primitive in primitives})
    evidence["sensors"] = sources

    injection_handles = [access for access in accesses if access.granted_access & INJECTION_ACCESS_MASK]
    if injection_handles:
        evidence["handle_access"] = sorted({hex(access.granted_access) for access in injection_handles})
        evidence["call_trace_sample"] = [
            access.call_trace[:400] for access in injection_handles[-2:] if access.call_trace
        ]
    verdicts = [verdict for access in injection_handles if (verdict := read_call_trace(access.call_trace))]
    frida_attached = any(primitive.source == "frida" for primitive in primitives)
    if any(verdict.unbacked_frames for verdict in verdicts):
        if frida_attached:
            evidence["unbacked_caller_unreliable"] = "frida trampolines"
        else:
            evidence["unbacked_caller"] = True
            bonus += UNBACKED_CALLER_BONUS
    if any(verdict.direct_syscall for verdict in verdicts):
        evidence["direct_syscall"] = True
        bonus += DIRECT_SYSCALL_BONUS

    if _hook_bypass_suspected(primitives):
        evidence["hook_bypass_suspected"] = True
        bonus += HOOK_BYPASS_BONUS
    if any(primitive.details.get("unbacked_start") for primitive in primitives):
        evidence["unbacked_thread_start"] = True
    return bonus, evidence


def _hook_bypass_suspected(primitives: list[MemoryPrimitive]) -> bool:
    """Kernel saw a remote thread; Frida was attached to the actor but saw none."""
    frida_attached = any(primitive.source == "frida" for primitive in primitives)
    kernel_thread = any(
        primitive.source == "sysmon" and primitive.kind == PrimitiveKind.EXECUTE for primitive in primitives
    )
    frida_thread = any(
        primitive.source == "frida" and primitive.api.lower() in _REMOTE_THREAD_APIS for primitive in primitives
    )
    return frida_attached and kernel_thread and not frida_thread
