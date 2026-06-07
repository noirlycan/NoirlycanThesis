"""Frida fidelity driver — measure how many primitive emissions reach the
collector when the target process issues a known number of API calls.

Used to validate assumption **M5** in `docs/audit-and-threat-model.md`
("Frida user-mode hooks are accurate in argument and ordering"). Run this
**on the Windows lab VM** under the noirlycan-telemetry collector.

Protocol
--------

1.  Start the collector in *spawn* mode pointing at this script's compiled
    EXE (we drive the target via `ctypes`, no real malware required):

    .. code-block:: powershell

       noirlycan-telemetry spawn -- python -m tests.manual.frida_fidelity_driver

2.  This driver calls a fixed number `N` (default 1000) of `VirtualAlloc` +
    `WriteProcessMemory(self)` + `VirtualFree` triples in the **current**
    process, plus `N/10` cross-process `OpenProcess(self)` calls to give the
    hook a process-handle workout.

3.  At exit the driver writes its own counters to `frida_fidelity_emit.txt`.

4.  Compare with the collector's session JSONL:

    .. code-block:: powershell

       Get-Content logs\session-*.jsonl |
         Select-String '"api":"VirtualAlloc"' | Measure-Object

    Drop-rate = `1 - (frida_count / driver_count)`.

The Windows lab is the only environment where this is meaningful — the
script is *Windows-only* by construction. On other platforms it imports
cleanly but `main()` exits with an error.
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import sys
import time
from pathlib import Path

DEFAULT_ITERATIONS = 1000
ALLOC_SIZE = 0x1000  # one page
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _require_windows() -> None:
    if platform.system().lower() != "windows":
        sys.stderr.write(
            "frida_fidelity_driver is Windows-only. Run inside the lab VM.\n"
        )
        sys.exit(2)


def run(iterations: int = DEFAULT_ITERATIONS) -> dict[str, int]:
    _require_windows()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = (
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_uint32,
    )
    kernel32.VirtualFree.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32)
    kernel32.WriteProcessMemory.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    )
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)

    self_handle = kernel32.GetCurrentProcess()
    self_pid = os.getpid()

    counters = {
        "iterations": iterations,
        "virtual_alloc": 0,
        "write_process_memory": 0,
        "virtual_free": 0,
        "open_process": 0,
        "pid": self_pid,
    }

    payload = ctypes.create_string_buffer(b"\x90" * ALLOC_SIZE)
    written = ctypes.c_size_t(0)

    started = time.monotonic()
    for index in range(iterations):
        addr = kernel32.VirtualAlloc(None, ALLOC_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not addr:
            continue
        counters["virtual_alloc"] += 1
        ok = kernel32.WriteProcessMemory(self_handle, addr, payload, ALLOC_SIZE, ctypes.byref(written))
        if ok:
            counters["write_process_memory"] += 1
        if kernel32.VirtualFree(addr, 0, MEM_RELEASE):
            counters["virtual_free"] += 1
        if index % 10 == 0:
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, self_pid)
            if handle:
                counters["open_process"] += 1
                kernel32.CloseHandle(handle)

    counters["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return counters


def main() -> None:
    iterations = DEFAULT_ITERATIONS
    if len(sys.argv) > 1:
        iterations = int(sys.argv[1])
    counters = run(iterations)
    output = Path("frida_fidelity_emit.txt")
    output.write_text(json.dumps(counters, indent=2), encoding="utf-8")
    sys.stdout.write(json.dumps(counters, indent=2) + "\n")


if __name__ == "__main__":
    main()
