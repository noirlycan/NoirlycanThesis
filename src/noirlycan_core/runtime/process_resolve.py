from __future__ import annotations

import sys
from functools import lru_cache


def image_for_pid(pid: int | None) -> str | None:
    if pid is None or pid <= 0:
        return None
    if sys.platform != "win32":
        return None
    return _image_for_pid_windows(int(pid))


@lru_cache(maxsize=512)
def _image_for_pid_windows(pid: int) -> str | None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE

    query_name = kernel32.QueryFullProcessImageNameW
    query_name.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    query_name.restype = wintypes.BOOL

    handle = open_process(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32_768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not query_name(handle, 0, buffer, ctypes.byref(size)):
            return None
        path = buffer.value.strip()
        return path or None
    finally:
        kernel32.CloseHandle(handle)
