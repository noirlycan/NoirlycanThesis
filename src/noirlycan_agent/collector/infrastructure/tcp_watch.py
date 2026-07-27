"""Poll the Windows TCP table for connections from watched PIDs.

Uses GetExtendedTcpTable (iphlpapi.dll) via ctypes — no extra packages.
Catches connection ATTEMPTS (SYN_SENT) as well as established connections,
unlike Sysmon EID 3 which only fires after a completed TCP handshake.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Set

from noirlycan_core.kernel.entities.models import NetworkConnectionEvent

_TCP_TABLE_OWNER_PID_ALL = 5
_AF_INET = 2

_MIB_TCP_STATE = {
    1: "CLOSED",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RCVD",
    5: "ESTABLISHED",
    6: "FIN_WAIT1",
    7: "FIN_WAIT2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}


class _MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.wintypes.DWORD),
        ("dwLocalAddr", ctypes.wintypes.DWORD),
        ("dwLocalPort", ctypes.wintypes.DWORD),
        ("dwRemoteAddr", ctypes.wintypes.DWORD),
        ("dwRemotePort", ctypes.wintypes.DWORD),
        ("dwOwningPid", ctypes.wintypes.DWORD),
    ]


def _ip_from_dword(dw: int) -> str:
    return f"{dw & 0xFF}.{(dw >> 8) & 0xFF}.{(dw >> 16) & 0xFF}.{(dw >> 24) & 0xFF}"


def _port_from_dword(dw: int) -> int:
    return ((dw & 0xFF) << 8) | ((dw >> 8) & 0xFF)


def _get_tcp_table() -> list[_MIB_TCPROW_OWNER_PID]:
    iphlpapi = ctypes.windll.iphlpapi
    size = ctypes.wintypes.DWORD(0)
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, _AF_INET, _TCP_TABLE_OWNER_PID_ALL, 0)
    buf = (ctypes.c_byte * size.value)()
    ret = iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, _AF_INET, _TCP_TABLE_OWNER_PID_ALL, 0)
    if ret != 0:
        return []
    num_entries = ctypes.c_uint32.from_buffer(buf, 0).value
    rows = []
    offset = ctypes.sizeof(ctypes.c_uint32)
    row_size = ctypes.sizeof(_MIB_TCPROW_OWNER_PID)
    for i in range(num_entries):
        row = _MIB_TCPROW_OWNER_PID.from_buffer_copy(buf, offset + i * row_size)
        rows.append(row)
    return rows


class TcpWatchPoller:
    def __init__(self) -> None:
        self._seen: set[tuple[int, str, int, int]] = set()

    def poll(self, watched_pids: Set[int]) -> Iterator[NetworkConnectionEvent]:
        if not watched_pids:
            return
        try:
            rows = _get_tcp_table()
        except Exception:
            return
        current = set()
        for row in rows:
            if row.dwOwningPid not in watched_pids:
                continue
            state = row.dwState
            if state == 2:
                continue
            remote_ip = _ip_from_dword(row.dwRemoteAddr)
            if remote_ip == "0.0.0.0":
                continue
            remote_port = _port_from_dword(row.dwRemotePort)
            key = (row.dwOwningPid, remote_ip, remote_port, state)
            current.add(key)
            if key in self._seen:
                continue
            state_name = _MIB_TCP_STATE.get(state, f"state_{state}")
            yield NetworkConnectionEvent(
                timestamp=datetime.now(timezone.utc),
                pid=row.dwOwningPid,
                image=None,
                protocol=f"tcp/{state_name}",
                destination_ip=remote_ip,
                destination_hostname=None,
                destination_port=remote_port,
                initiated=True,
                succeeded=state == 5,
                source="tcp_table",
            )
        self._seen = current
