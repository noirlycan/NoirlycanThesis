"""Monitor Windows Filtering Platform audit events for connection attempts.

Security Event 5156 fires for EVERY outbound connection attempt permitted by
the firewall — regardless of whether the TCP handshake succeeds.  This lets us
detect beacon connect() calls even in sandboxes where the C2 is unreachable.

Requires: ``auditpol /set /subcategory:"Filtering Platform Connection" /success:enable``
"""

from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any

from noirlycan_core.kernel.entities.models import NetworkConnectionEvent


_PROTO_MAP = {"6": "tcp", "17": "udp"}


def enable_wfp_audit() -> bool:
    try:
        result = subprocess.run(
            [
                "auditpol", "/set",
                "/subcategory:Filtering Platform Connection",
                "/success:enable", "/failure:enable",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            print("[+] WFP connection audit enabled (Security 5156/5157)", flush=True)
            return True
        print(
            f"[!] Could not enable WFP audit (exit {result.returncode}): "
            f"{result.stderr.strip()}",
            file=sys.stderr,
            flush=True,
        )
    except Exception as exc:
        print(f"[!] Could not enable WFP audit: {exc}", file=sys.stderr, flush=True)
    return False


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_wfp_xml(xml_str: str) -> NetworkConnectionEvent | None:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", ns)
    if system is None:
        return None
    event_id_el = system.find("e:EventID", ns)
    if event_id_el is None:
        return None
    event_id = _safe_int(event_id_el.text)
    if event_id not in (5156, 5157):
        return None

    time_el = system.find("e:TimeCreated", ns)
    timestamp = datetime.now(timezone.utc)
    if time_el is not None:
        sys_time = time_el.get("SystemTime")
        if sys_time:
            try:
                timestamp = datetime.fromisoformat(
                    sys_time.replace("Z", "+00:00")
                ).astimezone(timezone.utc)
            except ValueError:
                pass

    data: dict[str, str] = {}
    event_data = root.find("e:EventData", ns)
    if event_data is None:
        return None
    for item in event_data:
        name = item.get("Name")
        if name and item.text:
            data[name] = item.text

    direction = data.get("Direction")
    if direction and direction.strip() != "%%14593":
        return None

    pid = _safe_int(data.get("ProcessID"))
    if pid is None:
        return None

    dest_ip = data.get("DestAddress")
    if not dest_ip:
        return None
    if dest_ip.startswith("127.") or dest_ip == "::1":
        return None

    dest_port = _safe_int(data.get("DestPort"))
    proto_num = data.get("Protocol", "6")
    proto = _PROTO_MAP.get(proto_num, f"proto_{proto_num}")

    image = data.get("Application")

    return NetworkConnectionEvent(
        timestamp=timestamp,
        pid=pid,
        image=data.get("Application"),
        protocol=proto,
        destination_ip=dest_ip,
        destination_hostname=None,
        destination_port=dest_port,
        initiated=True,
        succeeded=event_id == 5156,
        source="wfp",
    )


class WfpPoller:
    _QUERY = (
        '<QueryList>'
        '<Query Id="0" Path="Security">'
        '<Select Path="Security">*[System[(EventID=5156 or EventID=5157)]]</Select>'
        '</Query>'
        '</QueryList>'
    )

    def __init__(self) -> None:
        self._last_record_id: int | None = None

    def poll(self, watched_pids: set[int]) -> Iterator[NetworkConnectionEvent]:
        if not watched_pids:
            return
        win32evtlog = _load_win32evtlog()
        if win32evtlog is None:
            return

        if self._last_record_id is None:
            self._bootstrap_cursor(win32evtlog)
            return

        try:
            handle = win32evtlog.EvtQuery(
                None, self._QUERY,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
            )
        except Exception:
            return

        try:
            while True:
                try:
                    events = win32evtlog.EvtNext(handle, 50, -1, 0)
                except Exception:
                    break
                if not events:
                    break
                for event_handle in events:
                    try:
                        xml_str = win32evtlog.EvtRender(
                            event_handle, win32evtlog.EvtRenderEventXml
                        )
                        record_id = _extract_record_id(xml_str)
                        if record_id is not None:
                            if self._last_record_id is not None and record_id <= self._last_record_id:
                                continue
                            self._last_record_id = record_id
                        net_event = _parse_wfp_xml(xml_str)
                        if net_event is not None and net_event.pid in watched_pids:
                            yield net_event
                    except Exception:
                        continue
        finally:
            win32evtlog.EvtClose(handle)

    def _bootstrap_cursor(self, win32evtlog: Any) -> None:
        try:
            handle = win32evtlog.EvtQuery(
                None, self._QUERY,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
            )
        except Exception:
            self._last_record_id = 0
            return
        try:
            events = win32evtlog.EvtNext(handle, 1, -1, 0)
            if events:
                xml_str = win32evtlog.EvtRender(
                    events[0], win32evtlog.EvtRenderEventXml
                )
                rid = _extract_record_id(xml_str)
                self._last_record_id = rid if rid is not None else 0
            else:
                self._last_record_id = 0
        except Exception:
            self._last_record_id = 0
        finally:
            win32evtlog.EvtClose(handle)


def _extract_record_id(xml_str: str) -> int | None:
    try:
        root = ET.fromstring(xml_str)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        el = root.find("e:System/e:EventRecordID", ns)
        if el is not None and el.text:
            return int(el.text)
    except Exception:
        pass
    return None


def _load_win32evtlog() -> Any:
    try:
        import win32evtlog  # type: ignore[import-untyped]
        return win32evtlog
    except ImportError:
        return None
