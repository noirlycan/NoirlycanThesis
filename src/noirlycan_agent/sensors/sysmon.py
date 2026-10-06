from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import datetime, timezone

from noirlycan_core.models import (
    FileEvent,
    NetworkConnectionEvent,
    ProcessEvent,
    TelemetryEvent,
    EventSource,
)
from noirlycan_agent.runtime.triage import is_interesting_path

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_INSTALL_HINT = (
    "Install Sysmon first, for example: "
    ".\\Sysmon\\Sysmon64.exe -accepteula -i .\\configs\\sysmon-noirlycan.xml"
)
SYSMON_ACCESS_HINT = (
    "Run PowerShell as Administrator to read Sysmon events, "
    "or add your user to the local 'Event Log Readers' group."
)


class SysmonUnavailable(RuntimeError):
    """Raised when Windows Event Log APIs are unavailable."""


def _load_win32evtlog():
    try:
        import win32evtlog  # type: ignore

        return win32evtlog
    except ImportError as exc:  # pragma: no cover - Windows-only dependency
        raise SysmonUnavailable(
            "pywin32 is required on Windows to read Sysmon events"
        ) from exc


def _evt_query_error(exc: BaseException) -> SysmonUnavailable | None:
    winerror = getattr(exc, "winerror", None)
    if winerror in {15007, 4201}:
        return SysmonUnavailable(
            f"Sysmon event log channel not found ({SYSMON_CHANNEL}). {SYSMON_INSTALL_HINT}"
        )
    if winerror == 5:
        return SysmonUnavailable(
            f"Access denied reading {SYSMON_CHANNEL}. {SYSMON_ACCESS_HINT}"
        )
    message = str(exc).lower()
    if "access is denied" in message or "access denied" in message:
        return SysmonUnavailable(
            f"Access denied reading {SYSMON_CHANNEL}. {SYSMON_ACCESS_HINT}"
        )
    return None


def _parse_utc(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _xml_data(xml: str) -> tuple[int | None, datetime, dict[str, str]]:
    root = ET.fromstring(xml)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    event_id_node = root.find("./e:System/e:EventID", ns)
    event_id = int(event_id_node.text) if event_id_node is not None else None
    time_node = root.find("./e:System/e:TimeCreated", ns)
    timestamp = _parse_utc(time_node.attrib.get("SystemTime") if time_node is not None else None)
    data: dict[str, str] = {}
    for node in root.findall("./e:EventData/e:Data", ns):
        name = node.attrib.get("Name")
        if name:
            data[name] = node.text or ""
    return event_id, timestamp, data


def parse_sysmon_xml(
    xml: str,
) -> TelemetryEvent | FileEvent | ProcessEvent | NetworkConnectionEvent | None:
    event_id, timestamp, data = _xml_data(xml)
    if event_id == 1:
        return ProcessEvent(
            timestamp=timestamp,
            pid=_safe_int(data.get("ProcessId")) or 0,
            image=data.get("Image", ""),
            command_line=data.get("CommandLine") or None,
            parent_pid=_safe_int(data.get("ParentProcessId")),
            parent_image=data.get("ParentImage") or None,
        )
    if event_id in {11, 15}:
        target = data.get("TargetFilename", "")
        if event_id == 15 and not _is_interesting_file_target(target):
            return TelemetryEvent(
                source=EventSource.SYSMON,
                kind=f"sysmon_eid_{event_id}",
                timestamp=timestamp,
                pid=_safe_int(data.get("ProcessId")),
                process_image=data.get("Image"),
                data=data,
            )
        return FileEvent(
            timestamp=timestamp,
            path=target,
            creator_pid=_safe_int(data.get("ProcessId")),
            creator_image=data.get("Image") or None,
        )
    if event_id == 3:
        initiated = data.get("Initiated")
        return NetworkConnectionEvent(
            timestamp=timestamp,
            pid=_safe_int(data.get("ProcessId")) or 0,
            image=data.get("Image") or None,
            protocol=data.get("Protocol") or None,
            destination_ip=data.get("DestinationIp") or None,
            destination_hostname=data.get("DestinationHostname") or None,
            destination_port=_safe_int(data.get("DestinationPort")),
            initiated=None if initiated is None else initiated.lower() == "true",
            # Sysmon's NetworkConnect (EID 3) only fires once the TCP
            # handshake actually completes — there's nothing to report here
            # for a connect() attempt that timed out or was refused.
            succeeded=True,
            source="sysmon",
        )
    if event_id in {7, 8, 10, 22, 23, 26}:
        return TelemetryEvent(
            source=EventSource.SYSMON,
            kind=f"sysmon_eid_{event_id}",
            timestamp=timestamp,
            pid=_safe_int(data.get("ProcessId") or data.get("SourceProcessId")),
            process_image=data.get("Image") or data.get("SourceImage"),
            data=data,
        )
    return None


def _is_interesting_file_target(path: str) -> bool:
    if not path:
        return False
    filename = path.rsplit("\\", 1)[-1]
    if ":" in filename:
        return False
    return is_interesting_path(path)


def _safe_int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


class SysmonPoller:
    """Polling reader for Sysmon's operational event log.

    The implementation intentionally uses polling rather than an event
    subscription callback so it can run as a simple console prototype.
    """

    def __init__(self, channel: str = SYSMON_CHANNEL, query: str = "*") -> None:
        self.channel = channel
        self.query = query
        self._last_record_id: int | None = None

    def follow(
        self, interval_seconds: float = 1.0
    ) -> Iterator[TelemetryEvent | FileEvent | ProcessEvent | NetworkConnectionEvent]:
        while True:
            yield from self.poll_once()
            time.sleep(interval_seconds)

    def poll_once(
        self,
        *,
        max_events: int = 200,
    ) -> Iterator[TelemetryEvent | FileEvent | ProcessEvent | NetworkConnectionEvent]:
        win32evtlog = _load_win32evtlog()
        if self._last_record_id is None:
            self._bootstrap_cursor(win32evtlog)
            return

        query = f"*[System/EventRecordID>{self._last_record_id}]"
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
        try:
            handle = win32evtlog.EvtQuery(self.channel, flags, query)
        except Exception as exc:
            mapped = _evt_query_error(exc)
            if mapped is not None:
                raise mapped from exc
            raise

        rendered: list[tuple[int, str]] = []
        while len(rendered) < max_events:
            try:
                batch = win32evtlog.EvtNext(handle, min(256, max_events - len(rendered)))
            except Exception:
                break
            if not batch:
                break
            for event in batch:
                xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                record_id = self._record_id(xml)
                if record_id <= (self._last_record_id or 0):
                    continue
                rendered.append((record_id, xml))
                if len(rendered) >= max_events:
                    break

        if not rendered:
            return
        self._last_record_id = max(record_id for record_id, _ in rendered)
        for _, xml in sorted(rendered, key=lambda item: item[0]):
            parsed = parse_sysmon_xml(xml)
            if parsed is not None:
                yield parsed

    def _bootstrap_cursor(self, win32evtlog) -> None:
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
        try:
            handle = win32evtlog.EvtQuery(self.channel, flags, self.query)
        except Exception as exc:
            mapped = _evt_query_error(exc)
            if mapped is not None:
                raise mapped from exc
            raise
        try:
            batch = win32evtlog.EvtNext(handle, 1)
        except Exception:
            return
        if not batch:
            return
        xml = win32evtlog.EvtRender(batch[0], win32evtlog.EvtRenderEventXml)
        self._last_record_id = self._record_id(xml)

    @staticmethod
    def _record_id(xml: str) -> int:
        root = ET.fromstring(xml)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        node = root.find("./e:System/e:EventRecordID", ns)
        if node is None or node.text is None:
            return 0
        return int(node.text)
