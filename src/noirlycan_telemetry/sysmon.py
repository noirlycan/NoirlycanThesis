from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import datetime, timezone

from .models import FileEvent, ProcessEvent, TelemetryEvent, EventSource

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


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


def parse_sysmon_xml(xml: str) -> TelemetryEvent | FileEvent | ProcessEvent | None:
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
    if event_id == 11:
        return FileEvent(
            timestamp=timestamp,
            path=data.get("TargetFilename", ""),
            creator_pid=_safe_int(data.get("ProcessId")),
            creator_image=data.get("Image") or None,
        )
    if event_id in {7, 8, 10, 15, 22, 23, 26}:
        return TelemetryEvent(
            source=EventSource.SYSMON,
            kind=f"sysmon_eid_{event_id}",
            timestamp=timestamp,
            pid=_safe_int(data.get("ProcessId") or data.get("SourceProcessId")),
            process_image=data.get("Image") or data.get("SourceImage"),
            data=data,
        )
    return None


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

    def follow(self, interval_seconds: float = 1.0) -> Iterator[TelemetryEvent | FileEvent | ProcessEvent]:
        while True:
            yield from self.poll_once()
            time.sleep(interval_seconds)

    def poll_once(self) -> Iterator[TelemetryEvent | FileEvent | ProcessEvent]:
        win32evtlog = _load_win32evtlog()
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
        handle = win32evtlog.EvtQuery(self.channel, flags, self.query)
        batch = win32evtlog.EvtNext(handle, 128)
        rendered: list[tuple[int, str]] = []
        for event in batch:
            xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            record_id = self._record_id(xml)
            if self._last_record_id is not None and record_id <= self._last_record_id:
                continue
            rendered.append((record_id, xml))
        if rendered:
            self._last_record_id = max(record_id for record_id, _ in rendered)
        for _, xml in sorted(rendered, key=lambda item: item[0]):
            parsed = parse_sysmon_xml(xml)
            if parsed is not None:
                yield parsed

    @staticmethod
    def _record_id(xml: str) -> int:
        root = ET.fromstring(xml)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        node = root.find("./e:System/e:EventRecordID", ns)
        if node is None or node.text is None:
            return 0
        return int(node.text)
