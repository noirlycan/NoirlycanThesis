from __future__ import annotations

from noirlycan_telemetry.models import FileEvent
from noirlycan_telemetry.sysmon import SysmonUnavailable, _evt_query_error, parse_sysmon_xml


class _AccessDeniedError(Exception):
    winerror = 5


def test_evt_query_error_maps_access_denied() -> None:
    mapped = _evt_query_error(_AccessDeniedError("Access is denied."))
    assert isinstance(mapped, SysmonUnavailable)
    assert "Access denied" in str(mapped)


def test_parse_sysmon_file_create_event() -> None:
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>11</EventID>
        <TimeCreated SystemTime="2026-06-07T17:20:00.0000000Z"/>
      </System>
      <EventData>
        <Data Name="Image">C:\\WINDOWS\\Explorer.EXE</Data>
        <Data Name="ProcessId">7084</Data>
        <Data Name="TargetFilename">D:\\thesis\\aes_decrypt_loader - Copy.exe</Data>
      </EventData>
    </Event>"""
    parsed = parse_sysmon_xml(xml)
    assert isinstance(parsed, FileEvent)
    assert parsed.path.endswith("aes_decrypt_loader - Copy.exe")
    assert parsed.creator_pid == 7084


def test_parse_sysmon_stream_hash_for_executable() -> None:
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>15</EventID>
        <TimeCreated SystemTime="2026-06-07T17:20:01.0000000Z"/>
      </System>
      <EventData>
        <Data Name="Image">C:\\WINDOWS\\Explorer.EXE</Data>
        <Data Name="ProcessId">7084</Data>
        <Data Name="TargetFilename">D:\\thesis\\aes_decrypt_loader - Copy.exe</Data>
      </EventData>
    </Event>"""
    parsed = parse_sysmon_xml(xml)
    assert isinstance(parsed, FileEvent)
    assert parsed.path.endswith("aes_decrypt_loader - Copy.exe")
