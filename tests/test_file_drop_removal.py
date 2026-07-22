from __future__ import annotations

from noirlycan_backend.domain.findings_groups import _file_drops_for_display, file_drop_key


def test_file_drop_key_normalizes_windows_path() -> None:
    assert file_drop_key(r"C:\Users\Public\Downloads\test.exe") == "c:/users/public/downloads/test.exe"
    assert (
        file_drop_key(r"C:\Users\Public\Downloads\test.exe")
        == file_drop_key("C:/Users/Public/Downloads/test.exe")
    )


def test_removed_file_drops_hidden_from_display() -> None:
    stats = {
        "recent_triages": [
            {"path": r"C:\Users\Public\Downloads\keep.exe", "timestamp": "2026-01-01T00:00:00Z"},
            {"path": r"C:\Users\Public\Downloads\gone.exe", "timestamp": "2026-01-02T00:00:00Z"},
        ],
        "pending_file_drops": [
            {"path": r"C:\Users\Public\Downloads\pending.exe", "timestamp": "2026-01-03T00:00:00Z"},
        ],
    }
    removed = {file_drop_key(r"C:\Users\Public\Downloads\gone.exe")}
    rows = _file_drops_for_display(stats, removed_drops=removed)
    paths = {row["path"] for row in rows}
    assert r"C:\Users\Public\Downloads\keep.exe" in paths
    assert r"C:\Users\Public\Downloads\pending.exe" in paths
    assert r"C:\Users\Public\Downloads\gone.exe" not in paths
    assert all(row.get("drop_key") for row in rows)
