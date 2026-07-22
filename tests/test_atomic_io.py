from __future__ import annotations

from pathlib import Path

from noirlycan_core.storage.infrastructure.atomic_io import atomic_write_text


def test_atomic_write_text_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    atomic_write_text(target, '{"ok": true}\n')
    assert target.read_text(encoding="utf-8") == '{"ok": true}\n'
