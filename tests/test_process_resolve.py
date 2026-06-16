from __future__ import annotations

import sys

import pytest

from noirlycan_telemetry.services.collector.infrastructure.process_resolve import image_for_pid


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only API")
def test_image_for_pid_current_process() -> None:
    image = image_for_pid(__import__("os").getpid())
    assert image is not None
    assert image.lower().endswith(".exe")
