from __future__ import annotations

import asyncio
import json
from pathlib import Path

from channels.testing import WebsocketCommunicator

from noirlycan_telemetry.services.dashboard import configure
from noirlycan_telemetry.services.dashboard.asgi import application
from noirlycan_telemetry.services.collector.application.runtime_config import touch_collector_heartbeat


def test_dashboard_websocket_runtime_message(tmp_path: Path) -> None:
    configure(tmp_path)
    touch_collector_heartbeat(logs_dir=tmp_path, watch_paths=["D:\\samples"])

    async def _run() -> None:
        communicator = WebsocketCommunicator(application, "/ws/dashboard/")
        connected, _ = await communicator.connect()
        assert connected

        message = await communicator.receive_json_from(timeout=3)
        assert message["type"] == "runtime"
        assert message["runtime"]["collector_online"] is True
        assert message["runtime"]["watch_paths"] == ["D:\\samples"]

        await communicator.disconnect()

    asyncio.run(_run())


def test_runtime_post_broadcasts_over_websocket(tmp_path: Path) -> None:
    configure(tmp_path)
    from asgiref.sync import sync_to_async

    from noirlycan_telemetry.services.dashboard import make_client

    client = make_client(tmp_path)

    async def _run() -> None:
        communicator = WebsocketCommunicator(application, "/ws/dashboard/")
        connected, _ = await communicator.connect()
        assert connected

        await communicator.receive_json_from(timeout=3)

        @sync_to_async(thread_sensitive=False)
        def post_runtime() -> object:
            return client.post(
                "/api/runtime",
                data=json.dumps({"file_drop_watch_enabled": False}),
                content_type="application/json",
            )

        response = await post_runtime()
        assert response.status_code == 200

        message = await communicator.receive_json_from(timeout=3)
        assert message["type"] == "runtime"
        assert message["runtime"]["file_drop_watch_enabled"] is False

        await communicator.disconnect()

    asyncio.run(_run())
