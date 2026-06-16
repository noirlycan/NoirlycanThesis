from __future__ import annotations

import asyncio

from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.conf import settings

from noirlycan_telemetry.services.collector.application.runtime_config import (
    load_runtime_config,
    runtime_config_payload,
)
from noirlycan_telemetry.services.storage.infrastructure.log_store import resolve_logs_dir
from .live_hub import bind_loop, register, unregister
from .live_sync import ensure_live_sync


class DashboardConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self) -> None:
        bind_loop(asyncio.get_running_loop())
        register(self)
        await self.accept()
        ensure_live_sync()
        await self.send_json(
            {
                "type": "runtime",
                "runtime": await self._runtime_payload(),
            }
        )

    async def disconnect(self, close_code: int) -> None:
        unregister(self)

    async def _runtime_payload(self) -> dict:
        logs_dir = resolve_logs_dir(getattr(settings, "NOIRLYCAN_LOGS_DIR", None) or None)
        config = await self._load_runtime_config(logs_dir)
        return runtime_config_payload(config)

    @staticmethod
    async def _load_runtime_config(logs_dir):
        from asgiref.sync import sync_to_async

        return await sync_to_async(load_runtime_config)(logs_dir)
