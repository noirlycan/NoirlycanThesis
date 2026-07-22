"""Broadcast hub for console WebSocket clients."""

from __future__ import annotations

import asyncio
import json
from typing import Any

_connections: set[Any] = set()
_lock = asyncio.Lock()


async def register(websocket: Any) -> None:
    async with _lock:
        _connections.add(websocket)


async def unregister(websocket: Any) -> None:
    async with _lock:
        _connections.discard(websocket)


async def broadcast(message: dict[str, Any]) -> None:
    payload = json.dumps(message, ensure_ascii=False)
    async with _lock:
        targets = list(_connections)
    dead: list[Any] = []
    for socket in targets:
        try:
            await socket.send_text(payload)
        except Exception:
            dead.append(socket)
    if dead:
        async with _lock:
            for socket in dead:
                _connections.discard(socket)


def schedule_broadcast(message: dict[str, Any]) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(broadcast(message))
