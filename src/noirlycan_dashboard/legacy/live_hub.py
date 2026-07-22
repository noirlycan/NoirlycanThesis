from __future__ import annotations

import asyncio
import weakref
from typing import Any

from channels.generic.websocket import AsyncJsonWebsocketConsumer

_loop: asyncio.AbstractEventLoop | None = None
_connections: weakref.WeakSet[AsyncJsonWebsocketConsumer] = weakref.WeakSet()


def bind_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _loop
    _loop = loop


def register(consumer: AsyncJsonWebsocketConsumer) -> None:
    _connections.add(consumer)


def unregister(consumer: AsyncJsonWebsocketConsumer) -> None:
    global _loop
    _connections.discard(consumer)
    if not _connections:
        _loop = None


async def _broadcast(message: dict[str, Any]) -> None:
    for consumer in list(_connections):
        try:
            await consumer.send_json(message)
        except Exception:
            unregister(consumer)


def _schedule(message: dict[str, Any]) -> None:
    if _loop is None or _loop.is_closed() or not _connections:
        return
    asyncio.run_coroutine_threadsafe(_broadcast(message), _loop)


def broadcast_runtime(payload: dict[str, Any]) -> None:
    _schedule({"type": "runtime", "runtime": payload})


def broadcast_refresh(*, reason: str = "logs") -> None:
    _schedule({"type": "refresh", "reason": reason})
