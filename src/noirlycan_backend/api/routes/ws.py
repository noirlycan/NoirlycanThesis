from __future__ import annotations

from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from noirlycan_backend.infrastructure.live_hub import broadcast, register, unregister

router = APIRouter(tags=["ws"])


@router.websocket("/ws/live")
async def live_socket(websocket: WebSocket) -> None:
    await websocket.accept()
    await register(websocket)
    try:
        await websocket.send_json({"type": "connected"})
        while True:
            message = await websocket.receive_text()
            if message.strip().lower() in {"ping", "refresh"}:
                await websocket.send_json({"type": "refresh"})
    except WebSocketDisconnect:
        pass
    finally:
        await unregister(websocket)
