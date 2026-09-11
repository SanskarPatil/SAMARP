"""WebSocket endpoint for live batched incident streaming (~250 ms cadence).

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 17, 18, 19, design.md section 19.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from api.state import AppState

logger = logging.getLogger("api.websocket")
ws_router = APIRouter()


@ws_router.websocket("/ws/incidents")
async def websocket_incidents_endpoint(websocket: WebSocket) -> None:
    """Live incident feed over WebSocket with batched delivery.

    On connection:
    - Accepts WebSocket connection.
    - Sends an initial snapshot of active incidents (up to 500 for the client ring buffer).
    - Subscribes to the ~250 ms batched broadcast from AppState.
    - Gracefully handles client disconnects and reconnections.
    """
    await websocket.accept()
    app_state: AppState = websocket.app.state.service_state

    # Send initial snapshot of recent incidents to populate the dashboard client ring buffer
    try:
        initial_incidents = app_state.store.list_incidents(limit=500)
        await websocket.send_json({
            "type": "snapshot",
            "count": len(initial_incidents),
            "incidents": initial_incidents,
            "capabilities": app_state.get_capabilities(),
        })
    except Exception as e:
        logger.warning("Failed to send initial websocket snapshot: %s", e)
        await websocket.close()
        return

    await app_state.register_websocket(websocket)

    try:
        while True:
            # Maintain connection and listen for client pings / text
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug("WebSocket client connection ended: %s", e)
    finally:
        await app_state.unregister_websocket(websocket)
