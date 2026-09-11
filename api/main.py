"""FastAPI application entry point for PS26145 Plane B monitoring service.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 17, 18, 19, design.md section 19.

Plane B is strictly read-only: GET and WebSocket only. No POST, PUT, PATCH, or DELETE.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router as http_router
from api.state import AppState
from api.websocket import ws_router
from ingest.capability import CapabilityState


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage application startup and clean background task shutdown."""
    service_state: AppState = getattr(app.state, "service_state", None)
    if service_state is not None:
        service_state.start_broadcast_task()
    yield
    if service_state is not None:
        service_state.close()


def create_app(
    db_path: str | Path = ":memory:",
    capability_state: CapabilityState | None = None,
    service_state: AppState | None = None,
) -> FastAPI:
    """Factory creating the Plane B FastAPI monitoring application."""
    app = FastAPI(
        title="Cyber Sentinel Plane B Monitoring API",
        version="1.3",
        description="Passive, read-only monitoring and export interface for PS26145.",
        lifespan=lifespan,
    )

    # Allow CORS for dashboard access (read-only methods)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["GET", "HEAD", "OPTIONS"],
        allow_headers=["*"],
    )

    # Attach shared service state
    if service_state is None:
        service_state = AppState(db_path=db_path, capability_state=capability_state)
    app.state.service_state = service_state

    # Include routes
    app.include_router(http_router)
    app.include_router(ws_router)

    return app


# Default singleton instance
app = create_app()
