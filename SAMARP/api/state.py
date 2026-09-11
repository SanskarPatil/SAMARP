"""Shared application state coordinating SQLite persistence, hash chain, and WebSocket broadcasts.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 17, 18, 19, design.md section 19.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from starlette.websockets import WebSocket, WebSocketState

from alerts.deduplicator import Deduplicator
from alerts.hash_chain import HashChainWriter
from api.persistence import SQLiteIncidentStore
from ingest.capability import CapabilityState, InputMode

logger = logging.getLogger("api.state")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AppState:
    """Central state manager for the Plane B read-only API service."""

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        capability_state: CapabilityState | None = None,
        deduplicator: Deduplicator | None = None,
        batch_interval: float = 0.25,
    ) -> None:
        self.store = SQLiteIncidentStore(db_path=db_path)
        last_seq, last_hash = self.store.get_latest_chain_state()
        self.chain_writer = HashChainWriter(initial_seq=last_seq, initial_prev_hash=last_hash)
        self.deduplicator = deduplicator or Deduplicator()
        self.capability_state = capability_state or CapabilityState(InputMode.PCAP_REPLAY)

        self.batch_interval = batch_interval
        self.active_websockets: set[WebSocket] = set()
        self.batch_queue: list[dict[str, Any]] = []

        self._start_time = datetime.now(timezone.utc)
        self._broadcast_task: asyncio.Task[None] | None = None
        self._running = False
        self._lock = asyncio.Lock()

    @property
    def uptime_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self._start_time).total_seconds()

    def get_health(self) -> dict[str, Any]:
        """Return system health and Plane B read-only status."""
        return {
            "status": "healthy",
            "read_only": True,
            "uptime_seconds": round(self.uptime_seconds, 2),
            "total_incidents": self.store.count_incidents(),
            "total_updates": self.store.count_updates(),
            "chain_seq": self.chain_writer.seq,
            "input_mode": str(self.capability_state.input_mode),
            "timestamp": _iso_now(),
        }

    def get_capabilities(self) -> dict[str, Any]:
        """Return serialized capability state conforming to frozen schema."""
        return self.capability_state.to_dict()

    def ingest_alert(self, raw_alert: dict[str, Any]) -> dict[str, Any]:
        """Deduplicate an alert into an incident, sign via hash chain, persist, and queue for push."""
        incident = self.deduplicator.process_alert(raw_alert)
        signed = self.chain_writer.append(incident)
        persisted = self.store.save_incident(signed)
        self.batch_queue.append(persisted)
        return persisted

    def record_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        """Sign and persist an incident directly, queuing for WebSocket broadcast."""
        signed = self.chain_writer.append(incident)
        persisted = self.store.save_incident(signed)
        self.batch_queue.append(persisted)
        return persisted

    def flush_batch(self) -> list[dict[str, Any]]:
        """Flush and return pending incident queue."""
        batch = list(self.batch_queue)
        self.batch_queue.clear()
        return batch

    async def register_websocket(self, ws: WebSocket) -> None:
        """Register an active client WebSocket connection."""
        self.active_websockets.add(ws)

    async def unregister_websocket(self, ws: WebSocket) -> None:
        """Unregister a disconnected client WebSocket."""
        self.active_websockets.discard(ws)

    async def broadcast_batch(self) -> None:
        """Broadcast queued incident batch to all connected WebSocket clients."""
        if not self.batch_queue or not self.active_websockets:
            return

        batch = self.flush_batch()
        message = {
            "type": "incident_batch",
            "timestamp": _iso_now(),
            "count": len(batch),
            "incidents": batch,
        }

        dead_connections: list[WebSocket] = []
        for ws in self.active_websockets:
            if ws.client_state != WebSocketState.CONNECTED:
                dead_connections.append(ws)
                continue
            try:
                await ws.send_json(message)
            except Exception:
                dead_connections.append(ws)

        for ws in dead_connections:
            self.active_websockets.discard(ws)

    async def _periodic_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self.batch_interval)
                await self.broadcast_batch()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in websocket broadcast loop: %s", e)

    def start_broadcast_task(self) -> None:
        """Start background broadcast loop if running inside an asyncio event loop."""
        if self._running:
            return
        self._running = True
        try:
            loop = asyncio.get_running_loop()
            self._broadcast_task = loop.create_task(self._periodic_loop())
        except RuntimeError:
            pass

    def stop_broadcast_task(self) -> None:
        """Stop background broadcast loop."""
        self._running = False
        if self._broadcast_task and not self._broadcast_task.done():
            self._broadcast_task.cancel()
            self._broadcast_task = None

    def close(self) -> None:
        """Clean shutdown of background tasks and SQLite database."""
        self.stop_broadcast_task()
        self.store.close()
