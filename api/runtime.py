from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from fastapi import WebSocket

from api.logging_utils import logfmt

logger = logging.getLogger("honeypot_api")


@dataclass
class APIMetrics:
    honeypot_requests: int = 0
    honeypot_failures: int = 0
    email_requests: int = 0
    email_failures: int = 0
    telemetry_requests: int = 0
    telemetry_failures: int = 0
    ingest_requests: Dict[str, int] = field(default_factory=dict)
    ingest_failures: Dict[str, int] = field(default_factory=dict)
    incidents_created: int = 0
    containment_actions: int = 0
    containment_failures: int = 0
    simulation_runs: int = 0
    simulation_failures: int = 0
    websocket_messages_sent: int = 0

    def record_ingest(self, source: str, success: bool) -> None:
        target = self.ingest_requests if success else self.ingest_failures
        target[source] = target.get(source, 0) + 1

    def snapshot(self) -> Dict[str, object]:
        return {
            "honeypot_requests": self.honeypot_requests,
            "honeypot_failures": self.honeypot_failures,
            "email_requests": self.email_requests,
            "email_failures": self.email_failures,
            "telemetry_requests": self.telemetry_requests,
            "telemetry_failures": self.telemetry_failures,
            "ingest_requests": dict(self.ingest_requests),
            "ingest_failures": dict(self.ingest_failures),
            "incidents_created": self.incidents_created,
            "containment_actions": self.containment_actions,
            "containment_failures": self.containment_failures,
            "simulation_runs": self.simulation_runs,
            "simulation_failures": self.simulation_failures,
            "websocket_messages_sent": self.websocket_messages_sent,
        }

    def reset(self) -> None:
        self.honeypot_requests = 0
        self.honeypot_failures = 0
        self.email_requests = 0
        self.email_failures = 0
        self.telemetry_requests = 0
        self.telemetry_failures = 0
        self.ingest_requests.clear()
        self.ingest_failures.clear()
        self.incidents_created = 0
        self.containment_actions = 0
        self.containment_failures = 0
        self.simulation_runs = 0
        self.simulation_failures = 0
        self.websocket_messages_sent = 0


class ConnectionManager:
    """Manages WebSocket connections for real-time dashboard updates."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.register(websocket)

    def register(self, websocket: WebSocket) -> None:
        """Register an already-authenticated WebSocket for broadcasts."""
        self.active_connections.append(websocket)
        logger.info(logfmt("websocket_connect", connections=len(self.active_connections)))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(logfmt("websocket_disconnect", connections=len(self.active_connections)))

    async def broadcast(self, message: dict, metrics: APIMetrics) -> None:
        if not self.active_connections:
            return
        data = json.dumps(message, default=str)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
                metrics.websocket_messages_sent += 1
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)


class RuntimeState:
    def __init__(self) -> None:
        self.start_time = time.time()
        self.simulation_task: Optional[asyncio.Task] = None
        self.simulation_running = False
        self.ws_manager = ConnectionManager()
        self.metrics = APIMetrics()

    def uptime_seconds(self) -> float:
        return round(time.time() - self.start_time, 0)

    def reset(self) -> None:
        self.start_time = time.time()
        self.simulation_task = None
        self.simulation_running = False
        self.metrics.reset()


runtime_state = RuntimeState()
