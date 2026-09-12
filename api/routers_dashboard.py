from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from api.logging_utils import logfmt
from api.runtime import runtime_state
from api.services import handle_ws_message, serve_dashboard_response, websocket_init_payload
from config import config

router = APIRouter()
logger = logging.getLogger("honeypot_api")

dashboard_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard")


@router.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    authenticated = False
    try:
        await websocket.accept()
        origin = websocket.headers.get("origin")
        if origin and origin not in config.api.cors_origins:
            await websocket.close(code=1008, reason="Origin not allowed")
            return
        try:
            raw_auth = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
            auth_message = json.loads(raw_auth)
        except (asyncio.TimeoutError, json.JSONDecodeError, TypeError):
            await websocket.close(code=1008, reason="WebSocket authentication required")
            return
        if auth_message.get("type") != "auth" or not hmac.compare_digest(
            str(auth_message.get("api_key", "")), config.api.api_key
        ):
            await websocket.close(code=1008, reason="Invalid WebSocket credentials")
            return
        runtime_state.ws_manager.register(websocket)
        authenticated = True
        await websocket.send_text(json.dumps({"type": "auth_ok", "timestamp": time.time()}))
        await websocket.send_text(json.dumps(await websocket_init_payload(), default=str))
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                await handle_ws_message(json.loads(data), websocket)
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"type": "heartbeat", "timestamp": time.time()}))
            except WebSocketDisconnect:
                break
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.exception(logfmt("websocket_error", error=exc))
    finally:
        if authenticated:
            runtime_state.ws_manager.disconnect(websocket)


@router.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    return serve_dashboard_response(dashboard_dir)
