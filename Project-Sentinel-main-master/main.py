from __future__ import annotations

import logging
import os
import time
from collections import OrderedDict, defaultdict
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from api.routers_dashboard import dashboard_dir, router as dashboard_router
from api.routers_incidents import router as incidents_router
from api.routers_ingest import router as ingest_router
from api.routers_public import router as public_router
from api.routers_reports import router as reports_router
from api.routers_swarm import router as swarm_router
from api.dependencies import authorize_websocket, verify_api_key
from api.services import startup, shutdown
from config import config
from geo_intel import resolve_origin

logging.basicConfig(
    level=config.log_level,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: start queue + decay on boot, drain on shutdown."""
    await startup()
    yield
    await shutdown()


ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]

app = FastAPI(
    title="SwarmSentinel - Honeypot + Swarm Intelligence",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "x-api-key"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: blob: https://server.arcgisonline.com https://*.basemaps.cartocdn.com https://tile.openstreetmap.org; "
        "connect-src 'self' ws: wss:; frame-ancestors 'none'; object-src 'none';"
    )
    return response


logger_app = logging.getLogger("sentinel.app")


MAX_WS_CONNECTIONS_GLOBAL = 100
MAX_WS_CONNECTIONS_PER_IP = 5
MAX_STORED_EMAILS = 100
RATE_LIMIT_MAX_REQUESTS = config.api.rate_limit_requests
RATE_LIMIT_WINDOW_SECONDS = config.api.rate_limit_window_seconds
MAX_TRACKED_IPS = 2000
RATE_LIMIT_STORE: Dict[str, List[float]] = defaultdict(list)
EMAILS_DB: OrderedDict[str, Dict[str, Any]] = OrderedDict()


class RelayHopInput(BaseModel):
    ip: str = Field(..., max_length=64)
    domain: str = Field("", max_length=255)
    timestamp: Optional[str] = Field(None, max_length=64)


class EmailAnalyzeRequest(BaseModel):
    email_id: Optional[str] = Field(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    subject: str = Field("Suspicious Email Notice", max_length=255)
    sender: str = Field("unknown@attacker.net", max_length=255)
    recipient: str = Field("target@company.com", max_length=255)
    relay_chain: List[RelayHopInput] = Field(..., min_length=1, max_length=50)


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.ip_connections: Dict[str, int] = defaultdict(int)

    async def connect(self, websocket: WebSocket, client_ip: str) -> bool:
        if len(self.active_connections) >= MAX_WS_CONNECTIONS_GLOBAL or self.ip_connections[client_ip] >= MAX_WS_CONNECTIONS_PER_IP:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Connection limit reached")
            return False
        await websocket.accept()
        self.active_connections.append(websocket)
        self.ip_connections[client_ip] += 1
        return True

    def disconnect(self, websocket: WebSocket, client_ip: str):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if client_ip in self.ip_connections:
            self.ip_connections[client_ip] -= 1
            if self.ip_connections[client_ip] <= 0:
                del self.ip_connections[client_ip]

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection, connection.client.host if connection.client else "unknown")


manager = ConnectionManager()


def check_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    timestamps = [stamp for stamp in RATE_LIMIT_STORE[client_ip] if now - stamp < RATE_LIMIT_WINDOW_SECONDS]
    if len(RATE_LIMIT_STORE) > MAX_TRACKED_IPS:
        for ip, values in list(RATE_LIMIT_STORE.items()):
            if not values or now - values[-1] >= RATE_LIMIT_WINDOW_SECONDS:
                RATE_LIMIT_STORE.pop(ip, None)
    if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded: Maximum 30 trace submissions per minute. Please try again later.")
    timestamps.append(now)
    RATE_LIMIT_STORE[client_ip] = timestamps


def store_email(email_id: str, record: Dict[str, Any]):
    if email_id in EMAILS_DB:
        del EMAILS_DB[email_id]
    elif len(EMAILS_DB) >= MAX_STORED_EMAILS:
        EMAILS_DB.popitem(last=False)
    EMAILS_DB[email_id] = record


def _build_email_record(email_id: str, subject: str, sender: str, recipient: str, timestamp: str, campaign_id: str, relay_chain: list[dict[str, Any]]):
    origin_trace, processed_hops = resolve_origin(relay_chain)
    return {
        "email_id": email_id, "subject": subject, "sender": sender, "recipient": recipient,
        "timestamp": timestamp, "campaign_id": campaign_id,
        "origin_trace": origin_trace.model_dump(),
        "hops": [hop.model_dump() for hop in processed_hops],
    }, origin_trace, processed_hops


def seed_demo_data():
    sample_emails = [
        {
            "email_id": "EML-89412",
            "subject": "URGENT: Executive Wire Transfer Authorization",
            "sender": "ceo-update@executive-mail.org",
            "recipient": "finance@corp.local",
            "timestamp": "2026-09-12T07:45:12Z",
            "campaign_id": "CAMP-PHISH-01",
            "relay_chain": [
                {"ip": "185.220.101.5", "domain": "exit.tor-node.de", "timestamp": "2026-09-12T07:44:00Z"},
                {"ip": "198.51.100.42", "domain": "mta1.host-relay.com", "timestamp": "2026-09-12T07:44:30Z"},
                {"ip": "198.96.155.3", "domain": "mta2.host-relay.com", "timestamp": "2026-09-12T07:44:45Z"},
                {"ip": "10.0.1.50", "domain": "mail-gate.corp.local", "timestamp": "2026-09-12T07:45:12Z"},
            ],
        },
        {
            "email_id": "EML-65209",
            "subject": "Invoice #INV-2026-0994 Attached",
            "sender": "billing@global-suppliers.jp",
            "recipient": "ap@corp.local",
            "timestamp": "2026-09-12T06:15:00Z",
            "campaign_id": "CAMP-LEGIT-04",
            "relay_chain": [
                {"ip": "203.0.113.195", "domain": "mail.global-suppliers.jp", "timestamp": "2026-09-12T06:14:10Z"},
                {"ip": "103.21.244.0", "domain": "gateway.mumbai-isp.in", "timestamp": "2026-09-12T06:14:35Z"},
                {"ip": "10.0.1.50", "domain": "mail-gate.corp.local", "timestamp": "2026-09-12T06:15:00Z"},
            ],
        },
        {
            "email_id": "EML-10294",
            "subject": "Security Alert: Password Expiring",
            "sender": "security-alert@id-verify-portal.cc",
            "recipient": "user99@corp.local",
            "timestamp": "2026-09-12T08:05:22Z",
            "campaign_id": "CAMP-PHISH-01",
            "relay_chain": [
                {"ip": "198.96.155.3", "domain": "mail.privacy-host.ch", "timestamp": "2026-09-12T08:04:10Z"},
                {"ip": "157.240.22.35", "domain": "outbound.meta-proxy.com", "timestamp": "2026-09-12T08:04:50Z"},
                {"ip": "10.0.1.50", "domain": "mail-gate.corp.local", "timestamp": "2026-09-12T08:05:22Z"},
            ],
        },
    ]
    for item in sample_emails:
        record, _, _ = _build_email_record(
            item["email_id"], item["subject"], item["sender"], item["recipient"],
            item["timestamp"], item["campaign_id"], item["relay_chain"],
        )
        store_email(item["email_id"], record)


seed_demo_data()


@app.get("/email-dashboard", response_class=FileResponse)
async def serve_email_dashboard():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))


@app.get("/emails", dependencies=[Depends(verify_api_key)])
async def list_emails():
    return [
        {
            "email_id": email_id,
            "subject": email["subject"],
            "sender": email["sender"],
            "timestamp": email["timestamp"],
            "origin_ip": email["origin_trace"]["ip"],
            "origin_country": email["origin_trace"]["country"],
            "origin_city": email["origin_trace"]["city"],
            "latitude": email["origin_trace"]["latitude"],
            "longitude": email["origin_trace"]["longitude"],
            "is_tor": email["origin_trace"]["is_tor"],
            "is_vpn": email["origin_trace"]["is_vpn"],
            "is_hosting": email["origin_trace"]["is_hosting"],
            "confidence": email["origin_trace"]["confidence"],
        }
        for email_id, email in EMAILS_DB.items()
    ]


@app.get("/emails/{email_id}/trace", dependencies=[Depends(verify_api_key)])
async def get_email_trace(email_id: str):
    email = EMAILS_DB.get(email_id)
    if email is None:
        raise HTTPException(status_code=404, detail=f"Email ID '{email_id}' not found")
    return {
        **email,
        "campaign_clusters": [
            {"cluster_id": "CAMP-PHISH-01", "cluster_name": "Frankfurt/Zurich TOR Exit Phishing Cluster", "origin_asn": "AS24940 / AS34305", "total_emails": 14, "threat_level": "HIGH", "center_lat": 48.8, "center_lon": 8.6},
            {"cluster_id": "CAMP-LEGIT-04", "cluster_name": "APAC Business Invoices", "origin_asn": "AS2914", "total_emails": 45, "threat_level": "LOW", "center_lat": 35.6, "center_lon": 139.6},
        ],
    }


@app.post("/emails/analyze", dependencies=[Depends(verify_api_key), Depends(check_rate_limit)])
async def analyze_email_trace(request: EmailAnalyzeRequest):
    email_id = request.email_id or f"EML-{time.time_ns() // 1_000_000 % 100000}"
    relay_chain = [hop.model_dump() for hop in request.relay_chain]
    origin_trace, processed_hops = resolve_origin(relay_chain)
    campaign_id = "CAMP-PHISH-01" if (origin_trace.is_tor or origin_trace.is_vpn) else "CAMP-GENERIC"
    record = {
        "email_id": email_id,
        "subject": request.subject,
        "sender": request.sender,
        "recipient": request.recipient,
        "timestamp": "Just now",
        "campaign_id": campaign_id,
        "origin_trace": origin_trace.model_dump(),
        "hops": [hop.model_dump() for hop in processed_hops],
    }
    store_email(email_id, record)
    await manager.broadcast({
        "msg_type": "email_trace",
        "email_id": email_id,
        "subject": request.subject,
        "sender": request.sender,
        "origin_trace": origin_trace.model_dump(),
        "hops": [hop.model_dump() for hop in processed_hops],
    })
    return {"status": "success", "email_id": email_id, "origin_trace": origin_trace.model_dump(), "total_hops": len(processed_hops)}


@app.websocket("/ws")
async def email_trace_websocket(websocket: WebSocket):
    if not await authorize_websocket(websocket):
        return
    client_ip = websocket.client.host if websocket.client else "unknown"
    if not await manager.connect(websocket, client_ip):
        return
    try:
        await websocket.send_json({"msg_type": "system_status", "status": "connected", "message": "Connected to Geolocation Trace Live Stream"})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket, client_ip)


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
    logger_app.debug("Validation failure on %s: %s", request.url.path, exc.errors())
    return JSONResponse(
        status_code=422,
        content={
            "detail": "Request validation failed.",
            "errors": exc.errors(),
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    payload = {"detail": exc.detail}
    if not isinstance(exc.detail, str):
        payload = {
            "detail": "Request failed.",
            "errors": exc.detail,
        }
    return JSONResponse(status_code=exc.status_code, content=payload)


if os.path.isdir(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="dashboard_static")

email_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(email_static_dir):
    app.mount("/email-static", StaticFiles(directory=email_static_dir), name="email_static")

app.include_router(public_router)
app.include_router(reports_router)
app.include_router(ingest_router)
app.include_router(swarm_router)
app.include_router(incidents_router)
app.include_router(dashboard_router)
