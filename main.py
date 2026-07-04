"""
SwarmSentinel — Agentic Honeypot + Ant Swarm Intelligence Backend
================================================================

FastAPI application with:
- Original honeypot conversation endpoints
- Telemetry ingestion + swarm pheromone publishing
- Ant agent system (Scout/Soldier/Queen) with asyncio
- Real-time WebSocket dashboard broadcasting
- Pheromone graph queries and simulation control
- Incident management with MITRE ATT&CK mapping
"""

from fastapi import FastAPI, Depends, HTTPException, Body, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from collections import defaultdict, deque
from threading import Lock
import asyncio
import json
import logging
import os
import time
from typing import List, Dict, Any

from schemas import ScamAnalysisResponse, ActionRequest, SimulationControl
from controller import handle_message

app = FastAPI(title="SwarmSentinel — Honeypot + Swarm Intelligence")

# ── CORS ──────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth + Rate Limiting ──────────────────────────────────────────────
API_KEY = (os.getenv("API_KEY") or "").strip()
api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("honeypot_api")

_rate_limit_buckets: dict[str, deque[float]] = defaultdict(deque)
_rate_limit_lock = Lock()


def verify_api_key(api_key: str = Depends(api_key_header)):
    if not API_KEY:
        raise HTTPException(status_code=503, detail="API key is not configured on the server.")
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _is_rate_limited(client_ip: str) -> bool:
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    with _rate_limit_lock:
        bucket = _rate_limit_buckets[client_ip]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_REQUESTS:
            return True
        bucket.append(now)
        return False


# ── WebSocket Manager ─────────────────────────────────────────────────

class ConnectionManager:
    """Manages WebSocket connections for real-time dashboard updates."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected (%d total)", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info("WebSocket client disconnected (%d remaining)", len(self.active_connections))

    async def broadcast(self, message: dict):
        """Send a message to all connected WebSocket clients."""
        if not self.active_connections:
            return
        data = json.dumps(message, default=str)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)


ws_manager = ConnectionManager()


# ── Swarm + Simulation State ─────────────────────────────────────────

_simulation_task = None
_simulation_running = False
_start_time = time.time()


# ── Dashboard static files ───────────────────────────────────────────

dashboard_dir = os.path.join(os.path.dirname(__file__), "dashboard")
if os.path.isdir(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="dashboard_static")


# =====================================================================
#  ORIGINAL HONEYPOT ENDPOINTS
# =====================================================================

@app.get("/")
async def root():
    return {"status": "ok", "service": "SwarmSentinel", "docs": "/docs", "dashboard": "/dashboard"}


@app.get("/health")
async def health():
    """Deep health check with dependency status."""
    from swarm_graph import pheromone_graph
    from event_queue import event_queue
    from config import config
    import sys

    graph_stats = pheromone_graph.get_stats()
    queue_stats = event_queue.stats()

    return {
        "status": "healthy",
        "service": "SwarmSentinel",
        "version": config.version,
        "environment": config.environment,
        "python": sys.version.split()[0],
        "graph": {
            "nodes": graph_stats["node_count"],
            "edges": graph_stats["edge_count"],
            "total_pheromone": round(graph_stats["total_pheromone"], 1),
            "backend": config.graph.backend,
        },
        "queue": {
            "depth": queue_stats["current_depth"],
            "throughput_eps": queue_stats["throughput_eps"],
            "backpressure": queue_stats.get("backpressure_active", False),
        },
        "simulation_running": _simulation_running,
        "uptime_seconds": round(time.time() - _start_time, 0),
    }


@app.get("/metrics")
async def metrics(api_key: str = Depends(verify_api_key)):
    """Operational metrics for monitoring and observability."""
    from swarm_graph import pheromone_graph
    from event_queue import event_queue
    from ingestion import ingestion_engine
    from containment import containment_engine
    from config import config
    import sys, os

    return {
        "system": {
            "version": config.version,
            "environment": config.environment,
            "uptime_seconds": round(time.time() - _start_time, 0),
            "pid": os.getpid(),
        },
        "graph": pheromone_graph.get_stats(),
        "queue": event_queue.stats(),
        "ingestion": ingestion_engine.stats(),
        "containment": containment_engine.stats(),
        "config": config.to_dict(),
    }


@app.post("/honeypot", response_model=ScamAnalysisResponse)
async def honeypot(
    request: Request,
    body: dict = Body(default=None),
    api_key: str = Depends(verify_api_key),
):
    start = time.perf_counter()
    client_ip = _get_client_ip(request)

    if _is_rate_limited(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    if not body:
        conversation_id = "guvi-test"
        message = "test message"
    else:
        conversation_id = body.get("conversation_id", "guvi-test")
        message = body.get("message", "test message")

    try:
        response = handle_message(
            conversation_id=conversation_id,
            message=message,
            ip=client_ip,
            user_agent=request.headers.get("user-agent", "unknown"),
        )
        logger.info(
            "honeypot_request_ok ip=%s conversation_id=%s latency_ms=%d",
            client_ip, conversation_id, int((time.perf_counter() - start) * 1000),
        )
        return response
    except Exception:
        logger.exception("honeypot_request_failed ip=%s", client_ip)
        raise HTTPException(status_code=500, detail="Internal processing error.")


@app.get("/debug/gemini")
async def debug_gemini(api_key: str = Depends(verify_api_key)):
    """Test endpoint to verify Gemini API is working"""
    import google.generativeai as genai
    api_key_value = os.getenv("GOOGLE_AI_STUDIO_KEY", "")
    result = {
        "api_key_present": bool(api_key_value),
        "api_key_length": len(api_key_value) if api_key_value else 0,
    }
    try:
        genai.configure(api_key=api_key_value)
        models = genai.list_models()
        result["available_models"] = [
            {"name": m.name, "supports_generate_content": "generateContent" in m.supported_generation_methods}
            for m in models
        ]
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {str(e)}"
    return result


@app.get("/admin/flagged-intelligence")
async def get_flagged_intelligence_stats(api_key: str = Depends(verify_api_key)):
    from storage import get_flagged_intelligence_stats
    return get_flagged_intelligence_stats()


# =====================================================================
#  TELEMETRY + SWARM ENDPOINTS
# =====================================================================

@app.post("/telemetry")
async def ingest_telemetry(
    request: Request,
    body: dict = Body(default=None),
    api_key: str = Depends(verify_api_key),
):
    """Ingest a telemetry event, publish pheromone, run correlation."""
    from swarm import publish_pheromone
    from correlation import evaluate_correlation
    from schemas import TelemetryEvent

    if not body:
        raise HTTPException(status_code=400, detail="Missing telemetry body")

    try:
        telemetry = TelemetryEvent(**body)
        pub = publish_pheromone(telemetry.dict())
        incidents = evaluate_correlation()

        # Broadcast graph update to dashboard
        await _broadcast_graph_update()

        if incidents:
            for inc in incidents:
                await ws_manager.broadcast({
                    "type": "incident",
                    "data": inc,
                    "timestamp": time.time(),
                })

        return {"published": pub["published"], "incidents_created": incidents}
    except Exception as e:
        logger.exception("telemetry_ingest_failed")
        raise HTTPException(status_code=500, detail=str(e))


# =====================================================================
#  LOG INGESTION (Real data sources)
# =====================================================================

@app.post("/ingest/json")
async def ingest_json(
    body: dict = Body(default=None),
    api_key: str = Depends(verify_api_key),
):
    """Ingest a JSON event from any SIEM/EDR source."""
    from ingestion import ingestion_engine
    from swarm import publish_pheromone
    from correlation import evaluate_correlation

    if not body:
        raise HTTPException(status_code=400, detail="Missing request body")

    event = ingestion_engine.ingest_json(body)
    if not event:
        raise HTTPException(status_code=422, detail="Could not parse event")

    pub = publish_pheromone(event)
    incidents = evaluate_correlation()
    await _broadcast_graph_update()

    if incidents:
        for inc in incidents:
            await ws_manager.broadcast({"type": "incident", "data": inc, "timestamp": time.time()})

    return {"status": "ingested", "event": pub["published"], "incidents": len(incidents)}


@app.post("/ingest/syslog")
async def ingest_syslog(
    body: dict = Body(default=None),
    api_key: str = Depends(verify_api_key),
):
    """Ingest syslog-formatted log lines."""
    from ingestion import ingestion_engine
    from swarm import publish_pheromone
    from correlation import evaluate_correlation

    if not body or "raw" not in body:
        raise HTTPException(status_code=400, detail="Missing 'raw' field with syslog line")

    lines = body["raw"] if isinstance(body["raw"], list) else [body["raw"]]
    results = []

    for line in lines[:100]:  # cap at 100 lines per request
        event = ingestion_engine.ingest_syslog(str(line))
        if event:
            pub = publish_pheromone(event)
            results.append(pub["published"])

    if results:
        evaluate_correlation()
        await _broadcast_graph_update()

    return {"status": "ingested", "count": len(results)}


@app.post("/ingest/csv")
async def ingest_csv(
    body: dict = Body(default=None),
    api_key: str = Depends(verify_api_key),
):
    """Ingest CSV-formatted log data."""
    from ingestion import ingestion_engine
    from swarm import publish_pheromone
    from correlation import evaluate_correlation

    if not body or "csv" not in body:
        raise HTTPException(status_code=400, detail="Missing 'csv' field with CSV data")

    events = ingestion_engine.ingest_csv(body["csv"], body.get("column_map"))
    for event in events:
        publish_pheromone(event)

    if events:
        evaluate_correlation()
        await _broadcast_graph_update()

    return {"status": "ingested", "count": len(events)}


# =====================================================================
#  CONTAINMENT
# =====================================================================

@app.post("/containment/action")
async def containment_action(
    body: dict = Body(default=None),
    api_key: str = Depends(verify_api_key),
):
    """Execute a containment action (block_ip, isolate_host, disable_user, escalate, release)."""
    from containment import containment_engine

    if not body or "action" not in body or "entity_id" not in body:
        raise HTTPException(status_code=400, detail="Required: action, entity_id")

    result = containment_engine.execute_action(
        action=body["action"],
        entity_id=body["entity_id"],
        entity_type=body.get("entity_type", "ip"),
        actor=body.get("actor", "dashboard"),
        reason=body.get("reason", ""),
        incident_id=body.get("incident_id"),
        ttl_seconds=body.get("ttl_seconds"),
    )

    # Broadcast to dashboard
    await ws_manager.broadcast({
        "type": "containment_action",
        "data": result,
        "timestamp": time.time(),
    })

    return result


@app.get("/containment/blocklist")
async def get_blocklist(api_key: str = Depends(verify_api_key)):
    """Current IP blocklist."""
    from containment import containment_engine
    return {"blocklist": containment_engine.get_blocklist()}


@app.get("/containment/audit")
async def get_containment_audit(
    entity_id: str = None,
    limit: int = 50,
    api_key: str = Depends(verify_api_key),
):
    """Containment action audit trail."""
    from containment import containment_engine
    return {"audit": containment_engine.get_audit_trail(entity_id=entity_id, limit=limit)}


@app.get("/swarm/status")
async def swarm_status(api_key: str = Depends(verify_api_key)):
    """Get swarm health: ant counts, graph stats, active investigations."""
    from ant_agents import swarm_coordinator
    from swarm_graph import pheromone_graph
    status = swarm_coordinator.get_status()
    status["graph_stats"] = pheromone_graph.get_stats()
    status["simulation_running"] = _simulation_running
    return status


@app.get("/swarm/graph")
async def swarm_graph_snapshot(api_key: str = Depends(verify_api_key)):
    """Full pheromone graph snapshot for visualization."""
    from swarm_graph import pheromone_graph
    return pheromone_graph.to_snapshot()


@app.get("/swarm/hotspots")
async def swarm_hotspots(top_n: int = 10, api_key: str = Depends(verify_api_key)):
    """Top-N highest pheromone nodes."""
    from swarm_graph import pheromone_graph
    return {"hotspots": pheromone_graph.get_hotspots(top_n=top_n)}


@app.get("/swarm/corridors")
async def swarm_corridors(min_strength: float = 0.5, api_key: str = Depends(verify_api_key)):
    """Detected attack corridors (high-weight edges)."""
    from swarm_graph import pheromone_graph
    return {"corridors": pheromone_graph.get_attack_corridors(min_strength=min_strength)}


@app.get("/swarm/activity")
async def swarm_activity(limit: int = 20, api_key: str = Depends(verify_api_key)):
    """Recent ant activity feed."""
    from ant_agents import swarm_coordinator
    return {"activity": swarm_coordinator.get_recent_activity(limit=limit)}


@app.get("/swarm/scenarios")
async def list_scenarios():
    """List available simulation scenarios."""
    from telemetry_simulator import TelemetrySimulator
    sim = TelemetrySimulator()
    return {"scenarios": sim.get_available_scenarios()}


# =====================================================================
#  RESET / CLEAR STATE
# =====================================================================

@app.post("/swarm/reset")
async def reset_swarm_state(api_key: str = Depends(verify_api_key)):
    """Clear all pheromone graph, incidents, and detector state for a fresh run."""
    from swarm_graph import pheromone_graph
    from storage import clear_all_state
    from detectors import reset_detectors

    pheromone_graph.clear()
    clear_all_state()
    reset_detectors()

    # Broadcast empty graph to dashboard
    await ws_manager.broadcast({
        "type": "graph_update",
        "data": pheromone_graph.to_snapshot(),
        "timestamp": time.time(),
    })

    logger.info("All swarm state reset")
    return {"status": "reset", "graph": pheromone_graph.get_stats()}


# =====================================================================
#  SIMULATION CONTROL
# =====================================================================

@app.post("/swarm/simulate")
async def control_simulation(
    body: dict = Body(default=None),
    api_key: str = Depends(verify_api_key),
):
    """Start/stop telemetry simulation or run a specific scenario."""
    global _simulation_task, _simulation_running

    if not body:
        raise HTTPException(status_code=400, detail="Missing request body")

    action = body.get("action", "scenario")
    scenario = body.get("scenario", "apt_killchain")

    if action == "stop":
        _simulation_running = False
        if _simulation_task and not _simulation_task.done():
            _simulation_task.cancel()
        return {"status": "stopped"}

    if action in ("start", "scenario"):
        if _simulation_running:
            return {"status": "already_running"}

        _simulation_running = True
        _simulation_task = asyncio.create_task(
            _run_simulation(scenario, body.get("events_per_second", 2.0))
        )
        return {"status": "started", "scenario": scenario}

    raise HTTPException(status_code=400, detail=f"Unknown action: {action}")


async def _run_simulation(scenario_name: str, events_per_second: float = 2.0):
    """Background task: feed simulated events through the swarm pipeline."""
    global _simulation_running
    from telemetry_simulator import TelemetrySimulator
    from swarm import publish_pheromone
    from correlation import evaluate_correlation

    sim = TelemetrySimulator()

    # Map scenario names to generator methods
    generators = {
        "normal_traffic": sim.generate_normal_traffic,
        "port_scan": sim.generate_port_scan,
        "credential_stuffing": sim.generate_credential_stuffing,
        "lateral_movement": sim.generate_lateral_movement,
        "data_exfiltration": sim.generate_data_exfiltration,
        "phishing_campaign": sim.generate_phishing_campaign,
        "apt_killchain": sim.generate_apt_killchain,
        "coordinated_attack": sim.generate_coordinated_attack,
    }

    generator = generators.get(scenario_name)
    if not generator:
        logger.error("Unknown scenario: %s", scenario_name)
        _simulation_running = False
        return

    events = generator()
    delay = 1.0 / events_per_second

    logger.info("🎬 Simulation started: %s (%d events, %.1f eps)", scenario_name, len(events), events_per_second)

    await ws_manager.broadcast({
        "type": "simulation_start",
        "data": {"scenario": scenario_name, "event_count": len(events)},
        "timestamp": time.time(),
    })

    for i, event in enumerate(events):
        if not _simulation_running:
            break

        try:
            # Override timestamp to "now" for live feel
            event["ts"] = time.time()
            pub = publish_pheromone(event)
            incidents = evaluate_correlation()

            # Broadcast telemetry event
            await ws_manager.broadcast({
                "type": "telemetry",
                "data": {
                    "event": pub["published"],
                    "graph_stats": pub.get("graph_stats", {}),
                    "progress": f"{i + 1}/{len(events)}",
                },
                "timestamp": time.time(),
            })

            # Broadcast graph update
            await _broadcast_graph_update()

            # Broadcast any new incidents
            if incidents:
                for inc in incidents:
                    await ws_manager.broadcast({
                        "type": "incident",
                        "data": inc,
                        "timestamp": time.time(),
                    })

        except Exception as e:
            logger.error("Simulation event %d failed: %s", i, e)

        await asyncio.sleep(delay)

    _simulation_running = False
    logger.info("🎬 Simulation complete: %s", scenario_name)
    await ws_manager.broadcast({
        "type": "simulation_end",
        "data": {"scenario": scenario_name},
        "timestamp": time.time(),
    })


async def _broadcast_graph_update():
    """Send current graph state to all WebSocket clients."""
    from swarm_graph import pheromone_graph
    snapshot = pheromone_graph.to_snapshot()
    await ws_manager.broadcast({
        "type": "graph_update",
        "data": snapshot,
        "timestamp": time.time(),
    })


# =====================================================================
#  SWARM LIFECYCLE (start/stop with app)
# =====================================================================

@app.post("/swarm/start")
async def start_swarm(api_key: str = Depends(verify_api_key)):
    """Start the ant swarm system."""
    from ant_agents import swarm_coordinator
    from swarm_graph import pheromone_graph

    if swarm_coordinator.is_running:
        return {"status": "already_running"}

    # Wire up WebSocket callbacks
    swarm_coordinator.on_graph_update = _on_swarm_graph_update
    swarm_coordinator.on_ant_activity = _on_ant_activity

    await swarm_coordinator.start(pheromone_graph)
    return {"status": "started", "scouts": swarm_coordinator.num_scouts}


@app.post("/swarm/stop")
async def stop_swarm(api_key: str = Depends(verify_api_key)):
    """Stop the ant swarm system."""
    from ant_agents import swarm_coordinator
    await swarm_coordinator.stop()
    return {"status": "stopped"}


async def _on_swarm_graph_update(snapshot: dict):
    """Callback from queen agent — broadcast graph update."""
    await ws_manager.broadcast({
        "type": "graph_update",
        "data": snapshot,
        "timestamp": time.time(),
    })


async def _on_ant_activity(activity: dict):
    """Callback from swarm coordinator — broadcast ant activity."""
    await ws_manager.broadcast({
        "type": "ant_activity",
        "data": activity,
        "timestamp": time.time(),
    })


# =====================================================================
#  INCIDENT MANAGEMENT
# =====================================================================

@app.get("/incidents")
async def list_all_incidents(api_key: str = Depends(verify_api_key)):
    from storage import list_incidents
    return {"incidents": list_incidents()}


@app.get("/playbooks")
async def list_playbook_actions(api_key: str = Depends(verify_api_key)):
    from policy import load_playbooks
    return {"playbooks": load_playbooks()}


@app.post("/incidents/{incident_id}/action")
async def take_incident_action(
    incident_id: int,
    body: dict = Body(default=None),
    api_key: str = Depends(verify_api_key),
):
    from policy import apply_action
    if not body:
        raise HTTPException(status_code=400, detail="Missing request body")
    try:
        action_request = ActionRequest(**body)
        result = apply_action(
            int(incident_id),
            action_request.action,
            actor=action_request.actor,
            params=action_request.params,
        )
        return result
    except Exception as e:
        logger.exception("incident_action_failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents/{incident_id}/audit")
async def incident_audit(incident_id: int, api_key: str = Depends(verify_api_key)):
    from storage import get_audit_log, get_incident
    incident = get_incident(int(incident_id))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incident": incident, "audit": get_audit_log(int(incident_id))}


# =====================================================================
#  EMAIL ANALYSIS
# =====================================================================

@app.post("/analyze-email")
async def analyze_email(
    request: Request,
    body: dict = Body(default=None),
    api_key: str = Depends(verify_api_key),
):
    from schemas import EmailAnalysisRequest
    from email_analyzer import analyze_email as analyze_email_func

    client_ip = _get_client_ip(request)
    if _is_rate_limited(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    try:
        if not body:
            raise HTTPException(status_code=400, detail="Missing email data")
        email_request = EmailAnalysisRequest(**body)
        response = analyze_email_func(email_request)
        return response
    except Exception:
        logger.exception("email_analyze_failed")
        raise HTTPException(status_code=500, detail="Internal processing error.")


# =====================================================================
#  WEBSOCKET
# =====================================================================

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time WebSocket for dashboard updates."""
    await ws_manager.connect(websocket)

    # Send initial state
    from swarm_graph import pheromone_graph
    from ant_agents import swarm_coordinator
    from storage import list_incidents

    try:
        initial = {
            "type": "init",
            "data": {
                "graph": pheromone_graph.to_snapshot(),
                "swarm": swarm_coordinator.get_status(),
                "incidents": list_incidents(),
                "simulation_running": _simulation_running,
            },
            "timestamp": time.time(),
        }
        await websocket.send_text(json.dumps(initial, default=str))

        # Keep connection alive and handle client messages
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                msg = json.loads(data)
                await _handle_ws_message(msg, websocket)
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_text(json.dumps({"type": "heartbeat", "timestamp": time.time()}))
            except WebSocketDisconnect:
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WebSocket error: %s", e)
    finally:
        ws_manager.disconnect(websocket)


async def _handle_ws_message(msg: dict, websocket: WebSocket):
    """Handle incoming WebSocket messages from the dashboard."""
    msg_type = msg.get("type", "")

    if msg_type == "request_graph":
        from swarm_graph import pheromone_graph
        await websocket.send_text(json.dumps({
            "type": "graph_update",
            "data": pheromone_graph.to_snapshot(),
            "timestamp": time.time(),
        }, default=str))

    elif msg_type == "request_status":
        from ant_agents import swarm_coordinator
        await websocket.send_text(json.dumps({
            "type": "swarm_status",
            "data": swarm_coordinator.get_status(),
            "timestamp": time.time(),
        }, default=str))


# =====================================================================
#  DASHBOARD
# =====================================================================

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the real-time SwarmSentinel dashboard."""
    dashboard_path = os.path.join(dashboard_dir, "index.html")
    if os.path.exists(dashboard_path):
        return FileResponse(dashboard_path, media_type="text/html")
    return HTMLResponse(content="<h1>Dashboard not found. Create dashboard/index.html</h1>", status_code=404)
