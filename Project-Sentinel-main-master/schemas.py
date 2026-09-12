import json
import re
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, RootModel, field_validator, model_validator

_SAFE_ENTITY_ID_PATTERN = re.compile(r"^[a-zA-Z0-9._:@\-\[\]/]{1,512}$")


class StrictRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class MessageRequest(StrictRequestModel):
    conversation_id: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=4000)


class ExtractedIntelligence(BaseModel):
    upi_ids: List[str] = Field(default_factory=list)
    bank_accounts: List[str] = Field(default_factory=list)
    phishing_links: List[str] = Field(default_factory=list)


class ScamAnalysisResponse(BaseModel):
    is_scam: bool
    scam_type: Optional[str]
    extracted_intelligence: Optional[ExtractedIntelligence]
    confidence: float
    honeypot_reply: str
    risk: Optional[Dict[str, Any]] = None
    blocked: bool = False
    blocked_message: Optional[str] = None
    flagged_match: bool = False


class EmailAnalysisRequest(StrictRequestModel):
    message_id: Optional[str] = Field(default=None, max_length=128)
    thread_id: Optional[str] = Field(default=None, max_length=128)
    from_email: str = Field(min_length=3, max_length=320)
    from_name: Optional[str] = Field(default=None, max_length=256)
    subject: Optional[str] = Field(default=None, max_length=512)
    message_text: str = Field(min_length=1, max_length=20000)
    links: List[str] = Field(default_factory=list, max_length=100)
    raw_headers: Optional[str] = Field(default=None, max_length=65536)
    raw_eml: Optional[str] = Field(default=None, max_length=2_000_000)


class RelayHop(BaseModel):
    hop_index: int
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    timestamp: Optional[datetime] = None
    delay_seconds: Optional[float] = None


class AuthProtocolResult(BaseModel):
    status: str
    domain: Optional[str] = None
    details: Optional[str] = None


class HeaderAnalysisResult(BaseModel):
    relay_chain: List[RelayHop] = Field(default_factory=list)
    origin_ip: Optional[str] = None
    spf: AuthProtocolResult
    dkim: AuthProtocolResult
    dmarc: AuthProtocolResult
    anomalies: List[str] = Field(default_factory=list)
    is_spoofed: bool
    spoofing_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


class EmailIndicator(BaseModel):
    key: str
    value: str


class EmailAnalysisResponse(BaseModel):
    is_scam: bool
    confidence: float
    risk: Dict[str, Any]
    scam_type: Optional[str] = None
    reasons: List[str] = Field(default_factory=list)
    extracted_intelligence: Optional[ExtractedIntelligence] = None
    header_analysis: Optional["HeaderAnalysisResult"] = None


class Evidence(StrictRequestModel):
    """Structured evidence from a detector or telemetry event."""
    type: str = Field(description="Evidence type (e.g., 'text', 'entity', 'metric')", min_length=1, max_length=128)
    text: Optional[str] = Field(default=None, description="Text or value of the evidence", max_length=4096)
    source: Optional[str] = Field(default=None, description="Source of evidence (e.g., 'honeypot', 'detector')", max_length=128)


class TelemetryEvent(StrictRequestModel):
    """Telemetry event for swarm pheromone ingestion."""
    entity_type: str = Field(description="Entity type (e.g., 'ip', 'user', 'host', 'asset')", min_length=1, max_length=64)
    entity_id: str = Field(description="Unique identifier for the entity", min_length=1, max_length=512)
    score: float = Field(default=10, ge=0, le=100, description="Risk score 0-100")
    evidence: List[Evidence] = Field(default_factory=list, description="List of evidence items", max_length=100)
    ts: Optional[float] = Field(default=None, description="Unix timestamp")

    @field_validator("entity_id")
    @classmethod
    def validate_entity_id(cls, v: str) -> str:
        if not _SAFE_ENTITY_ID_PATTERN.fullmatch(v):
            raise ValueError("entity_id contains invalid characters")
        return v


class JSONIngestRequest(RootModel[Dict[str, Any]]):
    @model_validator(mode="after")
    def validate_non_empty(self) -> "JSONIngestRequest":
        if not self.root:
            raise ValueError("Request body must be a non-empty JSON object.")
        try:
            encoded = json.dumps(self.root, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("Request body must contain JSON-compatible values.") from exc
        if len(encoded) > 256_000:
            raise ValueError("JSON request body exceeds the 256KB limit.")

        def count_nodes(value: Any, depth: int = 0) -> int:
            if depth > 12:
                raise ValueError("JSON request nesting exceeds the maximum depth.")
            if isinstance(value, dict):
                return 1 + sum(count_nodes(key, depth + 1) + count_nodes(item, depth + 1) for key, item in value.items())
            if isinstance(value, list):
                return 1 + sum(count_nodes(item, depth + 1) for item in value)
            return 1

        if count_nodes(self.root) > 5_000:
            raise ValueError("JSON request contains too many values.")
        return self


class SyslogIngestRequest(StrictRequestModel):
    raw: str | List[str]

    @model_validator(mode="after")
    def validate_raw(self) -> "SyslogIngestRequest":
        if isinstance(self.raw, str):
            if not self.raw.strip():
                raise ValueError("raw must not be empty.")
            return self
        if not self.raw:
            raise ValueError("raw must contain at least one syslog line.")
        if len(self.raw) > 100:
            raise ValueError("raw may contain at most 100 syslog lines per request.")
        if any(not str(line).strip() for line in self.raw):
            raise ValueError("raw may not contain empty syslog lines.")
        return self


class CSVIngestRequest(StrictRequestModel):
    csv: str = Field(min_length=1, max_length=1_000_000)
    column_map: Optional[Dict[str, str]] = Field(default=None, max_length=50)


class ActionRequest(StrictRequestModel):
    action: str = Field(min_length=1, max_length=128)
    actor: str = Field(default="api_user", min_length=1, max_length=128)
    params: Dict[str, Any] = Field(default_factory=dict)


class ContainmentActionRequest(StrictRequestModel):
    action: str = Field(min_length=1, max_length=128)
    entity_id: str = Field(min_length=1, max_length=512)
    entity_type: str = Field(default="ip", min_length=1, max_length=64)
    actor: str = Field(default="dashboard", min_length=1, max_length=128)
    reason: str = Field(default="", max_length=1024)
    incident_id: Optional[int] = None
    ttl_seconds: Optional[float] = Field(default=None, ge=0)

    @field_validator("entity_id")
    @classmethod
    def validate_entity_id(cls, v: str) -> str:
        if not _SAFE_ENTITY_ID_PATTERN.fullmatch(v):
            raise ValueError("entity_id contains invalid characters")
        return v


class PlaybookParamSpec(BaseModel):
    name: str
    type: Literal["string", "integer", "number", "boolean", "array", "object"]
    required: bool = False
    description: Optional[str] = None
    default: Optional[Any] = None


class PlaybookAction(BaseModel):
    action: str
    description: str
    params: List[PlaybookParamSpec] = Field(default_factory=list)
    simulation_only: bool = True
    resolves_incident: bool = False
    status_on_success: Optional[str] = "mitigated"
    escalation_threshold: float = Field(default=70.0, ge=0, le=100)
    blast_radius_multiplier: float = Field(default=1.0, gt=0)


class PlaybookManifest(BaseModel):
    playbook_id: str
    name: str
    version: str = "1.0"
    actions: List[PlaybookAction] = Field(default_factory=list)


class PheromoneNode(BaseModel):
    """A node in the pheromone graph representing a network entity."""
    entity_id: str
    entity_type: Literal[
        "ip",
        "user",
        "host",
        "device",
        "asset",
        "domain",
        "honeypot",
        "conversation",
        "unknown",
        "email_domain",
        "email_ip",
        "asn",
        "upi_id",
        "reply_to",
    ] = Field(description="Supported pheromone graph entity type")
    total_pheromone: float = 0.0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PheromoneEdge(BaseModel):
    """An edge in the pheromone graph representing an observed relationship."""
    source: str
    target: str
    weight: float = 0.0
    signal_types: List[str] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    reinforcement_count: int = 0
    last_reinforced: Optional[float] = None


class GraphSnapshot(BaseModel):
    """Serializable snapshot of the pheromone graph for dashboard broadcast."""
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[float] = None


class AntStatus(BaseModel):
    """Status of an ant agent in the swarm."""
    ant_id: str
    ant_type: str = Field(description="scout, soldier, queen")
    state: str = Field(default="idle", description="idle, probing, investigating, reporting")
    current_entity: Optional[str] = None
    pheromones_deposited: int = 0
    anomalies_found: int = 0
    last_active: Optional[float] = None
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class SwarmStatus(BaseModel):
    """Overall swarm health and metrics."""
    is_running: bool = False
    scout_count: int = 0
    soldier_count: int = 0
    queen_active: bool = False
    graph_stats: Dict[str, Any] = Field(default_factory=dict)
    active_investigations: int = 0
    total_pheromones_deposited: int = 0
    total_incidents_created: int = 0
    uptime_seconds: float = 0.0


class MitreMatch(BaseModel):
    """A matched MITRE ATT&CK technique."""
    technique_id: str
    technique_name: str
    tactic: Optional[str] = None
    similarity_score: float = Field(ge=0.0, le=1.0)
    description: Optional[str] = None


class AttackChain(BaseModel):
    """A linked sequence of ATT&CK techniques forming an attack path."""
    chain_id: str
    techniques: List[MitreMatch] = Field(default_factory=list)
    entities_involved: List[str] = Field(default_factory=list)
    confidence: float = 0.0
    predicted_next: List[str] = Field(default_factory=list)
    timestamp: Optional[float] = None


class SimulationControl(StrictRequestModel):
    """Request to control the telemetry simulator."""
    action: Literal["start", "stop", "scenario"] = Field(description="start, stop, scenario")
    scenario: Optional[str] = Field(default=None, description="Scenario name for 'scenario' action", max_length=128)
    events_per_second: float = Field(default=2.0, ge=0.1, le=20.0)


class WSMessage(BaseModel):
    """WebSocket message format for real-time dashboard updates."""
    msg_type: str = Field(description="graph_update, incident, ant_activity, swarm_status, alert")
    data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[float] = None
