"""
SwarmSentinel - Centralized Configuration
=========================================

Single source of truth for all configurable parameters.
Values are loaded from environment variables with sensible defaults.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

_PLACEHOLDER_SECRET_VALUES = {
    "YOUR_API_KEY_HERE",
    "YOUR_GOOGLE_AI_STUDIO_KEY_HERE",
}

# Geolocation and origin-trace intelligence data used by geo_intel.py.
TRUSTED_MTA_PATTERNS = [
    r"^([a-zA-Z0-9-]+\.)*internal\.company\.com$",
    r"^([a-zA-Z0-9-]+\.)*corp\.local$",
    r"^trusted-mta\.security\.net$",
    r"^mail-relay\.internal$",
    r"^10(\.[0-9]{1,3}){3}$",
    r"^172\.(1[6-9]|2[0-9]|3[0-1])(\.[0-9]{1,3}){2}$",
    r"^192\.168(\.[0-9]{1,3}){2}$",
    r"^127\.0\.0\.1$",
    r"^::1$",
]
COMPILED_TRUSTED_MTAS = [re.compile(pattern, re.IGNORECASE) for pattern in TRUSTED_MTA_PATTERNS]
TRUSTED_MTAS = TRUSTED_MTA_PATTERNS

KNOWN_TOR_NODES = {
    "185.220.101.5", "185.220.101.7", "185.220.101.15", "198.96.155.3",
    "109.70.100.22", "162.247.74.200", "193.218.118.179", "195.176.3.24",
}
KNOWN_HOSTING_ISPS = [
    "Amazon.com, Inc.", "Amazon Data Services", "AWS", "DigitalOcean, LLC",
    "Hetzner Online GmbH", "Linode, LLC", "Akamai Connected Cloud", "OVH SAS",
    "Vultr Holdings LLC", "M247 Ltd", "Google Cloud Platform", "Microsoft Corporation",
    "Azure", "Leaseweb", "Contabo GmbH", "Choopa, LLC",
]
KNOWN_HOSTING_ASNS = {
    "AS16509", "AS14618", "AS14061", "AS24940", "AS63949", "AS16276",
    "AS20473", "AS34305", "AS15169", "AS8075", "AS51167",
}
KNOWN_VPN_PROVIDERS = [
    "NordVPN", "ExpressVPN", "Proton AG", "Surfshark Ltd", "Mullvad VPN",
    "CyberGhost", "Private Internet Access", "PIA", "Ipvanish",
]
MOCK_GEO_DATABASE = {
    "185.220.101.5": {"country": "Germany", "city": "Frankfurt", "isp": "Tor Exit Node Network", "asn": "AS24940", "latitude": 50.1109, "longitude": 8.6821, "is_tor": True, "is_vpn": False, "is_hosting": True},
    "198.96.155.3": {"country": "Switzerland", "city": "Zurich", "isp": "Privacy Host Net", "asn": "AS34305", "latitude": 47.3769, "longitude": 8.5417, "is_tor": True, "is_vpn": True, "is_hosting": True},
    "198.51.100.42": {"country": "United States", "city": "Chicago", "isp": "DigitalOcean LLC", "asn": "AS14061", "latitude": 41.8781, "longitude": -87.6298, "is_tor": False, "is_vpn": True, "is_hosting": True},
    "203.0.113.195": {"country": "Japan", "city": "Tokyo", "isp": "NTT Communications", "asn": "AS2914", "latitude": 35.6762, "longitude": 139.6503, "is_tor": False, "is_vpn": False, "is_hosting": False},
    "103.21.244.0": {"country": "India", "city": "Mumbai", "isp": "Reliance Jio Infocomm", "asn": "AS55836", "latitude": 19.076, "longitude": 72.8777, "is_tor": False, "is_vpn": False, "is_hosting": False},
    "157.240.22.35": {"country": "United States", "city": "Ashburn", "isp": "Meta Platforms", "asn": "AS32934", "latitude": 39.0438, "longitude": -77.4874, "is_tor": False, "is_vpn": False, "is_hosting": True},
}


class ConfigError(RuntimeError):
    """Raised when required runtime configuration is missing or unsafe."""



def _is_placeholder_secret(value: Optional[str]) -> bool:
    if not value:
        return False
    normalized = value.strip()
    if normalized in _PLACEHOLDER_SECRET_VALUES:
        return True
    return "YOUR_UPSTASH_PASSWORD" in normalized or "YOUR_UPSTASH_HOST" in normalized


@dataclass
class GraphConfig:
    """Pheromone graph tuning parameters."""
    decay_rate: float = 0.95
    min_threshold: float = 0.01
    decay_interval: float = 30.0
    max_nodes: int = 50000
    max_edges: int = 200000
    reinforcement_blend_old: float = 0.7
    reinforcement_blend_new: float = 0.3
    hotspot_threshold: float = 0.5
    backend: str = "memory"  # "memory" or "redis"


@dataclass
class DetectorConfig:
    """Anomaly detector thresholds."""
    zscore_threshold: float = 2.0
    zscore_max_delta: float = 50.0
    frequency_threshold: int = 2
    frequency_max_delta: float = 30.0
    sequence_unique_threshold: int = 3
    sequence_max_delta: float = 40.0
    min_history_samples: int = 3


@dataclass
class SwarmConfig:
    """Ant swarm agent parameters."""
    num_scouts: int = 5
    soldier_threshold: float = 15.0
    scout_pheromone_strength: float = 0.3
    soldier_pheromone_strength: float = 50.0
    queen_hotspot_min_strength: float = 3.0
    convergence_threshold: float = 5.0
    max_soldiers: int = 20
    investigation_timeout_seconds: float = 300.0


@dataclass
class CorrelationConfig:
    """Incident correlation parameters."""
    window_seconds: float = 300.0
    create_threshold: float = 60.0
    severity_critical: float = 80.0
    severity_high: float = 60.0
    severity_medium: float = 40.0


@dataclass
class QueueConfig:
    """Event queue parameters."""
    max_size: int = 10000
    batch_size: int = 50
    flush_interval: float = 0.5


@dataclass
class APIConfig:
    """API server configuration."""
    api_key: str = ""
    google_ai_studio_key: str = ""
    rate_limit_requests: int = 30
    rate_limit_window_seconds: int = 60
    cors_origins: list = field(default_factory=lambda: ["*"])
    ws_heartbeat_seconds: float = 30.0
    max_incidents_per_page: int = 50


@dataclass
class AppConfig:
    """Top-level application configuration."""
    graph: GraphConfig = field(default_factory=GraphConfig)
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    swarm: SwarmConfig = field(default_factory=SwarmConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    queue: QueueConfig = field(default_factory=QueueConfig)
    api: APIConfig = field(default_factory=APIConfig)
    version: str = "2.0.0"
    environment: str = "development"
    log_level: str = "INFO"
    redis_url: Optional[str] = None

    @classmethod
    def from_env(cls) -> "AppConfig":
        """Load configuration from environment variables with safe bounds."""
        cfg = cls()

        def safe_int(name: str, default: int) -> int:
            value = os.getenv(name)
            try:
                return int(value.strip()) if value else default
            except (AttributeError, ValueError):
                return default

        def safe_float(name: str, default: float) -> float:
            value = os.getenv(name)
            try:
                return float(value.strip()) if value else default
            except (AttributeError, ValueError):
                return default

        # API
        cfg.api.api_key = (os.getenv("API_KEY") or "").strip()
        cfg.api.google_ai_studio_key = (os.getenv("GOOGLE_AI_STUDIO_KEY") or "").strip()
        cfg.api.rate_limit_requests = max(1, safe_int("RATE_LIMIT_REQUESTS", 30))
        cfg.api.rate_limit_window_seconds = max(1, safe_int("RATE_LIMIT_WINDOW_SECONDS", 60))
        cors_env = os.getenv("CORS_ALLOWED_ORIGINS")
        if cors_env:
            cfg.api.cors_origins = [o.strip() for o in cors_env.split(",") if o.strip()]

        # Graph
        cfg.graph.decay_rate = min(1.0, max(0.01, safe_float("GRAPH_DECAY_RATE", 0.95)))
        cfg.graph.backend = os.getenv("GRAPH_BACKEND", "memory")

        # Environment
        cfg.environment = os.getenv("ENVIRONMENT", "development")
        cfg.log_level = os.getenv("LOG_LEVEL", "INFO")
        cfg.redis_url = os.getenv("REDIS_URL")

        # Correlation
        cfg.correlation.window_seconds = max(10.0, safe_float("CORRELATION_WINDOW", 300.0))
        cfg.correlation.create_threshold = min(100.0, max(1.0, safe_float("CORRELATION_THRESHOLD", 60.0)))

        return cfg

    def validate_runtime_requirements(self) -> "AppConfig":
        """Fail fast when required or placeholder secrets are present."""
        if not self.api.api_key:
            raise ConfigError("API_KEY environment variable is required.")
        if _is_placeholder_secret(self.api.api_key):
            raise ConfigError("API_KEY must be replaced with a real secret before startup.")
        if self.api.google_ai_studio_key and _is_placeholder_secret(self.api.google_ai_studio_key):
            raise ConfigError("GOOGLE_AI_STUDIO_KEY contains a placeholder value.")
        if self.redis_url and _is_placeholder_secret(self.redis_url):
            raise ConfigError("REDIS_URL contains placeholder credentials.")
        if (
            self.environment == "production"
            and self.redis_url
            and "@" not in self.redis_url
            and os.getenv("REDIS_ALLOW_NO_AUTH", "").lower() != "true"
        ):
            raise ConfigError(
                "REDIS_URL has no credentials and ENVIRONMENT=production. "
                "Set a password or explicitly allow this via REDIS_ALLOW_NO_AUTH=true."
            )
        if self.environment == "production":
            if (
                os.getenv("REQUIRE_REDIS_IN_PRODUCTION", "").lower() == "true"
                or self.graph.backend == "redis"
            ):
                import storage
                if not storage._redis_available():
                    raise ConfigError("Production environment requires a connected Redis instance.")
        return self

    def to_dict(self) -> dict:
        """Serialize config for /health or /metrics endpoints (redacts secrets)."""
        return {
            "version": self.version,
            "environment": self.environment,
            "graph_backend": self.graph.backend,
            "graph_max_nodes": self.graph.max_nodes,
            "queue_max_size": self.queue.max_size,
            "rate_limit": f"{self.api.rate_limit_requests}/{self.api.rate_limit_window_seconds}s",
            "api_key_set": bool(self.api.api_key),
            "google_ai_studio_key_set": bool(self.api.google_ai_studio_key),
            "redis_configured": bool(self.redis_url),
        }


# Module-level singleton
config = AppConfig.from_env()
