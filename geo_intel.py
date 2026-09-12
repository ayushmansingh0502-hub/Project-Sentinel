from __future__ import annotations

import ipaddress
import os
from typing import Iterable

from schemas import OriginTrace, RelayHop


def _public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return address.is_global
    except ValueError:
        return False


def resolve_origin(relay_chain: Iterable[RelayHop], sender_ip: str | None = None) -> OriginTrace:
    candidates = [sender_ip] if sender_ip else []
    trusted_values = {
        value.strip().lower()
        for value in os.getenv("TRUSTED_RELAY_IPS", "").split(",")
        if value.strip()
    }
    hops = list(relay_chain)
    candidates.extend(
        ip
        for hop in reversed(hops)
        for ip in hop.ip_addresses
        if ip.lower() not in trusted_values
    )
    origin = next((ip for ip in candidates if ip and _public_ip(ip)), None)
    result = OriginTrace(ip=origin, confidence=0.65 if origin else 0.0)
    if not origin:
        return result

    database_path = os.getenv("GEOIP_DATABASE_PATH", "")
    if not database_path or not os.path.exists(database_path):
        return result
    try:
        import geoip2.database
        with geoip2.database.Reader(database_path) as reader:
            city = reader.city(origin)
            result.country = city.country.name
            result.city = city.city.name
            result.asn = str(city.traits.autonomous_system_number or "") or None
            result.latitude = city.location.latitude
            result.longitude = city.location.longitude
            result.confidence = 0.9
    except Exception:
        return result
    return result