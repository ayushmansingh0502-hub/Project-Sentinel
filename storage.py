import json
import os
import redis
import logging
import time
from lifecycle import ScamPhase
from typing import Optional, Dict, List

logger = logging.getLogger("honeypot.storage")

# In-memory fallback store so the API still works if Redis is unavailable.
_memory_store: dict[str, str] = {}
_flagged_upi_ids = set()
_flagged_bank_accounts = set()
_flagged_phishing_links = set()

# Pheromone and incident in-memory stores for prototype
_pheromones: dict[str, dict] = {}
_incidents: dict[int, dict] = {}
_audit_logs: dict[int, list] = {}
_next_incident_id = 1


def _build_redis_client():
    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        return redis.Redis.from_url(redis_url, decode_responses=True)

    return redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        password=os.getenv("REDIS_PASSWORD"),
        decode_responses=True,
    )


redis_client = _build_redis_client()


def _redis_available() -> bool:
    try:
        redis_client.ping()
        return True
    except Exception:
        return False


def get_conversation(conversation_id: str):
    data = None

    if _redis_available():
        data = redis_client.get(conversation_id)
    else:
        data = _memory_store.get(conversation_id)

    if not data:
        return None

    obj = json.loads(data)
    obj["phase"] = ScamPhase(obj["phase"])
    return obj


def save_conversation(conversation_id: str, state: dict):
    serializable = {
        "phase": state["phase"].value,
        "messages": state["messages"],
    }
    payload = json.dumps(serializable)

    if _redis_available():
        redis_client.set(conversation_id, payload)
    else:
        _memory_store[conversation_id] = payload


def add_flagged_intelligence(
    upi_ids: List[str] = None,
    bank_accounts: List[str] = None,
    phishing_links: List[str] = None
):
    """
    Add extracted intelligence to the flagged (blacklist) database.
    These will be instantly blocked in future conversations.
    """
    upi_ids = upi_ids or []
    bank_accounts = bank_accounts or []
    phishing_links = phishing_links or []
    
    if _redis_available():
        # Add to Redis sets
        if upi_ids:
            redis_client.sadd("flagged:upi_ids", *upi_ids)
            logger.info(f"🚩 Flagged {len(upi_ids)} UPI IDs: {upi_ids}")
        if bank_accounts:
            redis_client.sadd("flagged:bank_accounts", *bank_accounts)
            logger.info(f"🚩 Flagged {len(bank_accounts)} bank accounts: {bank_accounts}")
        if phishing_links:
            redis_client.sadd("flagged:phishing_links", *phishing_links)
            logger.info(f"🚩 Flagged {len(phishing_links)} phishing links: {phishing_links}")
    else:
        # Add to in-memory sets
        _flagged_upi_ids.update(upi_ids)
        _flagged_bank_accounts.update(bank_accounts)
        _flagged_phishing_links.update(phishing_links)
        logger.info(f"🚩 Flagged (in-memory): {len(upi_ids)} UPI, {len(bank_accounts)} accounts, {len(phishing_links)} links")


def check_flagged_intelligence(extracted_intelligence: Dict) -> tuple:
    """
    Check if any extracted intelligence matches flagged items.
    
    Returns: (is_flagged: bool, reason: str)
    """
    if not extracted_intelligence:
        return False, ""
    
    upi_ids = extracted_intelligence.get("upi_ids", [])
    bank_accounts = extracted_intelligence.get("bank_accounts", [])
    phishing_links = extracted_intelligence.get("phishing_links", [])
    
    if _redis_available():
        # Check Redis sets
        for upi in upi_ids:
            if redis_client.sismember("flagged:upi_ids", upi):
                logger.warning(f"🚨 FLAGGED UPI DETECTED: {upi}")
                return True, f"UPI ID {upi} has been flagged as suspicious in previous scams"
        
        for account in bank_accounts:
            if redis_client.sismember("flagged:bank_accounts", account):
                logger.warning(f"🚨 FLAGGED BANK ACCOUNT DETECTED: {account}")
                return True, f"Bank account {account} has been flagged as suspicious"
        
        for link in phishing_links:
            if redis_client.sismember("flagged:phishing_links", link):
                logger.warning(f"🚨 FLAGGED PHISHING LINK DETECTED: {link}")
                return True, f"Phishing link {link} has been reported multiple times"
    else:
        # Check in-memory sets
        for upi in upi_ids:
            if upi in _flagged_upi_ids:
                logger.warning(f"🚨 FLAGGED UPI DETECTED: {upi}")
                return True, f"UPI ID {upi} has been flagged as suspicious in previous scams"
        
        for account in bank_accounts:
            if account in _flagged_bank_accounts:
                logger.warning(f"🚨 FLAGGED BANK ACCOUNT DETECTED: {account}")
                return True, f"Bank account {account} has been flagged as suspicious"
        
        for link in phishing_links:
            if link in _flagged_phishing_links:
                logger.warning(f"🚨 FLAGGED PHISHING LINK DETECTED: {link}")
                return True, f"Phishing link {link} has been reported multiple times"
    
    return False, ""


def get_flagged_intelligence_stats() -> Dict:
    """Get statistics on flagged intelligence"""
    if _redis_available():
        upi_count = redis_client.scard("flagged:upi_ids")
        account_count = redis_client.scard("flagged:bank_accounts")
        link_count = redis_client.scard("flagged:phishing_links")
    else:
        upi_count = len(_flagged_upi_ids)
        account_count = len(_flagged_bank_accounts)
        link_count = len(_flagged_phishing_links)
    
    return {
        "flagged_upi_ids_count": upi_count,
        "flagged_bank_accounts_count": account_count,
        "flagged_phishing_links_count": link_count,
        "total_flagged": upi_count + account_count + link_count
    }


def add_pheromone(entity_type: str, entity_id: str, score: float, evidence: dict, ts: float = None):
    """
    Register or reinforce a pheromone signal for an entity.
    entity_type: e.g. 'host', 'user', 'ip', 'asset'
    entity_id: unique id for the entity
    score: numeric strength (0-100)
    evidence: arbitrary dict describing why
    """
    global _pheromones
    ts = ts or time.time()

    key = f"{entity_type}:{entity_id}"
    if _redis_available():
        redis_client.hset(f"pheromone:{key}", mapping={"score": score, "ts": ts, "evidence": json.dumps(evidence)})
        redis_client.sadd("pheromone:entities", key)
    else:
        cur = _pheromones.get(key, {"score": 0, "ts": ts, "evidence": []})
        # reinforce: add score
        cur["score"] = min(100, cur.get("score", 0) + score)
        cur["ts"] = ts
        cur["evidence"].append(evidence)
        _pheromones[key] = cur


def get_pheromones_snapshot():
    """Return current pheromones as list of dicts{"entity_type","entity_id","score","evidence","ts"}"""
    out = []
    if _redis_available():
        for key in redis_client.smembers("pheromone:entities"):
            data = redis_client.hgetall(f"pheromone:{key}")
            if not data:
                continue
            entity_type, entity_id = key.split(":", 1)
            try:
                evidence = json.loads(data.get("evidence", "[]"))
            except Exception:
                evidence = data.get("evidence")
            out.append({
                "entity_type": entity_type,
                "entity_id": entity_id,
                "score": float(data.get("score", 0)),
                "evidence": evidence,
                "ts": float(data.get("ts", 0))
            })
    else:
        for key, val in _pheromones.items():
            entity_type, entity_id = key.split(":", 1)
            out.append({
                "entity_type": entity_type,
                "entity_id": entity_id,
                "score": float(val.get("score", 0)),
                "evidence": val.get("evidence", []),
                "ts": float(val.get("ts", 0))
            })
    return out


def create_incident(incident: dict) -> int:
    """Persist an incident and return its id."""
    global _next_incident_id
    if _redis_available():
        incident_id = redis_client.incr("incident:next_id")
        incident["id"] = int(incident_id)
        redis_client.set(f"incident:{incident_id}", json.dumps(incident))
        redis_client.lpush("incidents", incident_id)
        return int(incident_id)
    else:
        incident_id = _next_incident_id
        _next_incident_id += 1
        incident["id"] = incident_id
        _incidents[incident_id] = incident
        _audit_logs[incident_id] = []
        return incident_id


def get_incident(incident_id: int) -> Optional[dict]:
    if _redis_available():
        data = redis_client.get(f"incident:{incident_id}")
        return json.loads(data) if data else None
    else:
        return _incidents.get(int(incident_id))


def list_incidents() -> list:
    if _redis_available():
        ids = redis_client.lrange("incidents", 0, 50)
        out = []
        for i in ids:
            data = redis_client.get(f"incident:{i}")
            if data:
                out.append(json.loads(data))
        return out
    else:
        return list(_incidents.values())


def add_audit_log(incident_id: int, entry: dict):
    entry = {"incident_id": int(incident_id), **entry}
    if _redis_available():
        redis_client.lpush(f"incident:{incident_id}:audit", json.dumps(entry))
    else:
        _audit_logs.setdefault(int(incident_id), []).append(entry)


def get_audit_log(incident_id: int) -> list:
    if _redis_available():
        return [json.loads(x) for x in redis_client.lrange(f"incident:{incident_id}:audit", 0, 100)]
    else:
        return _audit_logs.get(int(incident_id), [])


def update_incident(incident_id: int, updates: dict) -> Optional[dict]:
    """Update incident fields and return updated incident."""
    if _redis_available():
        data = redis_client.get(f"incident:{incident_id}")
        if not data:
            return None
        obj = json.loads(data)
        obj.update(updates)
        redis_client.set(f"incident:{incident_id}", json.dumps(obj))
        return obj
    else:
        obj = _incidents.get(int(incident_id))
        if not obj:
            return None
        obj.update(updates)
        _incidents[int(incident_id)] = obj
        return obj


def reset_runtime_state():
    """Reset prototype in-memory state for local tests and demo runs."""
    global _next_incident_id
    _memory_store.clear()
    _flagged_upi_ids.clear()
    _flagged_bank_accounts.clear()
    _flagged_phishing_links.clear()
    _pheromones.clear()
    _incidents.clear()
    _audit_logs.clear()
    _next_incident_id = 1


# Alias used by the /swarm/reset endpoint
clear_all_state = reset_runtime_state

