from __future__ import annotations

import logging
import re
from typing import List, Optional

from attribution import record_email_attribution
from header_analyzer import analyze_headers
from intelligence import detect_scam, extract_intelligence
from lifecycle import ScamPhase
from scoring import compute_risk_score
from schemas import EmailAnalysisRequest, EmailAnalysisResponse, EmailIndicator, HeaderAnalysisResult
from swarm_graph import pheromone_graph

logger = logging.getLogger(__name__)


def _prepare_raw_eml(raw_eml: Optional[str]) -> Optional[bytes]:
    if not raw_eml:
        return None
    try:
        return raw_eml.encode("utf-8", errors="surrogateescape")
    except (UnicodeEncodeError, AttributeError):
        logger.warning("raw_eml could not be encoded to bytes; skipping DKIM verification.")
        return None


URGENCY_WORDS = {
    "urgent",
    "immediately",
    "now",
    "today",
    "asap",
    "suspend",
    "blocked",
    "expire",
    "final notice",
}
PAYMENT_WORDS = {
    "pay",
    "payment",
    "transfer",
    "upi",
    "bank",
    "account verification",
    "kyc",
}
BRAND_SPOOF_WORDS = {"bank", "support", "security team", "verification", "official"}


def _collect_text(payload: EmailAnalysisRequest) -> str:
    parts = [
        payload.from_name or "",
        payload.from_email,
        payload.subject or "",
        payload.message_text,
        " ".join(payload.links),
    ]
    return " ".join(p for p in parts if p).strip()


def _contains_any(text: str, words: set[str]) -> bool:
    lowered = text.lower()
    return any(word in lowered for word in words)


def _looks_suspicious_sender(email: str, display_name: str | None) -> bool:
    local_domain = email.split("@")[-1].lower() if "@" in email else email.lower()
    disposable_like = local_domain.endswith((".xyz", ".top", ".click", ".biz"))
    brand_like_name = bool(display_name and _contains_any(display_name, BRAND_SPOOF_WORDS))
    suspicious_chars = bool(re.search(r"\d{3,}", local_domain))
    return disposable_like or (brand_like_name and suspicious_chars)


def _phase_from_content(text: str) -> ScamPhase:
    lower = text.lower()
    if _contains_any(lower, PAYMENT_WORDS):
        return ScamPhase.PAYMENT
    if "http://" in lower or "https://" in lower or "www." in lower:
        return ScamPhase.ESCALATION
    if _contains_any(lower, URGENCY_WORDS):
        return ScamPhase.PRESSURE
    return ScamPhase.INITIAL


def _build_reasons(
    payload: EmailAnalysisRequest,
    intelligence,
    indicators: List[EmailIndicator],
) -> List[str]:
    reasons: List[str] = []
    text = _collect_text(payload).lower()

    if _contains_any(text, URGENCY_WORDS):
        reasons.append("Urgency language detected")
        indicators.append(EmailIndicator(key="urgency", value="true"))

    if intelligence and intelligence.phishing_links:
        reasons.append("Suspicious link/domain detected")
        indicators.append(EmailIndicator(key="phishing_links", value=str(len(intelligence.phishing_links))))

    if _contains_any(text, PAYMENT_WORDS):
        reasons.append("Payment/account-verification intent detected")
        indicators.append(EmailIndicator(key="payment_intent", value="true"))

    if _looks_suspicious_sender(payload.from_email, payload.from_name):
        reasons.append("Sender identity appears suspicious")
        indicators.append(EmailIndicator(key="sender_reputation", value="suspicious"))

    return reasons[:3]


def _scam_type(reasons: List[str], intelligence) -> str | None:
    if not reasons:
        return None
    if intelligence and intelligence.upi_ids:
        return "payment_fraud"
    if intelligence and intelligence.phishing_links:
        return "phishing_or_payment_fraud"
    return "social_engineering"


def _url_hostname(url: str) -> Optional[str]:
    """Extract the hostname from a URL, returning None if it cannot be parsed."""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname
        return host.lower() if host else None
    except Exception:
        return None


_DENIED_ATTRIBUTION_DOMAINS = {
    "google.com", "gmail.com", "yahoo.com", "outlook.com",
    "hotmail.com", "icloud.com", "microsoft.com", "amazon.com", "apple.com",
}


def analyze_email(payload: EmailAnalysisRequest) -> EmailAnalysisResponse:
    combined_text = _collect_text(payload)
    detection = detect_scam(combined_text)
    intelligence = extract_intelligence(combined_text) if detection.is_scam else extract_intelligence(payload.message_text)

    # 3.1 — Header & protocol analysis
    header_result: Optional[HeaderAnalysisResult] = None
    if payload.raw_headers:
        try:
            header_result = analyze_headers(payload.raw_headers, _prepare_raw_eml(payload.raw_eml))
        except Exception as exc:
            logger.warning("Header analysis failed and will be skipped: %s", exc)

    fingerprint = {
        "pressure_language": _contains_any(combined_text, URGENCY_WORDS),
        "links_shared": bool((payload.links or []) or (intelligence and intelligence.phishing_links)),
        "payment_intent": _contains_any(combined_text, PAYMENT_WORDS),
        "message_count": 1,
    }
    phase = _phase_from_content(combined_text)
    risk = compute_risk_score(
        detection=detection,
        fingerprint=fingerprint,
        phase=phase,
        intelligence=intelligence,
        header_result=header_result,
    )

    indicators: List[EmailIndicator] = []
    reasons = _build_reasons(payload, intelligence, indicators)

    # Prepend spoofing reason when header signals confirm it
    if header_result and header_result.is_spoofed:
        spoof_reason = "Email authentication failed — possible sender spoofing"
        if spoof_reason not in reasons:
            reasons = [spoof_reason] + reasons
        reasons = reasons[:3]

    scam_type = _scam_type(reasons, intelligence) if detection.is_scam else None

    # 3.4 — Sender / infrastructure attribution graph
    # Only deposit attribution nodes for confirmed scam or spoofed emails
    if detection.is_scam or (header_result and header_result.is_spoofed):
        try:
            email_id = payload.message_id or f"anon:{hash(payload.from_email)}"

            # Collect domain-type indicators, excluding major trusted providers from from_domain
            from_domain = payload.from_email.rsplit("@", 1)[-1].lower() if "@" in payload.from_email else None
            valid_from_domain = [from_domain] if (from_domain and from_domain not in _DENIED_ATTRIBUTION_DOMAINS) else []
            
            link_domains = [
                h for h in (_url_hostname(u) for u in (intelligence.phishing_links if intelligence else []))
                if h
            ]
            all_domains = list({d for d in (valid_from_domain + link_domains) if d})

            relay_ip = [header_result.origin_ip] if (header_result and header_result.origin_ip) else []

            attr_indicators: dict[str, list[str]] = {
                "domains": all_domains,
                "ips": relay_ip,
                "upi_ids": list(intelligence.upi_ids) if intelligence else [],
            }
            # Only call attribution if we have at least one indicator worth recording
            if any(attr_indicators.values()):
                record_email_attribution(email_id, attr_indicators, pheromone_graph)
        except Exception as exc:
            logger.warning("Email attribution failed and will be skipped: %s", exc)

    return EmailAnalysisResponse(
        is_scam=detection.is_scam,
        confidence=detection.confidence,
        risk=risk,
        scam_type=scam_type,
        reasons=reasons,
        extracted_intelligence=intelligence,
        header_analysis=header_result,
    )
