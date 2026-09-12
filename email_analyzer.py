from __future__ import annotations

import re
from typing import List

from domain_intel import analyze_domain, assess_brand_spoof
from email_auth import apply_observed_results, authentication_anomalies
from geo_intel import resolve_origin
from header_analyzer import analyze_headers, extract_message_body
from intelligence import detect_scam, extract_intelligence
from lifecycle import ScamPhase
from scoring import compute_risk_score
from schemas import EmailAnalysisRequest, EmailAnalysisResponse, EmailIndicator


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


def _collect_text(payload: EmailAnalysisRequest) -> str:
    message_text = payload.message_text or extract_message_body(payload.raw_eml)
    parts = [
        payload.from_name or "",
        payload.from_email,
        payload.subject or "",
        message_text,
        " ".join(payload.links),
    ]
    return " ".join(p for p in parts if p).strip()


def _contains_any(text: str, words: set[str]) -> bool:
    lowered = text.lower()
    return any(word in lowered for word in words)


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

    return reasons[:3]


def _scam_type(reasons: List[str], intelligence) -> str | None:
    if not reasons:
        return None
    if intelligence and intelligence.upi_ids:
        return "payment_fraud"
    if intelligence and intelligence.phishing_links:
        return "phishing_or_payment_fraud"
    return "social_engineering"


def analyze_email(payload: EmailAnalysisRequest) -> EmailAnalysisResponse:
    combined_text = _collect_text(payload)
    detection = detect_scam(combined_text)
    message_text = payload.message_text or extract_message_body(payload.raw_eml)
    intelligence = extract_intelligence(combined_text) if detection.is_scam else extract_intelligence(message_text)
    headers = analyze_headers(payload.raw_headers, payload.raw_eml)
    auth = headers.authentication
    auth.spf = payload.spf_result or auth.spf
    auth.dkim = payload.dkim_result or auth.dkim
    auth.dmarc = payload.dmarc_result or auth.dmarc
    observed_auth_anomalies = authentication_anomalies(apply_observed_results(
        auth,
        from_domain=headers.from_domain,
        spf=payload.spf_result,
        dkim=payload.dkim_result,
        dmarc=payload.dmarc_result,
    ))
    for anomaly in observed_auth_anomalies:
        if anomaly not in headers.anomalies:
            headers.anomalies.append(anomaly)
    origin = resolve_origin(headers.relay_hops, payload.sender_ip)
    domain_intel = analyze_domain(headers.from_domain or payload.from_email)
    auth_failure = any(value in {"fail", "softfail", "permerror"} for value in (auth.spf, auth.dkim, auth.dmarc))
    alignment_failure = any(item.endswith("alignment_failure") for item in headers.anomalies)
    brand_spoof = assess_brand_spoof(payload.from_name, domain_intel, auth_failure, alignment_failure)

    fingerprint = {
        "pressure_language": _contains_any(combined_text, URGENCY_WORDS),
        "links_shared": bool((payload.links or []) or (intelligence and intelligence.phishing_links)),
        "payment_intent": _contains_any(combined_text, PAYMENT_WORDS),
        "message_count": 1,
    }
    phase = _phase_from_content(combined_text)
    forensic_signals = {
        "header_anomaly": bool(headers.anomalies),
        "authentication_failure": auth_failure,
        "alignment_failure": alignment_failure,
        "geo_anomaly": origin.is_hosting or origin.is_vpn or origin.is_tor,
        "domain_reputation": bool(domain_intel.risk_signals),
        "brand_spoof": brand_spoof.suspected,
    }
    risk = compute_risk_score(
        detection=detection,
        fingerprint=fingerprint,
        phase=phase,
        intelligence=intelligence,
        forensic_signals=forensic_signals,
    )

    indicators: List[EmailIndicator] = []
    reasons = _build_reasons(payload, intelligence, indicators)
    if headers.anomalies:
        reasons.append("Email header anomalies detected")
    if brand_spoof.suspected:
        reasons.append("Brand lookalike domain with authentication concerns detected")
    if domain_intel.reputation_signals:
        reasons.append("Sender domain reputation signals detected")
    scam_type = _scam_type(reasons, intelligence) if detection.is_scam else None

    return EmailAnalysisResponse(
        is_scam=detection.is_scam,
        confidence=detection.confidence,
        risk=risk,
        scam_type=scam_type,
        reasons=reasons,
        extracted_intelligence=intelligence,
        header_analysis=headers,
        origin_trace=origin,
        domain_intel=domain_intel,
        brand_spoof=brand_spoof,
    )
