# scoring.py
from typing import Dict, Optional
from lifecycle import ScamPhase


def compute_risk_score(
    detection,
    fingerprint: Dict,
    phase: ScamPhase,
    intelligence,
    header_result=None,
) -> Dict:
    """
    Returns a normalized risk assessment.
    header_result: optional HeaderAnalysisResult from header_analyzer.
    """

    score = 0

    # Detection confidence
    if detection.is_scam:
        score += int(detection.confidence * 40)

    # Behavioral signals
    if fingerprint.get("pressure_language"):
        score += 15

    if fingerprint.get("links_shared"):
        score += 20

    if fingerprint.get("payment_intent"):
        score += 15

    if fingerprint.get("message_count", 0) > 3:
        score += 10

    # Lifecycle escalation
    if phase in {ScamPhase.ESCALATION, ScamPhase.PAYMENT}:
        score += 20

    # Intelligence evidence
    if intelligence:
        if intelligence.upi_ids:
            score += 15
        if intelligence.phishing_links:
            score += 20

    # 3.1 — Header / authentication signals
    if header_result is not None:
        if header_result.is_spoofed:
            score += 20
        elif header_result.spoofing_risk_score > 0:
            score += int(header_result.spoofing_risk_score * 15)

    score = min(score, 100)

    if score >= 75:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": score,
        "risk_level": level
    }