from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request

from api.dependencies import get_client_ip, is_rate_limited, verify_api_key
from api.logging_utils import logfmt
from api.runtime import runtime_state
from api.services import broadcast_message, build_health_payload, build_metrics_payload
from config import config
from controller import handle_message
from email_analyzer import analyze_email as analyze_email_func
from schemas import EmailAnalysisRequest, MessageRequest, ScamAnalysisResponse
from storage import get_flagged_intelligence_stats

router = APIRouter()
logger = logging.getLogger("honeypot_api")


@router.get("/")
async def root():
    return {"status": "ok", "service": "SwarmSentinel", "docs": "/docs", "dashboard": "/dashboard"}


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "SwarmSentinel"}


@router.get("/health/details")
async def health_details(api_key: str = Depends(verify_api_key)):
    return build_health_payload()


@router.get("/metrics")
async def metrics(api_key: str = Depends(verify_api_key)):
    return build_metrics_payload()


@router.post("/honeypot", response_model=ScamAnalysisResponse)
async def honeypot(
    request: Request,
    body: MessageRequest,
    api_key: str = Depends(verify_api_key),
):
    start = time.perf_counter()
    client_ip = get_client_ip(request)
    runtime_state.metrics.honeypot_requests += 1

    if is_rate_limited(client_ip):
        logger.warning(logfmt("honeypot_rate_limited", client_ip=client_ip, conversation_id=body.conversation_id))
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    try:
        response = handle_message(
            conversation_id=body.conversation_id,
            message=body.message,
            ip=client_ip,
            user_agent=request.headers.get("user-agent", "unknown"),
        )
        logger.info(
            logfmt(
                "honeypot_request_ok",
                client_ip=client_ip,
                conversation_id=body.conversation_id,
                latency_ms=(time.perf_counter() - start) * 1000,
                blocked=getattr(response, "blocked", False),
                flagged_match=getattr(response, "flagged_match", False),
            )
        )
        return response
    except HTTPException:
        raise
    except Exception as exc:
        runtime_state.metrics.honeypot_failures += 1
        logger.exception(logfmt("honeypot_request_failed", client_ip=client_ip, conversation_id=body.conversation_id, error=exc))
        raise HTTPException(status_code=500, detail="Internal processing error.")


@router.get("/debug/gemini")
async def debug_gemini(api_key: str = Depends(verify_api_key)):
    import google.generativeai as genai

    api_key_value = config.api.google_ai_studio_key
    result = {
        "api_key_present": bool(api_key_value),
        "api_key_length": len(api_key_value) if api_key_value else 0,
    }
    try:
        genai.configure(api_key=api_key_value)
        models = genai.list_models()
        result["available_models"] = [
            {"name": model.name, "supports_generate_content": "generateContent" in model.supported_generation_methods}
            for model in models
        ]
    except Exception as exc:
        logger.warning(logfmt("gemini_debug_failed", error=exc))
        result["error"] = f"{type(exc).__name__}: {str(exc)}"
    return result


@router.get("/admin/flagged-intelligence")
async def flagged_intelligence(api_key: str = Depends(verify_api_key)):
    return get_flagged_intelligence_stats()


@router.post("/analyze-email")
async def analyze_email(
    request: Request,
    body: EmailAnalysisRequest,
    api_key: str = Depends(verify_api_key),
):
    client_ip = get_client_ip(request)
    runtime_state.metrics.email_requests += 1

    if is_rate_limited(client_ip):
        logger.warning(logfmt("email_rate_limited", client_ip=client_ip, sender_present=bool(body.from_email)))
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    try:
        response = analyze_email_func(body)
        await broadcast_message(
            "email_trace",
            {
                "header_analysis": response.header_analysis.model_dump() if response.header_analysis else None,
                "origin_trace": response.origin_trace.model_dump() if response.origin_trace else None,
                "domain_intel": response.domain_intel.model_dump() if response.domain_intel else None,
                "brand_spoof": response.brand_spoof.model_dump() if response.brand_spoof else None,
                "risk": response.risk,
            },
        )
        logger.info(
            logfmt(
                "email_analysis_ok",
                client_ip=client_ip,
                sender_present=bool(body.from_email),
                is_scam=response.is_scam,
            )
        )
        return response
    except HTTPException:
        raise
    except Exception as exc:
        runtime_state.metrics.email_failures += 1
        logger.exception(logfmt("email_analysis_failed", client_ip=client_ip, sender_present=bool(body.from_email), error=exc))
        raise HTTPException(status_code=500, detail="Internal processing error.")
