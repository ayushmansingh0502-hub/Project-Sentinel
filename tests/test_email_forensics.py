from email_analyzer import analyze_email
from header_analyzer import analyze_headers
from schemas import EmailAnalysisRequest
from scoring import compute_risk_score
from intelligence import DetectionResult
from lifecycle import ScamPhase


RAW_HEADERS = """From: Bank Support <alerts@paypa1.xyz>
Return-Path: <bounce@paypa1.xyz>
Reply-To: help@paypa1.xyz
Authentication-Results: mx.example; spf=fail smtp.mailfrom=paypa1.xyz; dkim=fail header.d=paypa1.xyz; dmarc=fail header.from=paypa1.xyz
Received: from 192.168.1.4 by relay.example with ESMTPS; Thu, 12 Sep 2026 09:00:00 +0000
Received: from 8.8.8.8 by mx.example with ESMTPS; Thu, 12 Sep 2026 10:00:00 +0000
"""


def test_header_analysis_extracts_hops_and_authentication():
    result = analyze_headers(raw_headers=RAW_HEADERS)

    assert result.from_domain == "paypa1.xyz"
    assert len(result.relay_hops) == 2
    assert result.relay_hops[0].ip_addresses == ["192.168.1.4"]
    assert result.authentication.spf == "fail"
    assert result.authentication.dkim == "fail"
    assert result.authentication.dmarc == "fail"
    assert "spf_failure" in result.anomalies


def test_email_analysis_merges_forensic_signals():
    result = analyze_email(EmailAnalysisRequest(
        from_email="alerts@paypa1.xyz",
        from_name="Bank Support",
        message_text="Your account is blocked, verify now",
        raw_headers=RAW_HEADERS,
    ))

    assert result.header_analysis is not None
    assert result.origin_trace.ip == "8.8.8.8"
    assert result.domain_intel.is_lookalike is True
    assert result.brand_spoof.suspected is True
    assert result.risk["forensic_contributions"]["brand_spoof"] > 0


def test_display_name_alone_does_not_trigger_brand_spoof():
    result = analyze_email(EmailAnalysisRequest(
        from_email="support@example.com",
        from_name="Bank Support",
        message_text="Here is the monthly statement.",
    ))

    assert result.brand_spoof.suspected is False
    assert result.brand_spoof.domain_lookalike is False


def test_private_sender_ip_is_not_selected_as_origin():
    result = analyze_email(EmailAnalysisRequest(
        from_email="sender@example.com",
        message_text="Hello",
        sender_ip="10.0.0.4",
    ))

    assert result.origin_trace.ip is None


def test_existing_chat_scoring_contract_remains_compatible():
    result = compute_risk_score(
        detection=DetectionResult(is_scam=True, confidence=0.5),
        fingerprint={},
        phase=ScamPhase.INITIAL,
        intelligence=None,
    )

    assert result["risk_score"] == 20
    assert result["forensic_contributions"] == {}


def test_received_timestamp_order_is_flagged():
    result = analyze_headers(raw_headers="""From: sender@example.com
Received: from relay-a by mx.example; Thu, 12 Sep 2026 09:00:00 +0000
Received: from 8.8.8.8 by relay-a; Thu, 12 Sep 2026 10:00:00 +0000
""")

    assert "received_timestamp_order" in result.anomalies


def test_supplied_authentication_results_are_normalized_and_scored():
    result = analyze_email(EmailAnalysisRequest(
        from_email="alerts@example.com",
        message_text="Please review this notice.",
        spf_result="FAIL",
        dkim_result="not-a-real-status",
        dmarc_result="pass",
    ))

    assert result.header_analysis.authentication.spf == "fail"
    assert result.header_analysis.authentication.dkim == "unavailable"
    assert "spf_failure" in result.header_analysis.anomalies
    assert result.risk["forensic_contributions"]["authentication_failure"] > 0


def test_relaxed_subdomain_authentication_alignment_is_allowed():
    result = analyze_headers(raw_headers="""From: sender@example.com
Authentication-Results: mx; spf=pass smtp.mailfrom=mail.example.com; dkim=pass header.d=sign.example.com
""")

    assert result.authentication.aligned is True
    assert "authentication_alignment_failure" not in result.anomalies


def test_authentication_domain_mismatch_is_flagged():
    result = analyze_headers(raw_headers="""From: sender@example.com
Authentication-Results: mx; spf=pass smtp.mailfrom=attacker.example.net; dkim=pass header.d=attacker.example.net
""")

    assert result.authentication.aligned is False
    assert "authentication_alignment_failure" in result.anomalies


def test_raw_eml_can_supply_message_body_without_message_text():
    result = analyze_email(EmailAnalysisRequest(
        from_email="alerts@example.com",
        raw_eml="From: alerts@example.com\nSubject: Verify\nContent-Type: text/plain; charset=utf-8\n\nYour account is blocked. Verify now.",
    ))

    assert result.is_scam is True


def test_email_request_rejects_missing_message_sources():
    import pytest

    with pytest.raises(ValueError):
        EmailAnalysisRequest(from_email="alerts@example.com")


def test_malformed_raw_headers_return_structured_parse_signal():
    result = analyze_headers(raw_headers="From: \ud800\n\ud800")

    assert "header_parse_error" in result.anomalies


def test_benign_authentication_records_do_not_add_domain_risk():
    result = analyze_email(EmailAnalysisRequest(
        from_email="sender@example.com",
        message_text="A normal update.",
        raw_headers="""From: sender@example.com
Authentication-Results: mx; spf=pass smtp.mailfrom=sender.example.com; dkim=pass header.d=sender.example.com; dmarc=pass header.from=example.com
""",
    ))

    assert "spf_record_present" not in result.risk["forensic_contributions"]
    assert "domain_reputation" not in result.risk["forensic_contributions"]