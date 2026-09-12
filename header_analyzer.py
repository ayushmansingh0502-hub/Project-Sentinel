from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parsedate_to_datetime, parseaddr
from typing import Optional

from schemas import AuthenticationResults, HeaderAnalysis, RelayHop
from email_auth import apply_observed_results, authentication_anomalies

_RECEIVED_PARTS = re.compile(
    r"from\s+(?P<from>[^;]+?)\s+by\s+(?P<by>[^;]+?)(?:\s+with\s+(?P<with>\S+))?(?:\s*;\s*(?P<timestamp>.+))?$",
    re.IGNORECASE,
)
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\[[0-9a-fA-F:]+\]")
_AUTH_PATTERN = re.compile(r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(r"@([A-Za-z0-9.-]+)")


def _domain(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    address = parseaddr(value)[1] or value
    return address.rsplit("@", 1)[-1].lower().strip(" >") if "@" in address else None


def _parse_message(raw: str):
    raw = raw.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if "\n\n" in raw or "\r\n\r\n" in raw:
        return BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8", errors="replace"))
    return Parser(policy=policy.default).parsestr(raw)


def extract_message_body(raw_eml: Optional[str]) -> str:
    if not raw_eml:
        return ""
    try:
        message = _parse_message(raw_eml)
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_type() == "text/plain" and not part.get_filename():
                    return part.get_content().strip()
            for part in message.walk():
                if part.get_content_type() == "text/html" and not part.get_filename():
                    return part.get_content().strip()
        return message.get_content().strip() if message.get_content() else ""
    except (TypeError, ValueError, AttributeError, LookupError):
        return ""


def analyze_headers(raw_headers: Optional[str] = None, raw_eml: Optional[str] = None) -> HeaderAnalysis:
    raw = raw_eml or raw_headers
    if not raw:
        return HeaderAnalysis()
    try:
        if raw.encode("utf-8", errors="replace").decode("utf-8", errors="replace") != raw:
            parse_warning = ["header_parse_error"]
        else:
            parse_warning = []
    except (AttributeError, TypeError):
        return HeaderAnalysis(anomalies=["header_parse_error"])

    try:
        message = _parse_message(raw)
    except (TypeError, ValueError, LookupError):
        return HeaderAnalysis(anomalies=["header_parse_error"])
    try:
        from_domain = _domain(message.get("From"))
        auth = AuthenticationResults()
        authentication_header = message.get("Authentication-Results", "")
    except (UnicodeError, LookupError, ValueError):
        return HeaderAnalysis(anomalies=parse_warning or ["header_parse_error"])
    for name, result in _AUTH_PATTERN.findall(authentication_header):
        setattr(auth, name.lower(), result.lower())
    spf_domain_match = re.search(r"\bsmtp\.mailfrom=([^;\s]+)", authentication_header, re.IGNORECASE)
    if spf_domain_match:
        auth.spf_domain = spf_domain_match.group(1).lower()
    dkim_domain_match = re.search(r"\bheader\.d=([^;\s]+)", authentication_header, re.IGNORECASE)
    if dkim_domain_match:
        auth.dkim_domain = dkim_domain_match.group(1).lower()

    dkim_match = re.search(r"\bd=(?:[^;\s]+)", message.get("DKIM-Signature", ""), re.IGNORECASE)
    if dkim_match:
        auth.dkim_domain = dkim_match.group(0)[2:].lower()
    spf_match = re.search(r"\bs=([^;\s]+)", message.get("Received-SPF", ""), re.IGNORECASE)
    if spf_match:
        auth.spf_domain = spf_match.group(1).lower()

    hops = []
    for position, raw_hop in enumerate(message.get_all("Received", []), start=1):
        match = _RECEIVED_PARTS.search(" ".join(str(raw_hop).split()))
        hops.append(RelayHop(
            position=position,
            raw=str(raw_hop),
            from_host=match.group("from").strip() if match else None,
            by_host=match.group("by").strip() if match else None,
            protocol=match.group("with") if match else None,
            timestamp=match.group("timestamp").strip() if match and match.group("timestamp") else None,
            ip_addresses=[ip.strip("[]") for ip in _IP_PATTERN.findall(str(raw_hop))],
        ))

    anomalies = parse_warning
    if any(not _RECEIVED_PARTS.search(" ".join(str(raw_hop).split())) for raw_hop in message.get_all("Received", [])):
        anomalies.append("malformed_received_header")
    parsed_timestamps = []
    for hop in hops:
        if not hop.timestamp:
            continue
        try:
            parsed_timestamps.append(parsedate_to_datetime(hop.timestamp))
        except (TypeError, ValueError, IndexError):
            anomalies.append("invalid_received_timestamp")
    if any(current < following for current, following in zip(parsed_timestamps, parsed_timestamps[1:])):
        anomalies.append("received_timestamp_order")
    return_path_domain = _domain(message.get("Return-Path"))
    reply_to_domain = _domain(message.get("Reply-To"))
    message_id_domain = _domain(message.get("Message-ID"))
    if return_path_domain and from_domain and return_path_domain != from_domain:
        anomalies.append("return_path_mismatch")
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        anomalies.append("reply_to_mismatch")
    apply_observed_results(auth, from_domain=from_domain)
    anomalies.extend(authentication_anomalies(auth))

    return HeaderAnalysis(
        from_domain=from_domain,
        return_path_domain=return_path_domain,
        reply_to_domain=reply_to_domain,
        message_id_domain=message_id_domain,
        relay_hops=hops,
        anomalies=anomalies,
        authentication=auth,
    )