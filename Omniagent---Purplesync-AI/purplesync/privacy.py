"""Redact common identifiers before sending finding context to external services."""

from __future__ import annotations

import ipaddress
import re

_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_IP_ADDRESS = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_CANDIDATE = re.compile(r"(?<![\w:])[0-9a-f:]{2,}(?![\w:])", re.I)
_BEARER_TOKEN = re.compile(r"(?i)\bbearer\s+[A-Z0-9._~+/-]+=*")
_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|token|password|secret)\s*[:=]\s*" r"(['\"]?)[^\s,;'\"]+\2"
)


def redact_sensitive_text(value: str) -> str:
    """Mask common PII and credential-like values without changing other text."""
    redacted = _EMAIL.sub("[REDACTED_EMAIL]", value)
    redacted = _IP_ADDRESS.sub("[REDACTED_IP]", redacted)
    redacted = _IPV6_CANDIDATE.sub(_redact_ipv6, redacted)
    redacted = _BEARER_TOKEN.sub("Bearer [REDACTED_TOKEN]", redacted)
    return _SECRET.sub(lambda match: f"{match.group(1)}=[REDACTED]", redacted)


def _redact_ipv6(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        return "[REDACTED_IP]" if ipaddress.ip_address(value).version == 6 else value
    except ValueError:
        return value
