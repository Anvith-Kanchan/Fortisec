"""Redaction helpers for logs and text blobs."""

from __future__ import annotations

import re
from collections.abc import Iterable
from re import Pattern

from .constants import DEFAULT_REDACTION_PLACEHOLDER

RegexLike = str | Pattern[str]

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_AWS_SECRET_KEY_RE = re.compile(
    r"(?i)(aws(.{0,20})?(?:secret|private)?(.{0,20})?(?:key)?\s*[:=]\s*)[A-Za-z0-9/+=]{40}"
)
_GITHUB_PAT_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b")
_OPENAI_KEY_RE = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")
_GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_BEARER_RE = re.compile(r"(?i)(\bAuthorization:\s*Bearer\s+|\bBearer\s+)[A-Za-z0-9._~+/=-]+")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6_RE = re.compile(
    r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b|"
    r"\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b|"
    r"\b::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}\b"
)
_CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

_DEFAULT_PATTERNS: tuple[Pattern[str], ...] = (
    _JWT_RE,
    _AWS_ACCESS_KEY_RE,
    _AWS_SECRET_KEY_RE,
    _GITHUB_PAT_RE,
    _OPENAI_KEY_RE,
    _GOOGLE_API_KEY_RE,
    _BEARER_RE,
    _EMAIL_RE,
    _CREDIT_CARD_RE,
    _IPV6_RE,
)


def _redact_match(match: re.Match[str], placeholder: str) -> str:
    if match.lastindex:
        prefix = match.group(1) or ""
        return f"{prefix}{placeholder}"
    return placeholder


def redact_logs(
    text: str,
    *,
    redact_ip: bool = True,
    placeholder: str = DEFAULT_REDACTION_PLACEHOLDER,
    custom_patterns: Iterable[RegexLike] | None = None,
) -> str:
    """Redact common secrets and identifiers from logs.

    Args:
        text: Log text to redact.
        redact_ip: Whether to redact IPv4 addresses. IPv6 addresses are always redacted.
        placeholder: Replacement text for redacted values.
        custom_patterns: Additional regex patterns to redact.

    Returns:
        Redacted text. Non-string values are converted with str().

    Raises:
        re.error: If a custom string regex pattern is invalid.

    Examples:
        >>> redact_logs("Authorization: Bearer token", placeholder="***")
        'Authorization: Bearer ***'
    """
    redacted = text if isinstance(text, str) else str(text)
    patterns = list(_DEFAULT_PATTERNS)
    if redact_ip:
        patterns.append(_IPV4_RE)
    if custom_patterns:
        for pattern in custom_patterns:
            patterns.append(re.compile(pattern) if isinstance(pattern, str) else pattern)
    for pattern in patterns:
        redacted = pattern.sub(lambda match: _redact_match(match, placeholder), redacted)
    return redacted

