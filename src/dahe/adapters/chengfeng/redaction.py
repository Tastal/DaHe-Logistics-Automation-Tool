from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence

REDACTED = "[REDACTED]"

_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "password",
    "passwd",
    "phone",
    "mobile",
    "token",
    "accesstoken",
    "refreshtoken",
    "signature",
    "sig",
    "accesskey",
    "secret",
}
_HEADER_PATTERN = re.compile(
    r"(?i)(?P<label>\b(?:cookie|authorization)\s*:\s*)"
    r"(?P<value>.*?)"
    r"(?=(?:;\s*(?:cookie|authorization|password|passwd|token|signature|"
    r"access[\s_-]*key|phone|mobile)\s*[:=])|$)"
)
_KEY_VALUE_PATTERN = re.compile(
    r"(?i)(?P<label>\b(?:password|passwd|token|access[\s_-]*token|"
    r"refresh[\s_-]*token|signature|sig|access[\s_-]*key|phone|mobile)"
    r"\s*=\s*)(?P<value>[^&;\s]+)"
)
_PHONE_PATTERN = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _redact_header(match: re.Match[str]) -> str:
    return f"{match.group('label')}{REDACTED}"


def _redact_key_value(match: re.Match[str]) -> str:
    return f"{match.group('label')}{REDACTED}"


def redact_text(value: str) -> str:
    """Remove platform credentials and personal phone numbers from free text."""
    redacted = _HEADER_PATTERN.sub(_redact_header, value)
    redacted = _KEY_VALUE_PATTERN.sub(_redact_key_value, redacted)
    return _PHONE_PATTERN.sub(REDACTED, redacted)


def _redact_value(value: object, *, key: str | None = None) -> object:
    if key is not None and _normalized_key(key) in _SENSITIVE_KEYS:
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {
            str(child_key): _redact_value(child_value, key=str(child_key))
            for child_key, child_value in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return [_redact_value(child) for child in value]
    return value


def redact_mapping(value: Mapping[str, object]) -> dict[str, object]:
    """Return a recursively redacted copy without changing the caller's mapping."""
    return {str(key): _redact_value(child, key=str(key)) for key, child in value.items()}


def safe_diagnostic(
    *,
    error: BaseException,
    stage: str,
    diagnostic_code: str,
    retryable: bool,
    response_status: int | None = None,
    response_body: str | bytes | None = None,
    correlation_id: str | None = None,
) -> dict[str, object]:
    """Build a useful diagnostic without retaining a raw response or secret text."""
    cause = error.__cause__ if error.__cause__ is not None else error
    diagnostic: dict[str, object] = {
        "stage": redact_text(stage),
        "diagnostic_code": redact_text(diagnostic_code),
        "retryable": retryable,
        "error_type": type(error).__name__,
        "cause_type": type(cause).__name__,
    }
    if response_status is not None:
        diagnostic["response_status"] = response_status
    if correlation_id is not None:
        diagnostic["correlation_id"] = redact_text(correlation_id)
    if response_body is not None:
        encoded = (
            response_body.encode("utf-8")
            if isinstance(response_body, str)
            else bytes(response_body)
        )
        diagnostic["response_sha256"] = hashlib.sha256(encoded).hexdigest()
        diagnostic["response_size"] = len(encoded)
    return diagnostic
