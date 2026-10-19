"""PII redaction for application logs.

Patches Logger.makeRecord so every record, from any logger, is scrubbed
before it reaches a handler (and therefore CloudWatch).
"""

from __future__ import annotations

import logging
import re
from typing import Any

REDACTED = "[REDACTED]"

SENSITIVE_FIELDS = frozenset(
    {
        "email",
        "address",
        "card_last4",
        "card_number",
        "tenant_id",
        "token",
        "jwt",
        "authorization",
        "claims",
        "password",
        "secret",
    }
)

_JWT_RE = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]*")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_KV_RE = re.compile(
    r"""(?P<key>["']?(?:%s)["']?\s*[:=]\s*)(?P<val>"[^"]*"|'[^']*'|[^\s,}\)]+)"""
    % "|".join(sorted(SENSITIVE_FIELDS)),
    re.IGNORECASE,
)

_STANDARD_ATTRS = frozenset(
    logging.LogRecord("", 0, "", 0, "", None, None).__dict__
) | {"message", "asctime", "taskName"}


def redact_text(text: str) -> str:
    text = _JWT_RE.sub(REDACTED, text)
    text = _KV_RE.sub(lambda m: m.group("key") + REDACTED, text)
    text = _EMAIL_RE.sub(REDACTED, text)
    return _CARD_RE.sub(REDACTED, text)


def redact_value(value: Any, key: str | None = None) -> Any:
    if key is not None and key.lower() in SENSITIVE_FIELDS:
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact_value(v) for v in value)
    return value


def _scrub(record: logging.LogRecord) -> None:
    record.msg = redact_text(record.getMessage())
    record.args = None
    for attr in list(record.__dict__):
        if attr not in _STANDARD_ATTRS:
            record.__dict__[attr] = redact_value(record.__dict__[attr], attr)


_installed = False


def install_pii_redaction() -> None:
    """Patch Logger.makeRecord so all records (incl. `extra`) are redacted. Idempotent."""
    global _installed
    if _installed:
        return
    original = logging.Logger.makeRecord

    def make_record(self: logging.Logger, *args: Any, **kwargs: Any) -> logging.LogRecord:
        record = original(self, *args, **kwargs)
        _scrub(record)
        return record

    logging.Logger.makeRecord = make_record  # type: ignore[method-assign]
    _installed = True
