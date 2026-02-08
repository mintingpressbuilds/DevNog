"""Safe serialisation with automatic sensitive-data redaction.

Objects that are not JSON-serialisable by default are converted to safe
string representations so that no ``TypeError`` is raised.  Values whose
keys match known sensitive patterns (API keys, passwords, tokens, etc.)
are replaced with a ``"<REDACTED>"`` placeholder before storage.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, date
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

# ---------------------------------------------------------------------------
# Sensitive-key patterns
# ---------------------------------------------------------------------------

SENSITIVE_PATTERNS: list[str] = [
    r"api[_-]?key",
    r"secret",
    r"password",
    r"token",
    r"private[_-]?key",
    r"credential",
    r"auth",
    r"ssn",
    r"credit[_-]?card",
]

_SENSITIVE_RE = re.compile(
    "|".join(SENSITIVE_PATTERNS),
    re.IGNORECASE,
)

REDACTED_PLACEHOLDER = "<REDACTED>"


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------

def _is_sensitive_key(key: str) -> bool:
    """Return ``True`` when *key* matches any sensitive pattern."""
    return bool(_SENSITIVE_RE.search(str(key)))


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of *data* with sensitive values replaced."""
    out: dict[str, Any] = {}
    for key, value in data.items():
        if _is_sensitive_key(key):
            out[key] = REDACTED_PLACEHOLDER
        elif isinstance(value, dict):
            out[key] = redact_dict(value)
        elif isinstance(value, (list, tuple)):
            out[key] = _redact_sequence(value)
        else:
            out[key] = value
    return out


def _redact_sequence(seq: list | tuple) -> list:
    """Redact sensitive values inside a list/tuple (returns list)."""
    result: list[Any] = []
    for item in seq:
        if isinstance(item, dict):
            result.append(redact_dict(item))
        elif isinstance(item, (list, tuple)):
            result.append(_redact_sequence(item))
        else:
            result.append(item)
    return result


def redact_value(value: Any) -> Any:
    """Apply redaction to an arbitrary value."""
    if isinstance(value, dict):
        return redact_dict(value)
    if isinstance(value, (list, tuple)):
        return _redact_sequence(value)
    return value


# ---------------------------------------------------------------------------
# Safe JSON encoder
# ---------------------------------------------------------------------------

class _SafeEncoder(json.JSONEncoder):
    """JSONEncoder that converts non-serialisable objects to strings."""

    def default(self, o: Any) -> Any:  # noqa: ANN401
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, date):
            return o.isoformat()
        if isinstance(o, Decimal):
            return float(o)
        if isinstance(o, UUID):
            return str(o)
        if isinstance(o, Path):
            return str(o)
        if isinstance(o, bytes):
            try:
                return o.decode("utf-8", errors="replace")
            except Exception:
                return "<bytes>"
        if isinstance(o, set):
            return sorted(str(i) for i in o)
        if isinstance(o, frozenset):
            return sorted(str(i) for i in o)
        if isinstance(o, type):
            return f"{o.__module__}.{o.__qualname__}"
        # Last resort: repr()
        try:
            return repr(o)
        except Exception:
            return f"<unserializable: {type(o).__name__}>"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def safe_serialize(obj: Any, *, redact: bool = True, max_bytes: int = 0) -> str:
    """Serialise *obj* to a JSON string.

    Parameters
    ----------
    obj:
        Any Python object.  Non-JSON types are converted via
        :class:`_SafeEncoder`.
    redact:
        When ``True`` (the default), keys matching :data:`SENSITIVE_PATTERNS`
        have their values replaced with ``"<REDACTED>"``.
    max_bytes:
        When > 0 the returned string is truncated to at most *max_bytes*
        bytes (UTF-8).  A ``"...<truncated>"`` marker is appended when
        truncation happens.

    Returns
    -------
    str
        A JSON-encoded string.
    """
    if redact:
        obj = redact_value(obj)

    try:
        result = json.dumps(obj, cls=_SafeEncoder, default=str)
    except (TypeError, ValueError, OverflowError):
        result = json.dumps(repr(obj))

    if max_bytes > 0 and len(result.encode("utf-8")) > max_bytes:
        # Truncate on character boundary
        encoded = result.encode("utf-8")[:max_bytes]
        result = encoded.decode("utf-8", errors="ignore") + '..."<truncated>"'

    return result


def safe_deserialize(data: str) -> Any:
    """Deserialise a JSON string produced by :func:`safe_serialize`.

    Returns the parsed Python object, or the raw string when parsing fails.
    """
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return data


def serialize_args(args: tuple, kwargs: dict, *, redact: bool = True) -> tuple[list, dict]:
    """Serialise function arguments to JSON-safe structures.

    Returns ``(args_list, kwargs_dict)`` where every element is safe for
    JSON encoding (potentially redacted).
    """
    safe_args = json.loads(safe_serialize(list(args), redact=redact))
    safe_kwargs = json.loads(safe_serialize(kwargs, redact=redact))
    return safe_args, safe_kwargs


def serialize_locals(local_vars: dict[str, Any], *, redact: bool = True) -> dict[str, Any]:
    """Serialise local variables from a stack frame.

    Skips dunder names and callables to keep the snapshot lean.
    """
    result: dict[str, Any] = {}
    for key, value in local_vars.items():
        # Skip dunder and callable entries (functions, classes, modules)
        if key.startswith("__") and key.endswith("__"):
            continue
        if callable(value) and not isinstance(value, type):
            continue
        try:
            serialized = json.loads(safe_serialize(value, redact=redact))
        except Exception:
            serialized = repr(value)

        if redact and _is_sensitive_key(key):
            serialized = REDACTED_PLACEHOLDER

        result[key] = serialized
    return result
