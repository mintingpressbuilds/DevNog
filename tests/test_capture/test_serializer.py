"""Tests for the capture serializer: safe serialisation and sensitive-data redaction."""

from __future__ import annotations

import json
from datetime import datetime, date
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import pytest

from devnog.capture.serializer import (
    REDACTED_PLACEHOLDER,
    _is_sensitive_key,
    redact_dict,
    redact_value,
    safe_serialize,
    safe_deserialize,
    serialize_args,
    serialize_locals,
    _redact_sequence,
)


# -----------------------------------------------------------------------
# _is_sensitive_key
# -----------------------------------------------------------------------

class TestIsSensitiveKey:
    """Verify that keys matching sensitive patterns are detected."""

    @pytest.mark.parametrize(
        "key",
        [
            "api_key",
            "API_KEY",
            "apikey",
            "api-key",
            "secret",
            "SECRET_VALUE",
            "password",
            "PASSWORD",
            "token",
            "access_token",
            "private_key",
            "private-key",
            "credential",
            "credentials",
            "auth",
            "authorization",
            "auth_header",
            "ssn",
            "SSN",
            "credit_card",
            "credit-card",
            "creditcard",
        ],
    )
    def test_sensitive_keys_detected(self, key: str):
        assert _is_sensitive_key(key) is True

    @pytest.mark.parametrize(
        "key",
        [
            "username",
            "email",
            "count",
            "name",
            "description",
            "value",
            "data",
            "items",
            "id",
        ],
    )
    def test_non_sensitive_keys_pass(self, key: str):
        assert _is_sensitive_key(key) is False


# -----------------------------------------------------------------------
# redact_dict
# -----------------------------------------------------------------------

class TestRedactDict:
    """Verify dictionary-level redaction logic."""

    def test_redacts_flat_sensitive_keys(self):
        data = {"api_key": "sk-1234", "name": "alice"}
        result = redact_dict(data)
        assert result["api_key"] == REDACTED_PLACEHOLDER
        assert result["name"] == "alice"

    def test_redacts_nested_dicts(self):
        data = {
            "config": {
                "password": "hunter2",
                "host": "localhost",
            }
        }
        result = redact_dict(data)
        assert result["config"]["password"] == REDACTED_PLACEHOLDER
        assert result["config"]["host"] == "localhost"

    def test_redacts_inside_list_values(self):
        data = {
            "items": [
                {"token": "abc123", "id": 1},
                {"token": "def456", "id": 2},
            ]
        }
        result = redact_dict(data)
        assert result["items"][0]["token"] == REDACTED_PLACEHOLDER
        assert result["items"][0]["id"] == 1
        assert result["items"][1]["token"] == REDACTED_PLACEHOLDER

    def test_does_not_mutate_original(self):
        data = {"secret": "top-secret", "public": "ok"}
        original_secret = data["secret"]
        redact_dict(data)
        assert data["secret"] == original_secret

    def test_empty_dict(self):
        assert redact_dict({}) == {}

    def test_nested_list_of_lists(self):
        data = {
            "matrix": [[{"auth": "xyz"}, "plain"]]
        }
        result = redact_dict(data)
        assert result["matrix"][0][0]["auth"] == REDACTED_PLACEHOLDER
        assert result["matrix"][0][1] == "plain"


# -----------------------------------------------------------------------
# _redact_sequence
# -----------------------------------------------------------------------

class TestRedactSequence:
    def test_redacts_dicts_in_list(self):
        seq = [{"password": "pw"}, "normal", 42]
        result = _redact_sequence(seq)
        assert result[0]["password"] == REDACTED_PLACEHOLDER
        assert result[1] == "normal"
        assert result[2] == 42

    def test_handles_nested_tuples(self):
        seq = ({"secret": "s"}, ({"token": "t"},))
        result = _redact_sequence(seq)
        assert isinstance(result, list)
        assert result[0]["secret"] == REDACTED_PLACEHOLDER
        assert result[1][0]["token"] == REDACTED_PLACEHOLDER


# -----------------------------------------------------------------------
# redact_value
# -----------------------------------------------------------------------

class TestRedactValue:
    def test_dict_value(self):
        result = redact_value({"api_key": "abc"})
        assert result["api_key"] == REDACTED_PLACEHOLDER

    def test_list_value(self):
        result = redact_value([{"password": "pw"}])
        assert result[0]["password"] == REDACTED_PLACEHOLDER

    def test_scalar_value_unchanged(self):
        assert redact_value("hello") == "hello"
        assert redact_value(42) == 42
        assert redact_value(None) is None


# -----------------------------------------------------------------------
# safe_serialize -- type conversion
# -----------------------------------------------------------------------

class TestSafeSerialize:
    """Verify that non-JSON types are converted safely."""

    def test_dict_roundtrip(self):
        data = {"key": "value", "num": 42}
        result = safe_serialize(data, redact=False)
        parsed = json.loads(result)
        assert parsed == data

    def test_datetime_serialization(self):
        dt = datetime(2025, 1, 15, 10, 30, 0)
        result = safe_serialize(dt, redact=False)
        assert "2025-01-15" in result

    def test_date_serialization(self):
        d = date(2025, 6, 1)
        result = safe_serialize(d, redact=False)
        assert "2025-06-01" in result

    def test_decimal_serialization(self):
        val = Decimal("3.14")
        result = safe_serialize(val, redact=False)
        assert "3.14" in result

    def test_uuid_serialization(self):
        u = UUID("12345678-1234-5678-1234-567812345678")
        result = safe_serialize(u, redact=False)
        assert "12345678-1234-5678-1234-567812345678" in result

    def test_path_serialization(self):
        p = Path("/tmp/test.txt")
        result = safe_serialize(p, redact=False)
        assert "/tmp/test.txt" in result

    def test_bytes_serialization(self):
        b = b"hello world"
        result = safe_serialize(b, redact=False)
        assert "hello world" in result

    def test_set_serialization(self):
        s = {3, 1, 2}
        result = safe_serialize(s, redact=False)
        parsed = json.loads(result)
        # The set is converted to its str() representation.
        assert isinstance(parsed, str)
        assert "1" in parsed
        assert "2" in parsed
        assert "3" in parsed

    def test_frozenset_serialization(self):
        fs = frozenset(["b", "a"])
        result = safe_serialize(fs, redact=False)
        parsed = json.loads(result)
        # The frozenset is converted to its str() representation.
        assert isinstance(parsed, str)
        assert "a" in parsed
        assert "b" in parsed

    def test_type_serialization(self):
        result = safe_serialize(int, redact=False)
        assert "int" in result

    def test_unserializable_fallback(self):
        """Objects with no known conversion get repr()."""

        class Weird:
            def __repr__(self):
                return "Weird()"

        result = safe_serialize(Weird(), redact=False)
        assert "Weird()" in result


# -----------------------------------------------------------------------
# safe_serialize -- redaction
# -----------------------------------------------------------------------

class TestSafeSerializeRedaction:
    def test_redaction_on_by_default(self):
        data = {"password": "secret123", "name": "bob"}
        result = safe_serialize(data)
        parsed = json.loads(result)
        assert parsed["password"] == REDACTED_PLACEHOLDER
        assert parsed["name"] == "bob"

    def test_redaction_off(self):
        data = {"password": "secret123"}
        result = safe_serialize(data, redact=False)
        parsed = json.loads(result)
        assert parsed["password"] == "secret123"


# -----------------------------------------------------------------------
# safe_serialize -- truncation
# -----------------------------------------------------------------------

class TestSafeSerializeTruncation:
    def test_truncation_when_too_large(self):
        data = {"big": "x" * 10000}
        result = safe_serialize(data, redact=False, max_bytes=100)
        assert len(result.encode("utf-8")) <= 200  # some overhead from marker
        assert "<truncated>" in result

    def test_no_truncation_when_small(self):
        data = {"small": "ok"}
        result = safe_serialize(data, redact=False, max_bytes=1000)
        assert "<truncated>" not in result

    def test_truncation_disabled_by_default(self):
        data = {"big": "y" * 10000}
        result = safe_serialize(data, redact=False)
        assert "<truncated>" not in result


# -----------------------------------------------------------------------
# safe_deserialize
# -----------------------------------------------------------------------

class TestSafeDeserialize:
    def test_valid_json(self):
        result = safe_deserialize('{"key": "value"}')
        assert result == {"key": "value"}

    def test_invalid_json_returns_raw(self):
        result = safe_deserialize("not json at all")
        assert result == "not json at all"

    def test_none_input(self):
        result = safe_deserialize(None)  # type: ignore[arg-type]
        assert result is None


# -----------------------------------------------------------------------
# serialize_args
# -----------------------------------------------------------------------

class TestSerializeArgs:
    def test_basic_args_and_kwargs(self):
        args = (1, "hello", [3, 4])
        kwargs = {"key": "value"}
        safe_a, safe_kw = serialize_args(args, kwargs, redact=False)
        assert safe_a == [1, "hello", [3, 4]]
        assert safe_kw == {"key": "value"}

    def test_redaction_in_kwargs(self):
        args = ()
        kwargs = {"api_key": "sk-1234", "name": "test"}
        safe_a, safe_kw = serialize_args(args, kwargs, redact=True)
        assert safe_kw["api_key"] == REDACTED_PLACEHOLDER
        assert safe_kw["name"] == "test"

    def test_special_types_in_args(self):
        args = (datetime(2025, 1, 1), Path("/tmp"), Decimal("1.5"))
        kwargs = {}
        safe_a, safe_kw = serialize_args(args, kwargs, redact=False)
        assert isinstance(safe_a[0], str)
        assert "/tmp" in safe_a[1]


# -----------------------------------------------------------------------
# serialize_locals
# -----------------------------------------------------------------------

class TestSerializeLocals:
    def test_skips_dunder_vars(self):
        local_vars = {
            "__name__": "test_module",
            "__doc__": "docs",
            "x": 42,
        }
        result = serialize_locals(local_vars, redact=False)
        assert "__name__" not in result
        assert "__doc__" not in result
        assert result["x"] == 42

    def test_skips_callables(self):
        def some_func():
            pass

        local_vars = {
            "func": some_func,
            "x": 10,
        }
        result = serialize_locals(local_vars, redact=False)
        assert "func" not in result
        assert result["x"] == 10

    def test_keeps_class_types(self):
        """Types (classes) should be kept as they are not plain callables."""
        local_vars = {"MyClass": int, "val": 5}
        result = serialize_locals(local_vars, redact=False)
        assert "MyClass" in result
        assert result["val"] == 5

    def test_redacts_sensitive_local_vars(self):
        local_vars = {"password": "hunter2", "count": 5}
        result = serialize_locals(local_vars, redact=True)
        assert result["password"] == REDACTED_PLACEHOLDER
        assert result["count"] == 5

    def test_empty_locals(self):
        assert serialize_locals({}, redact=True) == {}
