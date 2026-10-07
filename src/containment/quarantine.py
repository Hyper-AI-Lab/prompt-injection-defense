"""Tool-less quarantined typed extract with closed JSON Schema validation.

Raw untrusted content is never given tools, credentials, or network here.
Callers pass candidate structured data (or JSON text); only schema-allowed
keys/types survive. Extra keys are rejected. Free-text instruction-like
values are rejected when the schema does not allow unconstrained strings
(or when using the allowlist helper schemas).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

_INSTRUCTION_RE = re.compile(
    r"(?is)\b("
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?"
    r"|system\s+prompt"
    r"|you\s+are\s+now\b"
    r"|do\s+not\s+follow\s+your\s+(previous|prior)\b"
    r"|disregard\s+(all\s+)?(previous|prior)\b"
    r"|override\s+(all\s+)?(safety|rules?|instructions?)"
    r")\b"
)


class QuarantineError(ValueError):
    """Raised when typed extract fails schema or instruction checks."""


@dataclass(frozen=True, slots=True)
class ExtractResult:
    """Successful quarantined extraction."""

    data: Mapping[str, Any]
    schema_id: str

    def __post_init__(self) -> None:
        if not self.schema_id or not str(self.schema_id).strip():
            raise ValueError("schema_id must be a non-empty string")
        if not isinstance(self.data, Mapping):
            raise TypeError("data must be a mapping")
        object.__setattr__(self, "data", MappingProxyType(dict(self.data)))


def _reject_additional_properties(schema: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy that sets additionalProperties=false on objects."""

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            out = {k: walk(v) for k, v in node.items()}
            if out.get("type") == "object" or "properties" in out:
                out.setdefault("additionalProperties", False)
            return out
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    return walk(schema)


def closed_object_schema(
    properties: Mapping[str, Any],
    *,
    required: list[str] | None = None,
    schema_id: str = "closed",
) -> dict[str, Any]:
    """Build a closed JSON Schema object (additionalProperties=false)."""
    return {
        "$id": schema_id,
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": dict(properties),
        "required": list(required or []),
    }


# Allowlist-style schema: only short enum / number / boolean fields — no free strings.
ALLOWLIST_SUMMARY_SCHEMA: dict[str, Any] = closed_object_schema(
    {
        "title": {"type": "string", "maxLength": 120},
        "score": {"type": "number", "minimum": 0, "maximum": 1},
        "category": {
            "type": "string",
            "enum": ["news", "weather", "sports", "other"],
        },
        "trusted": {"type": "boolean"},
    },
    required=["title", "category"],
    schema_id="allowlist_summary",
)


def _parse_candidate(raw: str | Mapping[str, Any]) -> Any:
    if isinstance(raw, Mapping):
        return dict(raw)
    if not isinstance(raw, str):
        raise QuarantineError("raw must be str or mapping")
    text = raw.strip()
    if not text:
        raise QuarantineError("raw text is empty")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise QuarantineError(f"raw text is not valid JSON: {exc}") from exc


def _schema_allows_free_strings(schema: Mapping[str, Any]) -> bool:
    """True if any string property lacks enum/const/maxLength<=32 pattern constraints."""

    def check(node: Any) -> bool:
        if isinstance(node, dict):
            if node.get("type") == "string":
                if "enum" in node or "const" in node:
                    return False
                max_len = node.get("maxLength")
                if isinstance(max_len, int) and max_len <= 32:
                    return False
                return True
            return any(check(v) for v in node.values())
        if isinstance(node, list):
            return any(check(v) for v in node)
        return False

    return check(schema)


def _find_instruction_strings(value: Any, *, path: str = "$") -> list[str]:
    hits: list[str] = []
    if isinstance(value, str):
        if _INSTRUCTION_RE.search(value):
            hits.append(path)
        return hits
    if isinstance(value, Mapping):
        for k, v in value.items():
            hits.extend(_find_instruction_strings(v, path=f"{path}.{k}"))
        return hits
    if isinstance(value, list):
        for i, v in enumerate(value):
            hits.extend(_find_instruction_strings(v, path=f"{path}[{i}]"))
    return hits


def extract(
    raw: str | Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    schema_id: str | None = None,
    enforce_closed: bool = True,
    reject_instruction_text: bool | None = None,
) -> ExtractResult:
    """Validate candidate data against a closed JSON Schema (tool-less).

    - Extra keys rejected when ``enforce_closed`` (default) forces
      ``additionalProperties: false``.
    - Instruction-like free text rejected when ``reject_instruction_text`` is
      True, or automatically when the schema does not allow unconstrained
      free-string fields (allowlist / enum-heavy schemas).
    """
    if not isinstance(schema, Mapping) or not schema:
        raise QuarantineError("schema must be a non-empty mapping")

    schema_dict = dict(schema)
    if enforce_closed:
        schema_dict = _reject_additional_properties(schema_dict)

    try:
        validator = Draft202012Validator(schema_dict)
        validator.check_schema(schema_dict)
    except SchemaError as exc:
        raise QuarantineError(f"invalid schema: {exc.message}") from exc

    candidate = _parse_candidate(raw)
    if not isinstance(candidate, dict):
        raise QuarantineError("extracted root must be a JSON object")

    errors = sorted(validator.iter_errors(candidate), key=lambda e: list(e.path))
    if errors:
        messages = "; ".join(_format_error(e) for e in errors[:5])
        raise QuarantineError(f"schema validation failed: {messages}")

    auto_reject = (
        reject_instruction_text
        if reject_instruction_text is not None
        else not _schema_allows_free_strings(schema_dict)
    )
    # Also reject instruction phrases in any string field when explicitly asked,
    # or when schema forbids unconstrained strings.
    if reject_instruction_text is True or auto_reject:
        hits = _find_instruction_strings(candidate)
        if hits:
            raise QuarantineError(
                "instruction-like free text rejected at " + ", ".join(hits)
            )
    elif reject_instruction_text is False:
        pass
    else:
        # Schema allows free strings: still scan string fields for injections
        # when maxLength is large / unconstrained — defense in depth for
        # title-like fields with maxLength > 32.
        hits = _find_instruction_strings(candidate)
        if hits:
            raise QuarantineError(
                "instruction-like free text rejected at " + ", ".join(hits)
            )

    sid = schema_id or str(schema_dict.get("$id") or "anonymous")
    return ExtractResult(data=candidate, schema_id=sid)


def _format_error(err: ValidationError) -> str:
    path = ".".join(str(p) for p in err.path) or "$"
    return f"{path}: {err.message}"
