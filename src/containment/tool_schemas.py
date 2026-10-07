"""Per-tool argument JSON Schema registry (additionalProperties: false)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

TOOL_ARG_SCHEMAS: dict[str, dict[str, Any]] = {
    "web.fetch": {
        "$id": "tool.web.fetch",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["url"],
        "properties": {
            "url": {"type": "string", "minLength": 1},
            "redirects": {"type": "integer", "minimum": 0},
            "max_redirects": {"type": "integer", "minimum": 0},
            "allow_redirects": {"type": "boolean"},
            "max_bytes": {"type": "integer", "minimum": 1},
            "body": {"type": "string"},
            "content": {"type": "string"},
            "data": {"type": "string"},
            "payload": {"type": "string"},
            "text": {"type": "string"},
        },
    },
    "email.send": {
        "$id": "tool.email.send",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["recipient"],
        "properties": {
            "recipient": {"type": "string", "minLength": 1},
            "subject": {"type": "string"},
            "body": {"type": "string"},
            "body_confidentiality": {
                "type": "string",
                "enum": ["public", "private", "identity"],
            },
            "confidentiality": {
                "type": "string",
                "enum": ["public", "private", "identity"],
            },
        },
    },
    "http.post": {
        "$id": "tool.http.post",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["url"],
        "properties": {
            "url": {"type": "string", "minLength": 1},
            "body": {"type": ["string", "object"]},
            "content": {"type": ["string", "object"]},
            "data": {"type": ["string", "object"]},
            "payload": {"type": ["string", "object"]},
            "headers": {"type": "object"},
        },
    },
    "wallet.transfer": {
        "$id": "tool.wallet.transfer",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["amount", "destination"],
        "properties": {
            "amount": {"type": "number"},
            "destination": {"type": "string", "minLength": 1},
            "memo": {"type": "string"},
        },
    },
    "shell.exec": {
        "$id": "tool.shell.exec",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["command"],
        "properties": {
            "command": {"type": "string"},
        },
    },
    "file.write": {
        "$id": "tool.file.write",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["path", "content"],
        "properties": {
            "path": {"type": "string", "minLength": 1},
            "content": {"type": "string"},
        },
    },
    # Write shape (path+content) or Edit shape (path+old_string+new_string).
    "fs.write": {
        "$id": "tool.fs.write",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "content"],
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "content": {"type": "string"},
                },
            },
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "old_string", "new_string"],
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "old_string": {"type": "string"},
                    "new_string": {"type": "string"},
                },
            },
        ],
    },
    "fs.read": {
        "$id": "tool.fs.read",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["path"],
        "properties": {
            "path": {"type": "string", "minLength": 1},
        },
    },
}


class ToolSchemaError(ValueError):
    """Raised when tool arguments fail the per-tool JSON Schema registry."""


def registry_schema_validator(tool: str, arguments: Mapping[str, Any]) -> None:
    """Validate args against TOOL_ARG_SCHEMAS when known; else structural check.

    Unknown tools are not schema-validated here — the broker ``known_tools`` /
    default-deny policy still denies them. Raises ``ToolSchemaError`` on failure
    (broker wraps into ``SecurityViolation``).
    """
    if not tool or not str(tool).strip():
        raise ToolSchemaError("tool name required")
    if not isinstance(arguments, Mapping):
        raise ToolSchemaError("arguments must be a mapping")
    schema = TOOL_ARG_SCHEMAS.get(tool)
    if schema is None:
        return
    try:
        Draft202012Validator(schema).validate(dict(arguments))
    except ValidationError as exc:
        raise ToolSchemaError(
            f"schema validation failed for {tool}: {exc.message}"
        ) from exc


__all__ = ["TOOL_ARG_SCHEMAS", "ToolSchemaError", "registry_schema_validator"]
