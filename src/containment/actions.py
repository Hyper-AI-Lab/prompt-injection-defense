"""Proposed actions, policy decisions, and audit trace events."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from containment.labels import SecurityLabel

PolicyEffect = Literal["allow", "deny", "require_human"]
_VALID_EFFECTS = frozenset({"allow", "deny", "require_human"})


def _freeze_mapping(data: Mapping[str, Any]) -> MappingProxyType[str, Any]:
    if not isinstance(data, Mapping):
        raise TypeError("expected a mapping")
    # Shallow freeze: nested mutables are the caller's responsibility;
    # broker/schema validation owns deep structure.
    return MappingProxyType(dict(data))


@dataclass(frozen=True, slots=True)
class ProposedAction:
    """Model-proposed tool call; never self-authorizing."""

    tool: str
    arguments: Mapping[str, Any]
    principal: str
    task_id: str
    reason_code: str
    input_labels: tuple[SecurityLabel, ...]
    plan_step: str

    def __post_init__(self) -> None:
        if not self.tool or not str(self.tool).strip():
            raise ValueError("tool must be a non-empty string")
        if not self.principal or not str(self.principal).strip():
            raise ValueError("principal must be a non-empty string")
        if not self.task_id or not str(self.task_id).strip():
            raise ValueError("task_id must be a non-empty string")
        if not self.reason_code or not str(self.reason_code).strip():
            raise ValueError("reason_code must be a non-empty string")
        if not self.plan_step or not str(self.plan_step).strip():
            raise ValueError("plan_step must be a non-empty string")
        if not isinstance(self.input_labels, tuple):
            raise TypeError("input_labels must be a tuple[SecurityLabel, ...]")
        for label in self.input_labels:
            if not isinstance(label, SecurityLabel):
                raise TypeError("input_labels items must be SecurityLabel")
        object.__setattr__(self, "arguments", _freeze_mapping(self.arguments))

    def any_untrusted(self) -> bool:
        return any(label.integrity == "untrusted" for label in self.input_labels)

    def all_trusted(self) -> bool:
        return bool(self.input_labels) and all(
            label.integrity == "trusted" for label in self.input_labels
        )


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Deterministic outcome of the reference monitor."""

    effect: PolicyEffect
    rule_id: str
    reason: str = ""
    requires_mfa: bool = False

    def __post_init__(self) -> None:
        if self.effect not in _VALID_EFFECTS:
            raise ValueError(
                f"effect must be one of {sorted(_VALID_EFFECTS)}, "
                f"got {self.effect!r}"
            )
        if not self.rule_id or not str(self.rule_id).strip():
            raise ValueError("rule_id must be a non-empty string")
        if not isinstance(self.reason, str):
            raise TypeError("reason must be str")
        if not isinstance(self.requires_mfa, bool):
            raise TypeError("requires_mfa must be bool")
        if self.requires_mfa and self.effect != "require_human":
            raise ValueError("requires_mfa is only valid with effect=require_human")


@dataclass(frozen=True, slots=True)
class TraceEvent:
    """One append-only audit record (payload side; writing is audit module)."""

    event_id: str
    timestamp: str
    kind: str
    task_id: str
    detail: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        for name, value in (
            ("event_id", self.event_id),
            ("timestamp", self.timestamp),
            ("kind", self.kind),
            ("task_id", self.task_id),
        ):
            if not value or not str(value).strip():
                raise ValueError(f"{name} must be a non-empty string")
        object.__setattr__(self, "detail", _freeze_mapping(self.detail))
