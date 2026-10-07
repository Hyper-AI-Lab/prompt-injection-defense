"""BrokeredRegistry: register callables; invoke only through ToolBroker."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from containment.actions import PolicyDecision, ProposedAction
from containment.broker import (
    LABEL_REQUIRED_SINKS,
    BrokerResult,
    SecurityViolation,
    ToolBroker,
)
from containment.capability import CapabilityToken
from containment.labels import SecurityLabel
from containment.plan import Plan

PlanFactory = Callable[[], Plan]
RegisteredFn = Callable[..., Any]


@dataclass(frozen=True, slots=True)
class _Entry:
    name: str
    fn: RegisteredFn
    tool: str


class BrokeredRegistry:
    """Map registry names to callables; every invoke goes through the broker.

    There is no public path that runs a registered function without
    ``ToolBroker.secure_execute``. Unknown names deny. Label-required sinks
    (``LABEL_REQUIRED_SINKS``) require non-empty ``input_labels`` (H1 spirit).
    """

    def __init__(
        self,
        broker: ToolBroker,
        plan: Plan | PlanFactory,
        *,
        principal: str = "agent",
        task_id: str = "task",
        reason_code: str = "brokered",
        plan_step: str = "step",
        sync_known_tools: bool = True,
    ) -> None:
        if not isinstance(broker, ToolBroker):
            raise TypeError("broker must be a ToolBroker")
        if not callable(plan) and not isinstance(plan, Plan):
            raise TypeError("plan must be a Plan or a zero-arg Plan factory")
        for name, value in (
            ("principal", principal),
            ("task_id", task_id),
            ("reason_code", reason_code),
            ("plan_step", plan_step),
        ):
            if not value or not str(value).strip():
                raise ValueError(f"{name} must be a non-empty string")
        self._broker = broker
        self._plan = plan
        self._principal = str(principal)
        self._task_id = str(task_id)
        self._reason_code = str(reason_code)
        self._plan_step = str(plan_step)
        self._sync_known_tools = bool(sync_known_tools)
        self._entries: dict[str, _Entry] = {}

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._entries)

    def register(
        self,
        name: str,
        fn: RegisteredFn,
        *,
        tool: str | None = None,
    ) -> RegisteredFn:
        """Register ``fn`` under ``name``. Policy tool id defaults to ``name``."""
        if not name or not str(name).strip():
            raise ValueError("name must be a non-empty string")
        if not callable(fn):
            raise TypeError("fn must be callable")
        tool_id = name if tool is None else tool
        if not tool_id or not str(tool_id).strip():
            raise ValueError("tool must be a non-empty string")
        key = str(name)
        self._entries[key] = _Entry(name=key, fn=fn, tool=str(tool_id))
        if self._sync_known_tools and self._broker.known_tools is not None:
            self._broker.known_tools = self._broker.known_tools | frozenset({str(tool_id)})
        return fn

    def call(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        input_labels: tuple[SecurityLabel, ...] = (),
        principal: str | None = None,
        task_id: str | None = None,
        reason_code: str | None = None,
        plan_step: str | None = None,
        plan: Plan | None = None,
        **broker_kwargs: Any,
    ) -> Any:
        """Build ProposedAction and run via broker; return the callable result."""
        entry = self._entries.get(name)
        if entry is None:
            decision = PolicyDecision(
                effect="deny",
                rule_id="unknown_registry_tool",
                reason=f"unknown registry tool {name!r}",
            )
            raise SecurityViolation(decision.reason, decision=decision)

        if not isinstance(arguments, Mapping):
            decision = PolicyDecision(
                effect="deny",
                rule_id="schema",
                reason="arguments must be a mapping",
            )
            raise SecurityViolation(decision.reason, decision=decision)

        if entry.tool in LABEL_REQUIRED_SINKS and not input_labels:
            decision = PolicyDecision(
                effect="deny",
                rule_id="empty_input_labels",
                reason=(
                    f"privileged sink {entry.tool!r} requires non-empty "
                    "input_labels (fail closed)"
                ),
            )
            raise SecurityViolation(decision.reason, decision=decision)

        action = ProposedAction(
            tool=entry.tool,
            arguments=dict(arguments),
            principal=principal if principal is not None else self._principal,
            task_id=task_id if task_id is not None else self._task_id,
            reason_code=reason_code if reason_code is not None else self._reason_code,
            input_labels=input_labels,
            plan_step=plan_step if plan_step is not None else self._plan_step,
        )
        resolved_plan = plan if plan is not None else self._resolve_plan()

        def _executor(act: ProposedAction, _token: CapabilityToken) -> Any:
            return entry.fn(**dict(act.arguments))

        # Per-call executor — never mutate shared broker.executor (C2).
        broker_kwargs.pop("executor", None)
        outcome: BrokerResult = self._broker.secure_execute(
            action,
            plan=resolved_plan,
            executor=_executor,
            **broker_kwargs,
        )
        return outcome.result

    def _resolve_plan(self) -> Plan:
        plan = self._plan
        if callable(plan) and not isinstance(plan, Plan):
            resolved = plan()
            if not isinstance(resolved, Plan):
                raise TypeError("plan factory must return a Plan")
            return resolved
        assert isinstance(plan, Plan)
        return plan


__all__ = ["BrokeredRegistry"]
