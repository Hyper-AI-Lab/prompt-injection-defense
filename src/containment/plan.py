"""Intent envelopes and immutable execution plans."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class IntentEnvelope:
    """Signed-style task identity and scope (fields only in 1.x; no crypto binding).

    Captures who asked for what, under which tenant and risk budget, before
    any untrusted content is read. Cryptographic intent signing remains out of
    scope for 1.x — see AUDIT non-goals / DECISIONS.
    """

    task_id: str
    tenant: str
    user: str
    scope: frozenset[str]
    risk_budget: str
    principal_authenticated: bool = True

    def __post_init__(self) -> None:
        for name, value in (
            ("task_id", self.task_id),
            ("tenant", self.tenant),
            ("user", self.user),
            ("risk_budget", self.risk_budget),
        ):
            if not value or not str(value).strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.scope, frozenset):
            raise TypeError("scope must be a frozenset[str]")
        for item in self.scope:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("scope items must be non-empty strings")
        if not isinstance(self.principal_authenticated, bool):
            raise TypeError("principal_authenticated must be bool")


@dataclass(frozen=True, slots=True)
class PlanStep:
    """One immutable step the privileged planner committed to."""

    step_id: str
    tool: str
    description: str = ""

    def __post_init__(self) -> None:
        if not self.step_id or not str(self.step_id).strip():
            raise ValueError("step_id must be a non-empty string")
        if not self.tool or not str(self.tool).strip():
            raise ValueError("tool must be a non-empty string")
        if not isinstance(self.description, str):
            raise TypeError("description must be str")


@dataclass(frozen=True, slots=True)
class Plan:
    """Immutable capability set for a task: exact tools, steps, and limits."""

    task_id: str
    steps: tuple[PlanStep, ...]
    capabilities: frozenset[str]
    approved_recipients: frozenset[str] = field(default_factory=frozenset)
    approved_wallets: frozenset[str] = field(default_factory=frozenset)
    approved_public_hosts: frozenset[str] = field(default_factory=frozenset)
    transaction_limit: float | None = None
    expiry_unix: float | None = None

    def __post_init__(self) -> None:
        if not self.task_id or not str(self.task_id).strip():
            raise ValueError("task_id must be a non-empty string")
        if not isinstance(self.steps, tuple):
            raise TypeError("steps must be a tuple[PlanStep, ...]")
        if not self.steps:
            raise ValueError("steps must be non-empty")
        seen: set[str] = set()
        for step in self.steps:
            if not isinstance(step, PlanStep):
                raise TypeError("steps items must be PlanStep")
            if step.step_id in seen:
                raise ValueError(f"duplicate step_id: {step.step_id!r}")
            seen.add(step.step_id)
        if not isinstance(self.capabilities, frozenset):
            raise TypeError("capabilities must be a frozenset[str]")
        if not self.capabilities:
            raise ValueError("capabilities must be non-empty")
        for name in (
            "approved_recipients",
            "approved_wallets",
            "approved_public_hosts",
        ):
            value = getattr(self, name)
            if not isinstance(value, frozenset):
                raise TypeError(f"{name} must be a frozenset[str]")
        if self.transaction_limit is not None and self.transaction_limit < 0:
            raise ValueError("transaction_limit must be >= 0 when set")
        tool_names = {step.tool for step in self.steps}
        missing = tool_names - self.capabilities
        if missing:
            raise ValueError(
                f"plan steps reference tools not in capabilities: "
                f"{sorted(missing)}"
            )

    def step_by_id(self, step_id: str) -> PlanStep:
        for step in self.steps:
            if step.step_id == step_id:
                return step
        raise KeyError(f"unknown plan step: {step_id!r}")

    def has_capability(self, tool: str) -> bool:
        return tool in self.capabilities
