"""OpenAI-style brokered_tool: decorate callables; invoke only via registry."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

from containment.adapters.registry import BrokeredRegistry, RegisteredFn
from containment.labels import SecurityLabel
from containment.plan import Plan

F = TypeVar("F", bound=RegisteredFn)


def brokered_tool(
    registry: BrokeredRegistry,
    name: str | None = None,
    *,
    tool: str | None = None,
) -> Callable[[F], F]:
    """Register ``fn`` on decorate; returned wrapper only calls ``registry.call``.

    Extra keyword-only broker controls (stripped before tool args)::

        _input_labels, _plan_step, _principal, _task_id, _reason_code, _plan

    Example::

        @brokered_tool(registry, tool="web.fetch")
        def fetch_url(url: str) -> str:
            ...

        fetch_url(url="https://example.com", _input_labels=(label,))
    """

    def decorator(fn: F) -> F:
        reg_name = name if name is not None else fn.__name__
        registry.register(reg_name, fn, tool=tool)

        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if args:
                raise TypeError(
                    f"brokered tool {reg_name!r} accepts keyword arguments only"
                )
            labels: tuple[SecurityLabel, ...] = kwargs.pop("_input_labels", ())
            broker_kwargs: dict[str, Any] = {}
            for key, dest in (
                ("_plan_step", "plan_step"),
                ("_principal", "principal"),
                ("_task_id", "task_id"),
                ("_reason_code", "reason_code"),
                ("_plan", "plan"),
            ):
                if key in kwargs:
                    broker_kwargs[dest] = kwargs.pop(key)
            if "plan" in broker_kwargs and broker_kwargs["plan"] is not None:
                if not isinstance(broker_kwargs["plan"], Plan):
                    raise TypeError("_plan must be a Plan | None")
            return registry.call(
                reg_name,
                kwargs,
                input_labels=labels,
                **broker_kwargs,
            )

        return wrapper  # type: ignore[return-value]

    return decorator


__all__ = ["brokered_tool"]
