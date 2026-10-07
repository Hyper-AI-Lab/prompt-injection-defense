"""BrokeredRegistry: allow/deny/unknown/privileged labels; no raw bypass."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.adapters import BrokeredRegistry
from containment.audit import AuditLog
from containment.broker import SecurityViolation, ToolBroker
from containment.capability import CapabilityMinter
from containment.labels import SecurityLabel
from containment.plan import Plan, PlanStep
from containment.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "default_deny.yaml"


def _label(*, integrity: str = "trusted", confidentiality: str = "private") -> SecurityLabel:
    return SecurityLabel(
        integrity=integrity,  # type: ignore[arg-type]
        confidentiality=confidentiality,  # type: ignore[arg-type]
        source="user" if integrity == "trusted" else "web",
        task_id="t1",
    )


def _plan() -> Plan:
    return Plan(
        task_id="t1",
        steps=(
            PlanStep(step_id="s_fetch", tool="web.fetch"),
            PlanStep(step_id="s_email", tool="email.send"),
            PlanStep(step_id="s_shell", tool="shell.exec"),
        ),
        capabilities=frozenset({"web.fetch", "email.send", "shell.exec"}),
        approved_public_hosts=frozenset({"example.com"}),
        approved_recipients=frozenset({"alice@acme.test"}),
    )


def _broker(tmp_path: Path, **kwargs) -> ToolBroker:
    return ToolBroker(
        policy=PolicyEngine.from_yaml_path(POLICY_PATH),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        minter=CapabilityMinter(secret=b"adapter-registry-test-secret-32!!"),
        known_tools=frozenset({"web.fetch", "email.send", "shell.exec"}),
        **kwargs,
    )


def _registry(tmp_path: Path, **kwargs) -> BrokeredRegistry:
    return BrokeredRegistry(
        _broker(tmp_path, **kwargs),
        _plan(),
        principal="alice",
        task_id="t1",
        reason_code="test",
        plan_step="s_fetch",
    )


def test_allow_path_returns_callable_result(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    calls: list[dict] = []

    def fetch(*, url: str) -> str:
        calls.append({"url": url})
        return f"ok:{url}"

    reg.register("web.fetch", fetch)
    out = reg.call(
        "web.fetch",
        {"url": "https://example.com/x"},
        input_labels=(_label(),),
    )
    assert out == "ok:https://example.com/x"
    assert calls == [{"url": "https://example.com/x"}]


def test_deny_path_raises_security_violation(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    fired = {"n": 0}

    def send(*, recipient: str, body: str = "") -> str:
        fired["n"] += 1
        return "sent"

    reg.register("email.send", send, tool="email.send")
    with pytest.raises(SecurityViolation) as excinfo:
        reg.call(
            "email.send",
            {"recipient": "alice@acme.test", "body": "hi"},
            input_labels=(_label(integrity="untrusted"),),
            plan_step="s_email",
        )
    assert excinfo.value.decision.effect == "deny"
    assert excinfo.value.decision.rule_id == "no-tainted-egress"
    assert fired["n"] == 0


def test_unknown_name_denied_never_calls(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    with pytest.raises(SecurityViolation) as excinfo:
        reg.call("no.such.tool", {"x": 1}, input_labels=(_label(),))
    assert excinfo.value.decision.rule_id == "unknown_registry_tool"
    assert excinfo.value.decision.effect == "deny"


def test_privileged_without_labels_denied(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    fired = {"n": 0}

    def shell(*, command: str) -> str:
        fired["n"] += 1
        return command

    reg.register("shell.exec", shell)
    with pytest.raises(SecurityViolation) as excinfo:
        reg.call(
            "shell.exec",
            {"command": "id"},
            input_labels=(),
            plan_step="s_shell",
        )
    assert excinfo.value.decision.rule_id == "empty_input_labels"
    assert fired["n"] == 0


def test_only_call_executes_no_public_raw_invoke(tmp_path: Path) -> None:
    """Public API must not expose a path that runs fn without the broker."""
    reg = _registry(tmp_path)
    fired = {"n": 0}

    def fetch(*, url: str) -> str:
        fired["n"] += 1
        return url

    reg.register("web.fetch", fetch)
    # No public getter / invoke_raw / __getitem__ that bypasses the broker.
    assert not hasattr(reg, "invoke_raw")
    assert not hasattr(reg, "get_fn")
    with pytest.raises(TypeError):
        reg["web.fetch"]  # type: ignore[index]
    # Private entries exist but call() is the only execution API.
    assert "call" in dir(reg)
    assert "register" in dir(reg)
    assert fired["n"] == 0
    # Allow path still works through call().
    assert (
        reg.call(
            "web.fetch",
            {"url": "https://example.com/y"},
            input_labels=(_label(),),
        )
        == "https://example.com/y"
    )
    assert fired["n"] == 1


def test_sync_known_tools_on_register(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    assert "http.post" not in broker.known_tools  # type: ignore[operator]
    reg = BrokeredRegistry(
        broker,
        Plan(
            task_id="t1",
            steps=(PlanStep(step_id="s_post", tool="http.post"),),
            capabilities=frozenset({"http.post"}),
            approved_public_hosts=frozenset({"example.com"}),
        ),
        principal="alice",
        task_id="t1",
        plan_step="s_post",
    )

    def post(*, url: str) -> str:
        return url

    reg.register("http.post", post)
    assert "http.post" in broker.known_tools  # type: ignore[operator]


def test_plan_factory(tmp_path: Path) -> None:
    reg = BrokeredRegistry(
        _broker(tmp_path),
        _plan,
        principal="alice",
        task_id="t1",
        plan_step="s_fetch",
    )

    def fetch(*, url: str) -> str:
        return "z"

    reg.register("web.fetch", fetch)
    assert (
        reg.call(
            "web.fetch",
            {"url": "https://example.com/z"},
            input_labels=(_label(),),
        )
        == "z"
    )


def test_concurrent_calls_do_not_cross_wire_executor(tmp_path: Path) -> None:
    """C2: shared broker.executor swap must not cross-wire concurrent calls."""
    import threading

    policy = PolicyEngine.from_yaml_text(
        """
version: 1
default: deny
rules:
  - id: allow-a
    effect: allow
    tool: tool.a
    when:
      principal.authenticated: true
  - id: allow-b
    effect: allow
    tool: tool.b
    when:
      principal.authenticated: true
"""
    )
    broker = ToolBroker(
        policy=policy,
        audit=AuditLog(tmp_path / "audit-concurrent.jsonl"),
        minter=CapabilityMinter(secret=b"adapter-registry-concurrent-secret!"),
        known_tools=frozenset({"tool.a", "tool.b"}),
    )
    plan = Plan(
        task_id="t1",
        steps=(
            PlanStep(step_id="sa", tool="tool.a"),
            PlanStep(step_id="sb", tool="tool.b"),
        ),
        capabilities=frozenset({"tool.a", "tool.b"}),
    )
    reg = BrokeredRegistry(
        broker,
        plan,
        principal="alice",
        task_id="t1",
        reason_code="test",
        plan_step="sa",
    )

    barrier = threading.Barrier(2)
    out_a: list[str] = []
    out_b: list[str] = []
    errors: list[BaseException] = []

    def fn_a(**_kwargs: object) -> str:
        barrier.wait(timeout=5)
        return "a"

    def fn_b(**_kwargs: object) -> str:
        barrier.wait(timeout=5)
        return "b"

    reg.register("tool.a", fn_a, tool="tool.a")
    reg.register("tool.b", fn_b, tool="tool.b")

    def run_a() -> None:
        try:
            out_a.append(
                reg.call(
                    "tool.a",
                    {},
                    input_labels=(_label(),),
                    plan_step="sa",
                )
            )
        except BaseException as exc:  # noqa: BLE001 — collect for assert
            errors.append(exc)

    def run_b() -> None:
        try:
            out_b.append(
                reg.call(
                    "tool.b",
                    {},
                    input_labels=(_label(),),
                    plan_step="sb",
                )
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    # Repeat to catch intermittent cross-wire on the old shared-swap path.
    for _ in range(20):
        out_a.clear()
        out_b.clear()
        errors.clear()
        t1 = threading.Thread(target=run_a)
        t2 = threading.Thread(target=run_b)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)
        assert errors == [], errors
        assert out_a == ["a"], out_a
        assert out_b == ["b"], out_b
