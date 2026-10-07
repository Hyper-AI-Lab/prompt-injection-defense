"""Claude Code PreToolUse hook: deny Bash/unknown; allow with tiny policy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from containment.adapters.claude_hook import (
    default_claude_plan,
    handle_pretool_use,
    main,
    map_claude_tool,
)
from containment.audit import AuditLog
from containment.broker import ApprovalOutcome, ToolBroker
from containment.capability import CapabilityMinter
from containment.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "claude_hook"
DEFAULT_POLICY = ROOT / "policies" / "default_deny.yaml"


def _broker(tmp_path: Path, policy: PolicyEngine | None = None) -> ToolBroker:
    return ToolBroker(
        policy=policy or PolicyEngine.from_yaml_path(DEFAULT_POLICY),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        minter=CapabilityMinter(secret=b"claude-hook-test-secret-key-32b!"),
        known_tools=frozenset({"shell.exec", "fs.write", "fs.read", "email.send"}),
    )


def test_map_bash_and_write() -> None:
    assert map_claude_tool("Bash", {"command": "id"}) == (
        "shell.exec",
        {"command": "id"},
    )
    assert map_claude_tool("Write", {"file_path": "/a", "content": "x"}) == (
        "fs.write",
        {"path": "/a", "content": "x"},
    )
    assert map_claude_tool(
        "Edit",
        {"file_path": "/a", "old_string": "o", "new_string": "n"},
    ) == (
        "fs.write",
        {"path": "/a", "old_string": "o", "new_string": "n"},
    )
    assert map_claude_tool("Read", {"file_path": "/a"}) == (
        "fs.read",
        {"path": "/a"},
    )
    assert map_claude_tool("NotebookEdit", {}) is None


def test_bash_rm_denied_default_policy(tmp_path: Path) -> None:
    event = json.loads((FIXTURES / "bash_rm.json").read_text())
    out = handle_pretool_use(
        event,
        broker=_broker(tmp_path),
        plan=default_claude_plan(task_id="sess_test"),
    )
    decision = out["hookSpecificOutput"]
    assert decision["hookEventName"] == "PreToolUse"
    assert decision["permissionDecision"] == "deny"
    assert "permissionDecisionReason" in decision


def test_unknown_tool_denied(tmp_path: Path) -> None:
    event = json.loads((FIXTURES / "unknown_tool.json").read_text())
    out = handle_pretool_use(event, broker=_broker(tmp_path))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "unmapped" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_allow_with_inline_policy(tmp_path: Path) -> None:
    policy = PolicyEngine.from_yaml_text(
        """
version: 1
default: deny
rules:
  - id: allow-shell
    effect: allow
    tool: shell.exec
    when:
      principal.authenticated: true
"""
    )
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "session_id": "sess_allow",
    }
    out = handle_pretool_use(
        event,
        broker=_broker(tmp_path, policy=policy),
        plan=default_claude_plan(task_id="sess_allow"),
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_require_human_maps_to_ask(tmp_path: Path) -> None:
    policy = PolicyEngine.from_yaml_text(
        """
version: 1
default: deny
rules:
  - id: shell-needs-human
    effect: require_human
    tool: shell.exec
    when:
      principal.authenticated: true
"""
    )
    event = {
        "tool_name": "Bash",
        "tool_input": {"command": "echo ask"},
        "session_id": "sess_ask",
    }
    out = handle_pretool_use(
        event,
        broker=_broker(tmp_path, policy=policy),
        plan=default_claude_plan(task_id="sess_ask"),
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_malformed_event_denied(tmp_path: Path) -> None:
    out = handle_pretool_use({"tool_input": {}}, broker=_broker(tmp_path))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_cli_stdin_bash_deny(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("CONTAINMENT_POLICY", str(DEFAULT_POLICY))
    monkeypatch.setenv("CONTAINMENT_AUDIT", str(tmp_path / "cli-audit.jsonl"))
    payload = (FIXTURES / "bash_rm.json").read_text()
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(payload))
    rc = main([])
    assert rc == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_cli_malformed_json_still_exit_0(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("CONTAINMENT_POLICY", str(DEFAULT_POLICY))
    monkeypatch.setenv("CONTAINMENT_AUDIT", str(tmp_path / "cli-audit.jsonl"))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("{not-json"))
    rc = main([])
    assert rc == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pretool_use_dry_run_allow_does_not_execute(tmp_path: Path) -> None:
    """C3: allow PreToolUse must not invoke broker executor."""
    fired = {"n": 0}

    def executor(action, token):  # noqa: ANN001
        fired["n"] += 1
        return "should-not-run"

    policy = PolicyEngine.from_yaml_text(
        """
version: 1
default: deny
rules:
  - id: allow-shell
    effect: allow
    tool: shell.exec
    when:
      principal.authenticated: true
"""
    )
    broker = ToolBroker(
        policy=policy,
        audit=AuditLog(tmp_path / "audit-dry-allow.jsonl"),
        minter=CapabilityMinter(secret=b"claude-hook-dry-run-secret-key32"),
        known_tools=frozenset({"shell.exec", "fs.write", "fs.read"}),
        executor=executor,
    )
    event = {
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "session_id": "sess_dry_allow",
    }
    out = handle_pretool_use(
        event,
        broker=broker,
        plan=default_claude_plan(task_id="sess_dry_allow"),
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert fired["n"] == 0


def test_pretool_use_dry_run_require_human_ask_no_execute(tmp_path: Path) -> None:
    """C3: require_human → ask without approval hook or executor side effects."""
    fired = {"n": 0}
    approved = {"n": 0}

    def executor(action, token):  # noqa: ANN001
        fired["n"] += 1
        return "should-not-run"

    def approval(action, decision):  # noqa: ANN001
        approved["n"] += 1
        return ApprovalOutcome(mfa_verified=True)

    policy = PolicyEngine.from_yaml_text(
        """
version: 1
default: deny
rules:
  - id: shell-needs-human
    effect: require_human
    tool: shell.exec
    when:
      principal.authenticated: true
"""
    )
    broker = ToolBroker(
        policy=policy,
        audit=AuditLog(tmp_path / "audit-dry-ask.jsonl"),
        minter=CapabilityMinter(secret=b"claude-hook-dry-ask-secret-key32"),
        known_tools=frozenset({"shell.exec", "fs.write", "fs.read"}),
        executor=executor,
        approval=approval,
    )
    event = {
        "tool_name": "Bash",
        "tool_input": {"command": "echo ask"},
        "session_id": "sess_dry_ask",
    }
    out = handle_pretool_use(
        event,
        broker=broker,
        plan=default_claude_plan(task_id="sess_dry_ask"),
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert fired["n"] == 0
    assert approved["n"] == 0
