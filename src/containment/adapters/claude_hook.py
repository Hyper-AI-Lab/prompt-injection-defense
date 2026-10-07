"""Claude Code PreToolUse hook: map tool calls → broker decisions."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from containment.actions import ProposedAction
from containment.audit import AuditLog
from containment.broker import SecurityViolation, ToolBroker
from containment.capability import CapabilityMinter
from containment.labels import SecurityLabel
from containment.plan import Plan, PlanStep
from containment.policy import PolicyEngine

# Claude Code tool_name → (containment tool id, arg shaper).


def _shape_bash(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    cmd = tool_input.get("command", tool_input.get("cmd", ""))
    return {"command": str(cmd) if cmd is not None else ""}


def _shape_write(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    path = tool_input.get("file_path", tool_input.get("path", ""))
    content = tool_input.get("content", "")
    return {"path": str(path), "content": content if isinstance(content, str) else str(content)}


def _shape_edit(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    path = tool_input.get("file_path", tool_input.get("path", ""))
    return {
        "path": str(path),
        "old_string": str(tool_input.get("old_string", "")),
        "new_string": str(tool_input.get("new_string", "")),
    }


def _shape_read(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    path = tool_input.get("file_path", tool_input.get("path", ""))
    return {"path": str(path)}


_CLAUDE_TOOL_MAP = {
    "Bash": ("shell.exec", _shape_bash),
    "Write": ("fs.write", _shape_write),
    "Edit": ("fs.write", _shape_edit),
    "Read": ("fs.read", _shape_read),
}


def map_claude_tool(
    tool_name: str, tool_input: Mapping[str, Any] | None
) -> tuple[str, dict[str, Any]] | None:
    """Return (containment_tool, arguments) or None if unmapped (deny)."""
    entry = _CLAUDE_TOOL_MAP.get(tool_name)
    if entry is None:
        return None
    tool_id, shaper = entry
    raw = tool_input if isinstance(tool_input, Mapping) else {}
    return tool_id, shaper(raw)


def _decision_payload(
    permission: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        }
    }


def _deny(reason: str) -> dict[str, Any]:
    return _decision_payload("deny", reason)


def _allow(reason: str) -> dict[str, Any]:
    return _decision_payload("allow", reason)


def _ask(reason: str) -> dict[str, Any]:
    return _decision_payload("ask", reason)


def default_claude_plan(*, task_id: str = "claude") -> Plan:
    """Minimal plan covering mapped Claude tools (hosts should replace)."""
    tools = ("shell.exec", "fs.write", "fs.read")
    return Plan(
        task_id=task_id,
        steps=tuple(PlanStep(step_id=f"s_{t.replace('.', '_')}", tool=t) for t in tools),
        capabilities=frozenset(tools),
    )


def handle_pretool_use(
    event: dict[str, Any],
    *,
    broker: ToolBroker,
    plan: Plan | None = None,
    principal: str = "claude",
    reason_code: str = "claude_pretool_use",
) -> dict[str, Any]:
    """Evaluate a Claude PreToolUse event; return hookSpecificOutput JSON dict.

    Maps ``require_human`` → ``ask``, deny / ``SecurityViolation`` → ``deny``,
    allow → ``allow``. Unknown / malformed → deny (fail closed).
    """
    if not isinstance(event, dict):
        return _deny("malformed event: not a mapping")

    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        return _deny("malformed event: missing tool_name")

    tool_input = event.get("tool_input")
    mapped = map_claude_tool(tool_name, tool_input if isinstance(tool_input, Mapping) else None)
    if mapped is None:
        return _deny(f"unmapped Claude tool {tool_name!r} (fail closed)")

    containment_tool, arguments = mapped
    session_id = event.get("session_id")
    task_id = (
        str(session_id).strip()
        if isinstance(session_id, str) and session_id.strip()
        else "claude"
    )
    resolved_plan = plan if plan is not None else default_claude_plan(task_id=task_id)
    # Align action.task_id with plan when caller supplied a plan.
    if plan is not None:
        task_id = plan.task_id

    labels = (
        SecurityLabel(
            integrity="untrusted",
            confidentiality="private",
            source="claude_pretool_use",
            task_id=task_id,
        ),
    )
    # Prefer plan step matching the tool; fall back to first step.
    plan_step = resolved_plan.steps[0].step_id
    for step in resolved_plan.steps:
        if step.tool == containment_tool:
            plan_step = step.step_id
            break

    try:
        action = ProposedAction(
            tool=containment_tool,
            arguments=arguments,
            principal=principal,
            task_id=task_id,
            reason_code=reason_code,
            input_labels=labels,
            plan_step=plan_step,
        )
    except (TypeError, ValueError) as exc:
        return _deny(f"invalid ProposedAction: {exc}")

    try:
        # Evaluate-only: PreToolUse must not mint/execute (C3).
        result = broker.secure_execute(action, plan=resolved_plan, dry_run=True)
    except SecurityViolation as exc:
        decision = exc.decision
        if decision.effect == "require_human":
            return _ask(decision.reason or f"rule {decision.rule_id}")
        return _deny(decision.reason or f"rule {decision.rule_id}")

    decision = result.decision
    if decision.effect == "allow":
        return _allow(decision.reason or f"rule {decision.rule_id}")
    if decision.effect == "require_human":
        return _ask(decision.reason or f"rule {decision.rule_id}")
    return _deny(decision.reason or f"rule {decision.rule_id}")


def _build_broker(
    *,
    policy_path: Path,
    audit_path: Path | None,
) -> ToolBroker:
    policy = PolicyEngine.from_yaml_path(policy_path)
    if audit_path is None:
        tmp = tempfile.NamedTemporaryFile(
            prefix="containment-claude-audit-",
            suffix=".jsonl",
            delete=False,
        )
        audit_path = Path(tmp.name)
        tmp.close()
    secret_env = os.environ.get("CONTAINMENT_CAPABILITY_SECRET")
    if secret_env:
        secret = secret_env.encode("utf-8")
    else:
        secret = secrets.token_bytes(32)
    known = frozenset({"shell.exec", "fs.write", "fs.read", "email.send", "web.fetch"})
    return ToolBroker(
        policy=policy,
        audit=AuditLog(audit_path),
        minter=CapabilityMinter(secret=secret),
        known_tools=known,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="containment-claude-hook",
        description="Claude Code PreToolUse hook → containment ToolBroker",
    )
    parser.add_argument(
        "--policy",
        default=None,
        help="Policy YAML path (default: CONTAINMENT_POLICY or policies/default_deny.yaml)",
    )
    parser.add_argument(
        "--audit",
        default=None,
        help="Audit JSONL path (default: CONTAINMENT_AUDIT or a tempfile)",
    )
    parser.add_argument(
        "--principal",
        default=None,
        help="Principal id (default: CONTAINMENT_PRINCIPAL or 'claude')",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI: read PreToolUse JSON on stdin; write decision JSON on stdout."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else None
    except json.JSONDecodeError:
        payload = _deny("malformed JSON on stdin")
        print(json.dumps(payload, separators=(",", ":")))
        return 0

    if not isinstance(event, dict):
        payload = _deny("malformed event: expected JSON object")
        print(json.dumps(payload, separators=(",", ":")))
        return 0

    policy_env = os.environ.get("CONTAINMENT_POLICY")
    policy_arg = args.policy or policy_env
    if not policy_arg:
        # Package-relative default_deny.
        policy_path = Path(__file__).resolve().parents[3] / "policies" / "default_deny.yaml"
        if not policy_path.is_file():
            # Installed wheel may lack policies/; require explicit path.
            payload = _deny("missing policy: set CONTAINMENT_POLICY or --policy")
            print(json.dumps(payload, separators=(",", ":")))
            return 0
    else:
        policy_path = Path(policy_arg)

    if not policy_path.is_file():
        payload = _deny(f"policy not found: {policy_path}")
        print(json.dumps(payload, separators=(",", ":")))
        return 0

    audit_env = os.environ.get("CONTAINMENT_AUDIT")
    audit_arg = args.audit or audit_env
    audit_path = Path(audit_arg) if audit_arg else None

    principal = (
        args.principal
        or os.environ.get("CONTAINMENT_PRINCIPAL")
        or "claude"
    )

    try:
        broker = _build_broker(policy_path=policy_path, audit_path=audit_path)
        payload = handle_pretool_use(event, broker=broker, principal=str(principal))
    except Exception as exc:  # fail closed with JSON when possible
        payload = _deny(f"hook error: {exc}")

    try:
        print(json.dumps(payload, separators=(",", ":")))
        return 0
    except Exception:
        return 2


__all__ = [
    "default_claude_plan",
    "handle_pretool_use",
    "main",
    "map_claude_tool",
]
