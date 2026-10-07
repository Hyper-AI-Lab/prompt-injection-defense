"""YAML default-deny policy engine with taint predicates."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from containment.actions import PolicyDecision, ProposedAction
from containment.plan import Plan

_CONF_RANK = {"public": 0, "private": 1, "identity": 2}
_EFFECT_MAP = {
    "allow": ("allow", False),
    "deny": ("deny", False),
    "require_human": ("require_human", False),
    "require_human_and_mfa": ("require_human", True),
}


@dataclass(frozen=True, slots=True)
class PolicyRule:
    id: str
    effect: str
    when: Mapping[str, Any]
    tool: str | None = None
    tool_in: tuple[str, ...] | None = None
    limits: Mapping[str, Any] | None = None
    display: tuple[str, ...] | None = None


class PolicyEngine:
    """First-match policy evaluator; unmatched actions are denied."""

    def __init__(
        self,
        rules: tuple[PolicyRule, ...],
        *,
        default: str = "deny",
        version: int = 1,
    ) -> None:
        if default != "deny":
            raise ValueError("only default: deny is supported")
        if not isinstance(rules, tuple):
            raise TypeError("rules must be a tuple[PolicyRule, ...]")
        for rule in rules:
            if not isinstance(rule, PolicyRule):
                raise TypeError("rules items must be PolicyRule")
            if rule.effect not in _EFFECT_MAP:
                raise ValueError(f"unsupported effect: {rule.effect!r}")
        self.rules = rules
        self.default = default
        self.version = version

    @classmethod
    def from_yaml_path(cls, path: str | Path) -> PolicyEngine:
        text = Path(path).read_text(encoding="utf-8")
        return cls.from_yaml_text(text)

    @classmethod
    def from_yaml_text(cls, text: str) -> PolicyEngine:
        raw = yaml.safe_load(text)
        if not isinstance(raw, dict):
            raise ValueError("policy root must be a mapping")
        version = int(raw.get("version", 1))
        default = raw.get("default", "deny")
        raw_rules = raw.get("rules") or []
        if not isinstance(raw_rules, list):
            raise ValueError("rules must be a list")
        rules: list[PolicyRule] = []
        for item in raw_rules:
            rules.append(_parse_rule(item))
        return cls(tuple(rules), default=default, version=version)

    def evaluate(
        self,
        action: ProposedAction,
        *,
        plan: Plan,
        principal_authenticated: bool = True,
    ) -> PolicyDecision:
        if action.task_id != plan.task_id:
            return PolicyDecision(
                effect="deny",
                rule_id="task_mismatch",
                reason="action.task_id does not match plan.task_id",
            )
        for rule in self.rules:
            if not _tool_matches(rule, action.tool):
                continue
            if _when_matches(
                rule.when,
                action=action,
                plan=plan,
                principal_authenticated=principal_authenticated,
            ):
                effect, mfa = _EFFECT_MAP[rule.effect]
                return PolicyDecision(
                    effect=effect,  # type: ignore[arg-type]
                    rule_id=rule.id,
                    reason=f"matched rule {rule.id}",
                    requires_mfa=mfa,
                )
        return PolicyDecision(
            effect="deny",
            rule_id="default_deny",
            reason="no rule matched; default deny",
        )


def _parse_rule(item: Any) -> PolicyRule:
    if not isinstance(item, dict):
        raise ValueError("each rule must be a mapping")
    rule_id = item.get("id")
    effect = item.get("effect")
    if not rule_id or not isinstance(rule_id, str):
        raise ValueError("rule.id must be a non-empty string")
    if not effect or not isinstance(effect, str):
        raise ValueError("rule.effect must be a non-empty string")
    when = item.get("when") or {}
    if not isinstance(when, dict):
        raise ValueError("rule.when must be a mapping")
    tool = item.get("tool")
    tool_in = item.get("tool_in")
    if tool is not None and not isinstance(tool, str):
        raise ValueError("rule.tool must be a string")
    if tool_in is not None:
        if not isinstance(tool_in, list) or not all(
            isinstance(t, str) for t in tool_in
        ):
            raise ValueError("rule.tool_in must be a list of strings")
        tool_in_t: tuple[str, ...] | None = tuple(tool_in)
    else:
        tool_in_t = None
    limits = item.get("limits")
    if limits is not None and not isinstance(limits, dict):
        raise ValueError("rule.limits must be a mapping")
    display = item.get("display")
    display_t: tuple[str, ...] | None = None
    if display is not None:
        if not isinstance(display, list) or not all(
            isinstance(d, str) for d in display
        ):
            raise ValueError("rule.display must be a list of strings")
        display_t = tuple(display)
    return PolicyRule(
        id=rule_id,
        effect=effect,
        when=when,
        tool=tool,
        tool_in=tool_in_t,
        limits=limits,
        display=display_t,
    )


def _tool_matches(rule: PolicyRule, tool: str) -> bool:
    if rule.tool is not None and rule.tool != tool:
        return False
    if rule.tool_in is not None and tool not in rule.tool_in:
        return False
    return True


def _when_matches(
    when: Mapping[str, Any],
    *,
    action: ProposedAction,
    plan: Plan,
    principal_authenticated: bool,
) -> bool:
    for key, expected in when.items():
        if not _predicate(
            key,
            expected,
            action=action,
            plan=plan,
            principal_authenticated=principal_authenticated,
        ):
            return False
    return True


def _predicate(
    key: str,
    expected: Any,
    *,
    action: ProposedAction,
    plan: Plan,
    principal_authenticated: bool,
) -> bool:
    if key == "principal.authenticated":
        return principal_authenticated is bool(expected)

    if key == "task.capabilities_contains":
        return str(expected) in plan.capabilities

    if key == "input.any_integrity":
        if expected == "untrusted":
            return action.any_untrusted()
        if expected == "trusted":
            return any(lbl.integrity == "trusted" for lbl in action.input_labels)
        return False

    if key == "input.all_integrity":
        if expected == "trusted":
            return action.all_trusted()
        if expected == "untrusted":
            return bool(action.input_labels) and all(
                lbl.integrity == "untrusted" for lbl in action.input_labels
            )
        return False

    if key == "args.url.scheme":
        url = action.arguments.get("url")
        if not isinstance(url, str):
            return False
        return urlparse(url).scheme == str(expected)

    if key == "args.url.host_in":
        url = action.arguments.get("url")
        if not isinstance(url, str):
            return False
        host = urlparse(url).hostname
        if host is None:
            return False
        allowlist = _named_set(str(expected), plan)
        return host in allowlist

    if key == "args.recipient_in":
        recipient = action.arguments.get("recipient")
        if not isinstance(recipient, str):
            return False
        allowlist = _named_set(str(expected), plan)
        return recipient in allowlist

    if key == "args.destination_in":
        destination = action.arguments.get("destination")
        if not isinstance(destination, str):
            return False
        allowlist = _named_set(str(expected), plan)
        return destination in allowlist

    if key == "args.amount_lte":
        amount = action.arguments.get("amount")
        if not isinstance(amount, (int, float)):
            return False
        limit = _named_limit(str(expected), plan)
        if limit is None:
            return False
        return float(amount) <= float(limit)

    if key == "args.body_confidentiality_lte":
        threshold = str(expected)
        if threshold not in _CONF_RANK:
            return False
        if not action.input_labels:
            # No labeled inputs: treat as meeting the bound (nothing to leak).
            return True
        max_rank = max(_CONF_RANK[lbl.confidentiality] for lbl in action.input_labels)
        return max_rank <= _CONF_RANK[threshold]

    # Unknown predicates fail closed (do not match).
    return False


def _named_set(name: str, plan: Plan) -> frozenset[str]:
    # Allow "task.approved_recipients" or bare "approved_recipients".
    bare = name.removeprefix("task.")
    mapping = {
        "approved_public_hosts": plan.approved_public_hosts,
        "approved_recipients": plan.approved_recipients,
        "approved_wallets": plan.approved_wallets,
    }
    return mapping.get(bare, frozenset())


def _named_limit(name: str, plan: Plan) -> float | None:
    bare = name.removeprefix("task.")
    if bare == "transaction_limit":
        return plan.transaction_limit
    return None
