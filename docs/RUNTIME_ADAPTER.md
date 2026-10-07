# Runtime adapters (Bar C)

Wire agent tool calls through the same `ToolBroker` reference monitor used by
in-process hosts. Adapters never authorize: they only shape calls into
`ProposedAction` and return broker outcomes.

## BrokeredRegistry

Register callables by name; the only execution path is `call()` →
`ToolBroker.secure_execute`.

```python
from containment import (
    BrokeredRegistry,
    ToolBroker,
    PolicyEngine,
    AuditLog,
    CapabilityMinter,
    Plan,
    PlanStep,
    SecurityLabel,
)
from pathlib import Path

broker = ToolBroker(
    policy=PolicyEngine.from_yaml_path("policies/default_deny.yaml"),
    audit=AuditLog(Path("audit.jsonl")),
    minter=CapabilityMinter(secret=secret_bytes),  # from SecretProvider / env
    known_tools=frozenset({"web.fetch"}),
)
plan = Plan(
    task_id="t1",
    steps=(PlanStep(step_id="s_fetch", tool="web.fetch"),),
    capabilities=frozenset({"web.fetch"}),
    approved_public_hosts=frozenset({"example.com"}),
)
reg = BrokeredRegistry(broker, plan, principal="agent", task_id="t1", plan_step="s_fetch")

def fetch(*, url: str) -> str:
    return url

reg.register("web.fetch", fetch)
label = SecurityLabel(
    integrity="trusted", confidentiality="public", source="user", task_id="t1"
)
reg.call("web.fetch", {"url": "https://example.com"}, input_labels=(label,))
```

- Unknown registry names → `SecurityViolation` (`unknown_registry_tool`).
- Privileged sinks (`PRIVILEGED_SINKS`) require non-empty `input_labels`.
- There is no public raw invoke; only `call()` runs registered functions.

## OpenAI-style `brokered_tool`

Decorator that registers on decorate; the wrapper only calls `registry.call`.

```python
from containment import brokered_tool

@brokered_tool(reg, tool="web.fetch")
def fetch_url(url: str) -> str:
    return url

fetch_url(url="https://example.com", _input_labels=(label,))
```

Reserved keyword-only controls (stripped before tool args): `_input_labels`,
`_plan_step`, `_principal`, `_task_id`, `_reason_code`, `_plan`.

## Claude Code PreToolUse hook

CLI entrypoint: `containment-claude-hook`.

### Tool map (fail closed)

| Claude `tool_name` | Containment tool | Args shaped |
| --- | --- | --- |
| Bash | `shell.exec` | `{command}` |
| Write / Edit | `fs.write` | `{path, …}` |
| Read | `fs.read` | `{path}` |
| anything else | — | **deny** |

Default-deny policies have no allow rules for `shell.exec` / `fs.write` /
`fs.read`, so mapped tools deny until the host adds explicit rules. Companion
fragment: `policies/claude_code_hooks.yaml`.

Decision mapping: broker `allow` → `allow`; `deny` / `SecurityViolation` →
`deny`; `require_human` → `ask`.

### Env / flags

| Name | Role |
| --- | --- |
| `CONTAINMENT_POLICY` / `--policy` | Policy YAML (required in installs without repo `policies/`) |
| `CONTAINMENT_AUDIT` / `--audit` | Audit JSONL path (else tempfile) |
| `CONTAINMENT_CAPABILITY_SECRET` | Minter secret (else ephemeral process secret) |
| `CONTAINMENT_PRINCIPAL` / `--principal` | Principal id (default `claude`) |

### Sample `.claude/settings.json` snippet

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|Read",
        "hooks": [
          {
            "type": "command",
            "command": "containment-claude-hook"
          }
        ]
      }
    ]
  }
}
```

Use matcher `"*"` to cover all tools (unmapped names still deny). Ensure
`CONTAINMENT_POLICY` points at your YAML in the hook process environment.

### Residuals (honest)

- **Install ≠ wired:** shipping the package does not enable Claude hooks; the
  user must add settings and env.
- **User can disable hooks** in Claude Code settings; this is a host-config
  residual, not a library bypass claim.
- Hook decisions label Claude tool input as `integrity=untrusted`; privileged
  empty-label fail-closed still applies inside the broker for
  `PRIVILEGED_SINKS`.
