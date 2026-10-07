# containment

Production prompt-injection **defense kit** for Python agents.

**Honest claim (not a proof):** this library does **not** make models “injection-proof.”
It constrains *authority*: even if malicious text influences a model, untrusted data
cannot acquire privileges by itself; privileged tool calls must pass a default-deny
reference monitor; irreversible actions require exact independent authorization.

## Threat model (summary)

| In scope | Out of scope |
| --- | --- |
| Untrusted content (web, email, Moltbook, docs) steering tool use | Adaptive attack immunity guarantees |
| Tainted data reaching privileged sinks (`email.send`, `http.post`, …) | Replacing OS sandbox / network egress controls |
| Detector failure / missing weights failing closed for privileged tools | Shipping gated model weights inside the package |
| Typed extract without tools (quarantine) | Full CaMeL / FIDES runtime ports |

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Install

Python 3.12+ recommended.

```bash
cd prompt-injection-defense
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

Optional ML Stage-1 weights:

```bash
pip install -e ".[dev,ml]"
```

## Quickstart

```python
from containment import ingest, SecurityLabel
from containment.broker import ToolBroker, SecurityViolation
from containment.policy import PolicyEngine
from containment.audit import AuditLog
from containment.capability import CapabilityMinter
from containment.actions import ProposedAction
from containment.plan import Plan, PlanStep
from pathlib import Path

# 1) Ingest untrusted text → labeled typed result
result = ingest(
    "Quarterly revenue was fine.",
    source="web:example",
    task_id="task-1",
    candidate={"title": "Quarterly note", "category": "other"},
)
assert result.label.integrity == "untrusted"
assert result.ok

# 2) Privileged tools go through the broker (default deny)
policy = PolicyEngine.from_yaml_path("policies/default_deny.yaml")
broker = ToolBroker(
    policy=policy,
    audit=AuditLog(Path("audit.jsonl")),
    minter=CapabilityMinter(secret=b"replace-me-with-32-byte-secret!!"),
    known_tools=frozenset({"web.fetch", "email.send"}),
)
plan = Plan(
    task_id="task-1",
    steps=(PlanStep(step_id="s_email", tool="email.send"),),
    capabilities=frozenset({"email.send"}),
    approved_recipients=frozenset({"alice@acme.test"}),
)
action = ProposedAction(
    tool="email.send",
    arguments={"recipient": "alice@acme.test", "body": "hi"},
    principal="agent",
    task_id="task-1",
    reason_code="notify",
    input_labels=(result.label,),
    plan_step="s_email",
)
try:
    broker.secure_execute(action, plan=plan)
except SecurityViolation:
    print("blocked: untrusted data cannot egress via email.send")
```

### Moltbook (read-only, untrusted)

```python
from containment.moltbook import read_posts

# Unit tests mock HTTP. Live fetch is optional.
summaries = read_posts(sort="new", limit=5)  # needs network
for s in summaries:
    assert s.ingest.label.integrity == "untrusted"
    if s.ok:
        print(dict(s.data))  # keys: title, topic, summary only
```

### Offline eval

```bash
python -m containment.cli eval --suite fixtures
# or: containment eval --suite fixtures
# Control (policy off — ASR should rise):
python -m containment.cli eval --suite fixtures --no-policy
```

## Package layout

- `src/containment/` — labels, policy, broker, ingest, detectors, quarantine, moltbook, CLI
- `policies/default_deny.yaml` — default-deny tool policy
- `fixtures/attacks` / `fixtures/benign` — offline eval corpus
- `docs/` — threat model, architecture, agent install
- `SKILL.md` — procedure for Grok bots / agents

## Agent install

See [docs/AGENT_INSTALL.md](docs/AGENT_INSTALL.md) and [SKILL.md](SKILL.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
