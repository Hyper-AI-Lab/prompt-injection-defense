# prompt-injection-defense

Python package **`containment`**: production **prompt-injection defense** for LLM agents (labels, default-deny policy broker, quarantine extract, detectors).


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

## Host residual close (Bar B)

Enterprise hosts should use `build_enterprise_host()` plus
[docs/HOST_HARDENING.md](docs/HOST_HARDENING.md): `HostChecklist` / HostGate,
`SecretProvider`, `EgressProvider`, `AuditShipper`, resolve-pin helpers, and optional
`containment-egress-proxy` (resolve-pin-forward; not TLS MITM). Optional
Ed25519 (`[crypto]`), Redis consume store (`[redis]`), and `RateLimitGate`.
This is not a FedRAMP claim and not an OS sandbox.

## Runtime adapters (Bar C)

Wire agent runtimes through the same broker: `BrokeredRegistry`, OpenAI-style
`brokered_tool`, and Claude Code PreToolUse CLI (`containment-claude-hook`).
See [docs/RUNTIME_ADAPTER.md](docs/RUNTIME_ADAPTER.md). Install does not auto-wire
host hooks; users can disable Claude hooks (host-config residual).

## Reference host demo (Bar D)

Runnable end-to-end wiring: `containment-reference-host` exercises attack deny,
benign allow, and require_human approval against `build_enterprise_host` +
`BrokeredRegistry` (offline by default). See
[docs/REFERENCE_HOST.md](docs/REFERENCE_HOST.md).

```bash
containment-reference-host --scenario all
```

## Install

Python 3.12+ recommended. PyPI package name is `containment`.

```bash
pip install "git+https://github.com/Hyper-AI-Lab/prompt-injection-defense.git"
```

From a clone:

```bash
git clone https://github.com/Hyper-AI-Lab/prompt-injection-defense.git
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

### Enable PIGuard (optional)

Default `ingest()` stays **RulesOnly** (fail-closed metadata) until the host wires
PIGuard and passes cascade / `fail_closed_privileged` into the broker. Recipe and
host residual checklist: [docs/AGENT_INSTALL.md](docs/AGENT_INSTALL.md) §7–§8.
Short path: `CONTAINMENT_STAGE1=piguard` + `CONTAINMENT_PIGUARD_ALLOW_DOWNLOAD=1`,
or `make_stage1_cascade(prefer="piguard", allow_download=True)`.

OWASP LLM Top 10 control map: [docs/OWASP_LLM_TOP10_MAP.md](docs/OWASP_LLM_TOP10_MAP.md).

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
# Prefer build_enterprise_host() for production (see docs/HOST_HARDENING.md).
from containment.host import FileSecretProvider

secrets = FileSecretProvider(Path("secrets"))  # files: capability, intent
policy = PolicyEngine.from_yaml_path("policies/default_deny.yaml")
broker = ToolBroker(
    policy=policy,
    audit=AuditLog(Path("audit.jsonl")),
    minter=CapabilityMinter(secret=secrets.get_bytes("capability")),
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

Citable ON+OFF scorecard (Markdown + JSON; fail-closed prove-it):

```bash
containment-eval-card --suite fixtures --out-dir artifacts/eval-card
```

See [docs/EVAL_CARD.md](docs/EVAL_CARD.md). Fixture-only offline rates — not a
public leaderboard or SOTA claim. `release_gate.sh` keeps the single ON eval;
the card CLI is the separate prove-it smoke.

## Package layout

- `src/containment/` — labels, policy, broker, ingest, detectors, quarantine, moltbook, adapters (Bar C), reference_host (Bar D), eval_card (Bar E), CLI
- `policies/default_deny.yaml` — default-deny tool policy
- `fixtures/attacks` / `fixtures/benign` — offline eval corpus
- `docs/` — threat model, architecture, agent install, host hardening, eval card
- `SKILL.md` — procedure for Grok bots / agents

## Agent install

See [docs/AGENT_INSTALL.md](docs/AGENT_INSTALL.md),
[docs/HOST_HARDENING.md](docs/HOST_HARDENING.md), and [SKILL.md](SKILL.md).

## CI / SBOM (local)

GitHub Actions: `.github/workflows/ci.yml` (ruff, pytest, `scripts/release_gate.sh`, `pip-audit`, CycloneDX).
Dependabot: `.github/dependabot.yml`.

```bash
pip install pip-audit "cyclonedx-bom>=5"
pip-audit
cyclonedx-py environment -o sbom.cdx.json --of json --pyproject pyproject.toml --mc-type library
```

## License

Apache-2.0. See [LICENSE](LICENSE).
