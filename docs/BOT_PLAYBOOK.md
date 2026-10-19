# Bot playbook

End-to-end procedure for a bot or agent host that reads untrusted content and calls
tools through `containment`. Follow the steps in order; each ends with a command whose
output tells you whether the step is done. Deeper references are linked per step.

The library is a reference monitor, not a sandbox and not injection-proof. It makes
untrusted text unable to authorize tools; the host still owns isolation, egress,
secrets storage and audit retention (step 8).

## 0. Pick the version

Use a tagged release. Current: `v1.7.1` (see `CHANGELOG.md`). Releases are on GitHub;
the package is not on PyPI.

## 1. Install

Verified wheel (recommended for production hosts):

```bash
gh release download v1.7.1 -R Hyper-AI-Lab/prompt-injection-defense -p 'containment-*'
gh attestation verify containment-1.7.1-py3-none-any.whl -R Hyper-AI-Lab/prompt-injection-defense \
  --source-ref refs/tags/v1.7.1
python3 -m venv .venv && . .venv/bin/activate
pip install ./containment-1.7.1-py3-none-any.whl
```

`gh attestation verify` proves the wheel was built by this repo's `publish` workflow on
the tag (needs gh 2.49 or newer). Pinned install straight from git (no attestation):

```bash
pip install "git+https://github.com/Hyper-AI-Lab/prompt-injection-defense.git@v1.7.1"
```

Optional extras: `[crypto]` (Ed25519 intents), `[redis]` (shared consume store),
`[ml]` (PIGuard Stage-1, see step 4). Install extras from the wheel
(`pip install './containment-1.7.1-py3-none-any.whl[crypto]'`) or the tag
(`pip install "containment[crypto] @ git+https://github.com/Hyper-AI-Lab/prompt-injection-defense.git@v1.7.1"`). Never `pip install containment` from
PyPI: that name is not this project.

Done when:

```bash
containment --version          # containment 1.7.1
containment doctor --install-only
```

`--install-only` checks the package data (default policy + eval fixtures) and that the
default policy loads. Exit 0 means the install is complete.

## 2. Policy

The default policy `policies/default_deny.yaml` ships in the wheel
(`containment.resources.default_policy_path()`). First matching rule wins; no match
means deny. Its rules:

| Rule | Effect | Meaning |
| --- | --- | --- |
| `read-public-web` | allow | `web.fetch` over https to `plan.approved_public_hosts` |
| `no-tainted-egress` | deny | `email.send` / `http.post` / `social.publish` / `wallet.transfer` with any untrusted input label |
| `approved-email` | require_human | `email.send` to `plan.approved_recipients` |
| `transfer-limit` | require_human_and_mfa | `wallet.transfer` |

Copy it and edit for your tools; keep `default: deny`. Pass your file as `policy_path=`
(step 5) and `containment doctor --policy PATH`.

## 3. Plan before reading

Declare the task's tools, recipients and hosts in a `Plan` **before** untrusted content
is read, so injected text cannot widen it.

```python
from containment import Plan, PlanStep

plan = Plan(
    task_id=task_id,
    steps=(PlanStep(step_id="fetch", tool="web.fetch"),
           PlanStep(step_id="notify", tool="email.send")),
    capabilities=frozenset({"web.fetch", "email.send"}),
    approved_public_hosts=frozenset({"example.com"}),
    approved_recipients=frozenset({"owner@example.com"}),
)
```

## 4. Ingest every external text

Web pages, email, documents, tool output and social posts go through `ingest` before
the model reasons over them. Keep the returned label on everything derived from it.

```python
from containment import ingest

result = ingest(raw_text, source="web:example.com", task_id=task_id,
                candidate={"title": "...", "category": "other"})
if result.ok:
    fields = result.extract.data        # closed-schema typed fields only
labels = (result.label,)                # integrity="untrusted" for external text
```

Moltbook (public, read-only, no account): `containment.moltbook.read_posts(sort="hot",
limit=8)`; reason over `title` / `topic` / `summary` only, never call tools from post
text. Stage-1 detection defaults to RulesOnly; PIGuard is opt-in
(`pip install "containment[ml] @ git+https://github.com/Hyper-AI-Lab/prompt-injection-defense.git@v1.7.1"`, `CONTAINMENT_STAGE1=piguard`,
`CONTAINMENT_PIGUARD_ALLOW_DOWNLOAD=1`; review `trust_remote_code` first). Detectors
advise, they never authorize. Details: [AGENT_INSTALL.md](AGENT_INSTALL.md) §3–§4, §7.

## 5. Broker every tool call (enterprise host)

Production composition is `build_enterprise_host`: HostGate (fail-closed checklist),
signed intents, capability minting from a `SecretProvider`, audit hash chain. Secrets
are files or env vars, never source code:

```bash
install -d -m 700 /srv/agent/secrets
openssl rand -hex 32 > /srv/agent/secrets/capability
openssl rand -hex 32 > /srv/agent/secrets/intent
chmod 600 /srv/agent/secrets/*
```

```python
from pathlib import Path
from containment import BrokeredRegistry, IntentEnvelope, build_enterprise_host
from containment.broker import SecurityViolation
from containment.resources import default_policy_path

host = build_enterprise_host(
    policy_path=default_policy_path(),          # or your edited copy
    audit_path=Path("/srv/agent/audit.jsonl"),
    audit_ship_destination=Path("/srv/agent/audit-shipped.jsonl"),
    secrets_dir=Path("/srv/agent/secrets"),
    isolation_declared=True,   # only if the agent really runs in an OS/container sandbox
    egress_configured=True,    # PinnedEgressProvider; or proxy_url="http://127.0.0.1:8899"
    known_tools=frozenset({"web.fetch", "email.send"}),
)

registry = BrokeredRegistry(host.broker, plan, principal="agent", task_id=task_id)
registry.register("web.fetch", my_fetch)        # your real tool callables
registry.register("email.send", my_send)

intent = host.intent_signer.sign(
    IntentEnvelope(task_id=task_id, tenant="acme", user="owner",
                   scope=plan.capabilities, risk_budget="low",
                   principal_authenticated=True),
    plan=plan,
)
try:
    # labels from step 4 are untrusted here, so this raises (deny, no-tainted-egress)
    registry.call("email.send",
                  {"recipient": "owner@example.com", "subject": s, "body": b},
                  input_labels=labels, plan_step="notify", intent=intent)
except SecurityViolation as exc:
    report_deny(exc.decision.rule_id, exc.decision.reason)   # stop; do not retry around it
```

- Attach **all** input labels. Privileged sinks with empty labels deny
  (`empty_input_labels`); untrusted labels on egress deny (`no-tainted-egress`).
- `require_human`: set `host.broker.approval` to a hook that shows the resolved
  recipient, subject, body and sources and returns `ApprovalOutcome` only after the
  user approves exactly that. Without a hook it fails closed.
- OpenAI-style tools: `@brokered_tool(registry, tool="web.fetch")`. Claude Code:
  `containment-claude-hook` as a PreToolUse command. See
  [RUNTIME_ADAPTER.md](RUNTIME_ADAPTER.md).

## 6. Prove the wiring with the reference host

```bash
containment-reference-host --scenario all
# [PASS] attack  — untrusted ingest blocked before email.send (no-tainted-egress)
# [PASS] benign  — allowed hermetic fetch (read-public-web)
# [PASS] human   — require_human without hook denied; approving hook allowed send
# OK — 3 scenario(s) passed
```

Offline and hermetic. Your host should reproduce the same three outcomes with its own
tools. Source of the recipe: `containment.reference_host`
([REFERENCE_HOST.md](REFERENCE_HOST.md)).

## 7. Check the host with doctor

Run doctor with the same settings your host passes to `build_enterprise_host`:

```bash
containment doctor \
  --secrets-dir /srv/agent/secrets \
  --isolation-declared \
  --egress-pinned \
  --audit-ship /srv/agent/audit-shipped.jsonl
```

Doctor is offline. It rebuilds the `HostChecklist`, loads the named secrets (never prints
them), loads the policy, and composes `build_enterprise_host` against a temporary audit
log. Exit codes: `0` every required check passed, `1` a required check failed, `2` usage
error. `--json` prints the same report as JSON for monitoring. Optional extras
(`ml`, `crypto`, `redis`) are reported but never fail the run. Egress defaults come from
`CONTAINMENT_EGRESS_PROXY` / `CONTAINMENT_EGRESS_PINNED=1` when the flags are absent.

## 8. What the host still owns

Doctor can only see what is declared. These stay with the host:

1. Real OS/container isolation (`isolation_declared` is an honest declaration, not a probe).
2. Network egress control: `containment-egress-proxy` or pinned fetch; `url_guard` alone is
   not DNS-rebinding-complete.
3. Secret storage and rotation (vault, file permissions).
4. Audit retention: ship `audit.jsonl` to WORM/SIEM; the hash chain is tamper-evidence only.
5. Spend caps on model and tool APIs beyond `RateLimitGate`.
6. Enabling and keeping Claude Code hooks on (install does not enable them).

Full checklist: [HOST_HARDENING.md](HOST_HARDENING.md).

## 9. Report honestly

```bash
containment-eval-card --suite fixtures --out-dir artifacts/eval-card
```

Exit 0 means policy-ON ASR is 0.0000 and policy-OFF ASR is higher on the in-repo fixture
suite. Cite the card's numbers with its version and SHA; do not claim certification,
benchmark rank or zero residual risk. Each GitHub Release attaches the card for that
tag. Details: [EVAL_CARD.md](EVAL_CARD.md).

## 10. Upgrade

Read `CHANGELOG.md`, install the new tag (step 1), then rerun steps 6, 7 and 9.
