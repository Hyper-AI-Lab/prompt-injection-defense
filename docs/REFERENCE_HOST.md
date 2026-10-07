# Reference host demo (Bar D)

End-to-end wiring recipe: `build_enterprise_host` + signed intents +
`BrokeredRegistry` + ingest + hermetic demo tools. This is the concrete answer
to “install ≠ wired” — a runnable host that proves the broker is the authority.

## Quick run

```bash
pip install -e ".[dev]"
containment-reference-host --scenario all
# [PASS] attack / benign / human
# OK — 3 scenario(s) passed
```

Options:

| Flag | Meaning |
| --- | --- |
| `--scenario attack\|benign\|human\|all` | Which path (default `all`) |
| `--work-dir DIR` | Persist secrets + audit JSONL (else temp) |
| `--live-moltbook` | Optional one-post ingest; requires `CONTAINMENT_LIVE_MOLTBOOK=1` |

Default mode is **offline** (no live network). Hermetic stubs implement
`web.fetch` and `email.send`; they never open sockets.

## What each path proves

### Attack (deny)

1. Load `attack_inject.txt` (injection telling the model to `email.send` / exfil).
2. `ingest(..., integrity="untrusted")` → `SecurityLabel(integrity="untrusted")`.
3. Propose `email.send` with those labels through the registry + **signed intent**.
4. Policy rule `no-tainted-egress` → **deny**; stub never runs; audit records deny.

### Benign (allow)

1. Optional ingest of `benign_note.txt` (trusted).
2. Signed intent + trusted labels + `web.fetch` to `https://example.com/...`
   (`approved_public_hosts`, capability `web.fetch`).
3. Rule `read-public-web` → **allow**; hermetic stub returns a fake body string.
4. Audit records allow.

### Human (require_human)

1. Trusted labels + `email.send` to an approved recipient (`alice@acme.test`).
2. Rule `approved-email` → **require_human**.
3. Without an approval hook the broker fails closed (`SecurityViolation`).
4. With `ApprovalOutcome(mfa_verified=False)` on `broker.approval`, mint + stub run.
5. Audit records `require_human` / `approved-email`.

## Library API

```python
from pathlib import Path
from containment.reference_host import build_reference_host, run_all, STEP_FETCH

host = build_reference_host(Path("/tmp/ref-host"))
# host.enterprise — EnterpriseHost (checklist, broker, signer, …)
# host.registry  — BrokeredRegistry
# host.sign_intent() / host.call(...) — signed-intent helpers

out = host.call(
    "web.fetch",
    {"url": "https://example.com/"},
    input_labels=(host.trusted_label(),),
    plan_step=STEP_FETCH,
)
results = run_all(Path("/tmp/ref-host-all"))
```

Enterprise compose requires:

- `secrets_dir` with `capability` + `intent` files (≥32 bytes) — created under
  `work_dir/secrets/` by the builder.
- `isolation_declared=True` and `egress_configured=True` (PinnedEgressProvider).
- Every `secure_execute` / registry `call` passes a `SignedIntent` from
  `host.intent_signer.sign(...)`.

## Policy packaging (residual)

The reference-host CLI embeds scenario policy in code/fixtures and does **not** expose
`--policy` / `CONTAINMENT_POLICY` the way `containment-claude-hook` does. Wheel installs
ship the hermetic fixtures used by offline scenarios. Hosts that need a custom YAML
policy should compose `build_reference_host` / `build_enterprise_host` in-process and
pass their own `PolicyEngine`, or use the Claude hook CLI which does accept a policy path.

## Residuals (honest)

- **`isolation_declared` is honor-system** for this demo: the library cannot
  prove OS/container isolation; production hosts must actually isolate.
- **Live Moltbook is optional** and off by default; CI never requires it.
- Claude.app / IDE hooks are **not** auto-wired here (see
  [RUNTIME_ADAPTER.md](RUNTIME_ADAPTER.md)); this package shows the in-process
  wiring recipe.
- Hermetic stubs are not a substitute for resolve-pin egress in production —
  use `docs/HOST_HARDENING.md` for real network control.

## Related

- [HOST_HARDENING.md](HOST_HARDENING.md) — enterprise checklist
- [RUNTIME_ADAPTER.md](RUNTIME_ADAPTER.md) — BrokeredRegistry / Claude hook
- [AGENT_INSTALL.md](AGENT_INSTALL.md) — install + residual checklist
- `policies/default_deny.yaml` — rules exercised by the scenarios
