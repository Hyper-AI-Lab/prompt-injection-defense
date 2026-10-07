# Development Plan: `containment` — production prompt-injection defense kit

**Date:** 2026-10-07  
**Mode:** poteto-mode / figure-it-out  
**Sources:** Kirill research (`KIRILL_RESEARCH.md`) + Shiva prior detector survey  
**Build host:** box only (no Cursor Cloud Agents)  
**Progress log:** append-only `PROGRESS_LOG.md` (created at execution start)

## Done predicate (falsifiable)

A release is VERIFIED only if all of the following hold on the real artifact:

1. `pip install -e ".[dev]"` succeeds on Python 3.12+ on this box.
2. `pytest -q` is green, including contract tests that prove:
   - unknown tools are denied by default
   - untrusted-labeled data cannot reach a privileged sink (`email.send` / `http.post` style) without explicit policy allow + approval stub
   - detector failure / timeout fails closed for privileged tools
   - quarantined extract returns only schema-allowed keys
3. `python -m containment.cli eval --suite fixtures` prints measured ASR / FPR / utility numbers (not placeholders) against committed fixtures.
4. Package ships agent-facing install instructions (`SKILL.md` + `docs/AGENT_INSTALL.md`) with zero “TODO / TBD / implement later” markers.
5. `rg -n 'TODO|FIXME|NotImplemented|pass  #|placeholder|TBD' src tests docs` returns no hits except license-legal text if any.
6. README states threat model and explicitly refuses an “injection-proof” claim.

## Honest product claim

Not “injection-proof.” Testable claim: even if malicious text influences a model, untrusted data cannot acquire authority, privileged calls cannot bypass the reference monitor, and irreversible actions require exact independent authorization.

## Scope (v1.0)

**In**
- Framework-neutral Python library `containment`
- Core types: `SecurityLabel`, `IntentEnvelope`, `Plan`, `ProposedAction`, `PolicyDecision`, `TraceEvent`
- Default-deny YAML policy engine (allow / deny / require_human)
- Tool broker `secure_execute` with schema validation, taint check, one-use capability mint, audit append
- Ingestion pipeline: label → normalize → Stage0 rules → Stage1 local detector adapter → quarantine typed extract → provenance
- Datamarking / spotlighting helpers
- Detector adapters: PIGuard (default local), optional Prompt Guard 2 (gated HF), optional StackOne Defender if Apache and installable; null/fail-closed stub for CI without weights
- Quarantined reader API for Moltbook-style public feeds (no tools, fixed schema)
- Eval harness + committed attack/benign fixtures (synthetic + sample from public Moltbook dataset if license OK)
- Agent skill / install docs for Grok bots and generic agents
- Progress log + decision trail

**Out of v1.0 (documented as future, not stubs in code)**
- Full Microsoft Agent Framework FIDES dependency (license/framework lock-in)
- Full CaMeL research runtime port
- Hosted Lakera / Azure Prompt Shields
- Live AgentDojo CI (optional later; we ship a compatible fixture shape)
- TypeScript SDK

## Package layout

```
containment/
  pyproject.toml
  README.md
  LICENSE (Apache-2.0)
  PROGRESS_LOG.md
  DECISIONS.md
  SKILL.md
  docs/
    AGENT_INSTALL.md
    THREAT_MODEL.md
    ARCHITECTURE.md
  src/containment/
    __init__.py
    labels.py
    plan.py
    actions.py
    policy.py
    broker.py
    ingest.py
    quarantine.py
    datamark.py
    detectors/
      base.py
      rules.py
      piguard.py
      prompt_guard2.py
      cascade.py
    audit.py
    capability.py
    moltbook.py
    cli.py
  policies/
    default_deny.yaml
  tests/
    ...
  fixtures/
    attacks/
    benign/
```

## Execution steps (law — one point, one solution)

Execute strictly in order. After each step: run the step’s verify command, append a dated section to `PROGRESS_LOG.md`, do not start the next step until VERIFIED.

1. **Scaffold** — create repo layout, `pyproject.toml`, Apache-2.0 LICENSE, empty packages, Ruff/pytest config. Verify: `pip install -e ".[dev]"` and `pytest -q` (zero tests OK but runner works).
2. **Core types** — implement frozen dataclasses for labels, envelopes, plans, actions, decisions. Verify: unit tests for immutability and illegal-state rejection.
3. **Policy engine** — YAML load + default deny + allow/deny/require_human with taint predicates. Verify: table-driven tests from Kirill’s example policy rules.
4. **Capability + audit** — one-use capability mint/verify; append-only JSONL audit. Verify: second use fails; audit round-trip.
5. **Broker** — `secure_execute` reference monitor. Verify: unknown tool denied; tainted egress denied; require_human path calls approval hook.
6. **Stage-0 rules** — Unicode normalize, invisible chars, basic encoding discovery, size limits. Verify: fixture corpus for hidden chars / base64 markers.
7. **Detector cascade** — Stage0 → Stage1 adapter → Stage3 policy only (Stage2 contextual deferred as optional hook interface with a real no-op implementation that returns `inconclusive`, not a stub raise). Verify: cascade never authorizes; only policy authorizes.
8. **PIGuard adapter** — download/load via Hugging Face if available; else `RulesOnlyDetector` path selected by config with fail-closed for privileged sinks. Verify: offline CI path green; optional GPU/CPU weight path tested when weights present.
9. **Quarantine + typed extract** — tool-less extract API validating closed JSON Schema. Verify: extra keys rejected; instruction-like free text rejected when schema forbids.
10. **Datamarking** — random marker insertion + unwrap helper. Verify: round-trip integrity; marker uniqueness per call.
11. **Ingestion pipeline** — wire label → normalize → cascade → quarantine → labeled typed result. Verify: end-to-end on one attack fixture and one benign fixture.
12. **Moltbook reader** — public API client + containment ingest + fixed summary schema. Verify: live fetch mocked in unit tests; one optional live smoke (network) marked separately.
13. **CLI eval** — `containment eval` over fixtures, prints ASR/FPR/utility. Verify: numbers change when policy is disabled (control experiment).
14. **Fixture corpus** — commit ≥30 attack + ≥30 benign cases covering direct/indirect, trigger words benign, invisible unicode, encoded payloads. Verify: eval runs offline.
15. **Docs + SKILL** — README, threat model, architecture, agent install, Grok-bot procedure. Verify: no TODO/placeholder markers; install instructions runnable as written.
16. **Release gate script** — `scripts/release_gate.sh` runs install, lint, tests, eval, placeholder scan. Verify: script exit 0 on clean tree.
17. **Deep-research spot-checks** — for PIGuard, StackOne Defender-py, Microsoft AGT, Invariant: confirm license, last release, installability on this box; record in DECISIONS.md; wire only what passes due diligence. Verify: DECISIONS.md lists adopt/skip with URLs and dates.
18. **Final prove-it** — run release gate; package version `1.0.0`; hand back artifact path + measured eval numbers + known limits.

## Rigor

High. One-way doors are the public API surface and threat-model claim. Verification harness before feature depth. Local executor swarm allowed for parallel fixture writing and due-diligence fetches; no cloud agents.

## Defaults if you approve without extra answers

- Package name: `containment`
- License: Apache-2.0
- Language: Python 3.12+ (venv if system is 3.13-only for optional deps)
- GitHub: local repo on box first; push only if you name org/repo later
- Primary consumer: Grok bots + any Python agent
- Detector default: rules + PIGuard when weights available, else rules-only with fail-closed on privileged tools

## Explicit non-goals for this run

- Claiming adaptive-attack immunity
- Replacing OS sandboxing / network egress controls
- Shipping Meta gated weights inside the package
