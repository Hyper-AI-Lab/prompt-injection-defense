# Reference Host Plan — Bar D (→ 1.5.0)

**Date:** 2026-10-07 JST  
**Mode:** poteto-mode / plan-as-law / local executors  
**Inputs:** K approval (Bar D as framed); containment 1.4.0; Janus/OWASP-style attack-then-defense gate demos  
**Bar:** D — Reference host demo: enterprise compose + BrokeredRegistry + ingest + hermetic attack/benign/human paths  
**Host:** box only; append-only `PROGRESS_LOG.md`  
**Version:** bump to **1.5.0** at final prove-it only

## Done predicate

1. Every step VERIFIED with PROGRESS_LOG evidence.
2. Package `containment.reference_host` + CLI `containment-reference-host`: offline-by-default scenarios (attack deny, benign allow, require_human approval path); uses `build_enterprise_host` + secrets under tmp + `BrokeredRegistry` + `ingest`; Moltbook live only behind `CONTAINMENT_LIVE_MOLTBOOK`.
3. Hermetic tests cover all three paths; no placeholders; audit events asserted.
4. `docs/REFERENCE_HOST.md` + README / AGENT_INSTALL / DECISIONS / SKILL / exports updated.
5. `release_gate.sh` exit 0; version **1.5.0** on `origin/main`.

## Explicit non-goals

- Eval card / release ritual / bot playbook (later)
- Auto-wire Claude.app; OS sandbox / FedRAMP claims
- LLM round-trips in CI; requiring live network for prove-it

## Execution steps (law)

1. **Baseline** — gate + pytest + eval; no code.
2. **Fixtures + reference_host core** — scenario fixtures; host builder wiring enterprise + registry.
3. **Scenarios** — attack / benign / human paths complete.
4. **CLI** — `containment-reference-host` entrypoint + pyproject script.
5. **Tests** — hermetic coverage; optional live skip.
6. **Docs + exports** — REFERENCE_HOST.md; README/AGENT_INSTALL/DECISIONS/SKILL/__init__.
7. **Final prove-it** — version 1.5.0; release_gate; push origin/main.

After each step: verify, append PROGRESS_LOG, do not start next until VERIFIED.
