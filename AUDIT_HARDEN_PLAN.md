# Audit & Harden Plan — `containment` production integrity

**Date:** 2026-10-07 (JST)  
**Mode:** figure-it-out / Karpathy surgical  
**Inputs:** `DEVELOPMENT_PLAN.md` (approved), `AUDIT_PLAN_VS_CODE.md`, `AUDIT_CODE_FINDINGS.md`, `DECISIONS.md`, `PROGRESS_LOG.md`  
**Build host:** box only (no Cursor Cloud Agents)  
**Progress log:** append-only `PROGRESS_LOG.md` after every step  
**Package:** keep name `containment`; bump version to **1.1.0** only at final prove-it

## Done predicate (falsifiable)

Release VERIFIED only if all hold on the real artifact:

1. Every step below is VERIFIED with evidence appended to `PROGRESS_LOG.md`.
2. `scripts/release_gate.sh` exits 0.
3. `pytest -q` green; new regression tests cover each HIGH/MEDIUM fix (fail-before/pass-after where practical).
4. Empty `input_labels` on privileged sinks → deny (not require_human/allow).
5. `ToolBroker.secure_execute` enforces `privileged_sink_fail_closed` when cascade/selection says fail-closed.
6. `default_ingest_cascade()` uses production RulesOnly via `select_stage1` (Fake only in tests/helpers).
7. Broker binds `action.plan_step` to `Plan` (`step.tool == action.tool`); expired plans denied.
8. `requires_mfa` cannot mint without MFA-verified approval; rule `display` passed to approval hook.
9. Shipped policy `limits` that remain in YAML are enforced (or removed from YAML in the same step).
10. Eval reports **detector_block_rate** and **policy_block_rate** separately; ASR with policy ON is not a constant synthetic identical deny for every case.
11. Placeholder scan clean (`TODO|FIXME|NotImplemented|pass  #|placeholder|TBD` on src/tests/docs/SKILL/README).
12. No intentional Out-of-v1.0 scope creep (no FIDES/CaMeL/AGT/Invariant/PG2 weights/TS SDK).

## Honest claim (unchanged)

Not injection-proof. Harden authority path so documented controls actually fire.

## Explicit non-goals (do not add as steps)

CaMeL/FIDES/AGT/Invariant ports; Meta gated weights; OS sandbox/SSRF full stack; IntentEnvelope cryptography; Stage-2 real LLM; claiming adaptive immunity.

## Execution steps (law — one point, one solution)

Execute strictly in order. After each step: run that step’s verify command, append a dated section to `PROGRESS_LOG.md`, do not start the next until VERIFIED. Do not invent sub-steps or expand scope mid-run. If a step would break coherence, stop and record NOT VERIFIED with evidence — do not silently weaken the predicate.

1. **Baseline capture** — Run `scripts/release_gate.sh`; record exit code, pytest summary, ASR/FPR/utility (policy ON and OFF) in PROGRESS_LOG. Verify: gate exit recorded; no code changes.

2. **Empty-label fail-closed (H1)** — Privileged sinks (`PRIVILEGED_SINKS` / no-tainted-egress tools) with empty/missing `input_labels` → policy or broker **deny** + audit. Regression test. Verify: test fails on old behavior if reverted; `pytest tests/test_broker.py tests/test_policy.py -q` green.

3. **Wire detector fail-closed into broker (H2)** — `secure_execute` accepts optional `CascadeResult` and/or `fail_closed_privileged`; when `privileged_sink_fail_closed(tool, cascade)` would apply, deny before mint even if policy would allow/require_human. Integration test. Verify: `pytest tests/test_broker.py tests/test_cascade.py -q` green; helper still unit-tested.

4. **Production default ingest cascade (H3)** — Change `default_ingest_cascade()` to `select_stage1(prefer="rules_only")` path (RulesOnly + fail_closed metadata). Keep `FakeStage1Detector` for tests/eval helpers only; update call sites that relied on Fake default. Verify: ingest/moltbook tests green; production default is not Fake.

5. **Plan step binding (M1)** — In broker: resolve `plan.step_by_id(action.plan_step)`; require `step.tool == action.tool`; else deny + audit. Test wrong step id / tool mismatch. Verify: broker tests green.

6. **Plan expiry (M4)** — Deny when `plan.expiry_unix` is set and now > expiry. Test. Verify: broker/plan tests green.

7. **MFA + display on approval (M2 / part H4)** — If `decision.requires_mfa`, require approval hook to signal MFA verified (explicit API: e.g. return object/tuple or dedicated hook); default fail closed. Pass rule `display` into approval call. Tests for MFA deny and display passthrough. Verify: broker tests green.

8. **Enforce or strip policy limits (H4)** — For keys present in `default_deny.yaml` `limits` (`max_bytes`, `redirects`, `network`/schemes as applicable): enforce in broker/policy evaluation for matching tools, with tests; pass-through unused keys must not remain silently. If a limit cannot be enforced without inventing network stack, remove that key from shipped YAML in the same step and document in DECISIONS. Verify: policy/broker tests + YAML matches enforced surface.

9. **Confidentiality predicate honesty (M3)** — Rename or dual-support: document and implement `input.max_confidentiality_lte` (labels) and optionally honor args field with documented max(); update YAML + tests. Verify: policy tests green; no silent wrong-name behavior.

10. **Stage-2 NoOp aggregate footgun (M5)** — Ensure enabling default Stage-2 NoOp does not force aggregate `inconclusive` that always fail-closes privileged tools; omit NoOp from severity aggregate or treat as non-elevating. Test. Verify: cascade tests green.

11. **Stage-0 encoding discovery (plan WEAK step 6)** — Extend Stage-0 to flag hex runs, percent-encoding, rot13-hint patterns as discovery findings (no decode-execute). Tests using existing encoded fixtures. Verify: stage0 tests green; fixtures that scored 0 now produce findings where appropriate.

12. **Stage-1 timeout → error (done-predicate)** — Wrap Stage-1 scan with a bounded timeout; on timeout set detector label `error` so fail-closed privileged path applies. Test with a slow fake detector. Verify: cascade/piguard tests green.

13. **Eval honesty (H5 / M6)** — Per-case: use that case’s labels/cascade (and RulesOnly or shared production-like cascade, not silent constant); report `detector_block_rate` and `policy_block_rate` in CLI output; keep `--no-policy` control. Align high_risk heuristics with RulesOnly/quarantine patterns where Fake remains for unit tests only. Verify: eval runs offline; ON vs OFF still differs; numbers not identical synthetic deny for all 38 unless truly path-identical.

14. **Per-tool argument schema (plan step 5 WEAK)** — Add minimal JSON Schema registry for tools in default policy (`web.fetch`, `email.send`, `http.post`, `wallet.transfer`); broker validates args with `additionalProperties: false` when schema known; unknown tools still denied. Tests. Verify: broker tests green.

15. **Capability MAC delimiter (L2)** — Replace comma-join with unambiguous encoding (length-prefix or JSON array) for resource list in MAC. Test collision case. Verify: capability tests green.

16. **Audit integrity residual (L3)** — Document residual risk clearly in `docs/THREAT_MODEL.md` (filesystem writer can truncate). Optionally add simple hash-chain field on events if small; do not claim WORM. Verify: docs updated; tests still green.

17. **Public exports + packaging hygiene (L1 + scaffold)** — Re-export documented helpers (`closed_object_schema`, `ALLOWLIST_SUMMARY_SCHEMA`, `MoltbookError`, `DetectorCascade`, `select_stage1`) or document submodule-only policy in README consistently. Fix `pyproject.toml` classifiers nesting under `[project.urls]`. Align `release_gate.sh` placeholder `rg` with done-predicate pattern (`pass  #` included). Fix IntentEnvelope “v0.1” docstring vs 1.x. Verify: import smoke + gate placeholder scan.

18. **Web deep-research spot-check** — For Stage-1 timeout patterns and any 2026 updates to PIGuard / StackOne Defender relevant to fail-closed integration: fetch current docs/releases; append adopt/skip notes to `DECISIONS.md`. No new heavy deps unless clearly superior and installable without breaking offline CI. Verify: DECISIONS entry with URLs and date.

19. **Final prove-it** — Bump version to `1.1.0`; run full `scripts/release_gate.sh`; append measured metrics + remaining known limits; ensure AUDIT findings H1–H5 and M1–M6 marked addressed in PROGRESS_LOG. Push to `origin/main` on Hyper-AI-Lab/prompt-injection-defense. Verify: gate exit 0; remote main updated.

## Rigor

High for authority path (steps 2–8, 12–14). Medium for discovery/eval honesty (11, 13). Docs/packaging mechanical (16–17).

## Defaults

- Surgical diffs; match existing style.
- Fake detectors only in tests / explicit helpers.
- Ask K only if a step is blocked by a product preference (e.g. strip vs enforce a limit that needs network stack).
