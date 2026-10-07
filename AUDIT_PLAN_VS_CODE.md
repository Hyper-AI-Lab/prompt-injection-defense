# Audit: DEVELOPMENT_PLAN / vision vs actual code

**Date:** 2026-10-07 (JST)  
**Artifact:** `/workspace/prompt-injection-defense` (`containment==1.0.0`)  
**Public repo:** Hyper-AI-Lab/prompt-injection-defense  
**Method:** read-only compliance matrix against ORIGINAL `DEVELOPMENT_PLAN.md`, `DECISIONS.md`, `KIRILL_RESEARCH.md` (architecture claims), `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `PROGRESS_LOG.md` known limits, and live `src/containment/**` + tests/fixtures/policies/docs.  
**Constraint:** box only; no code modifications; no Cursor Cloud Agents.

**Classification legend**

| Tag | Meaning |
| --- | --- |
| **PRESENT & COMPLETE** | Plan item exists with verify-grade evidence |
| **PRESENT BUT WEAK** | Exists, but named concrete gap vs plan/done-predicate/vision |
| **MISSING** | Should have been in v1 per plan / done-predicate |
| **INTENTIONALLY OUT** | Explicitly out of v1.0 (cite DECISIONS / Out of v1.0 / non-goals) |

---

## Executive counts (for handoff)

| Metric | Value |
| --- | --- |
| Plan-step WEAK | 5 |
| Plan-step MISSING | 0 |
| In-scope WEAK | 4 |
| Done-predicate WEAK | 3 (incl. detector fail-closed integration gap) |
| Unique WEAK themes (plan+in-scope+done+vision) | **10** |
| Hard MISSING integration vs done-predicate | **1** (broker does not enforce detector fail-closed/timeout) |
| Top harden candidates | 10 (see §F) |

---

## A. Eighteen execution steps

| # | Step | Status | Evidence | Gap (if any) |
| --- | --- | --- | --- | --- |
| 1 | Scaffold | **PRESENT & COMPLETE** | `pyproject.toml`, `LICENSE` (Apache-2.0), `src/containment/`, `tests/`, `policies/`, `fixtures/`, `docs/`, Ruff/pytest config in `pyproject.toml`, `.venv` install path in `PROGRESS_LOG.md` Step 1 | Minor packaging: PyPI `classifiers` incorrectly nested under `[project.urls]` as a URL key (`pyproject.toml` lines ~19–27) — does not block install |
| 2 | Core types | **PRESENT & COMPLETE** | Frozen dataclasses: `SecurityLabel` (`labels.py`), `IntentEnvelope`/`Plan`/`PlanStep` (`plan.py`), `ProposedAction`/`PolicyDecision`/`TraceEvent` (`actions.py`); `tests/test_core_types.py` | `IntentEnvelope` docstring admits “unsigned in v0.1” (`plan.py:10`); unused by broker (vision gap, not plan step failure) |
| 3 | Policy engine | **PRESENT BUT WEAK** | `PolicyEngine` YAML load + default deny (`policy.py`); `policies/default_deny.yaml` matches Kirill example rules; table tests `tests/test_policy.py` | (1) `limits` / `display` parsed onto `PolicyRule` (`policy.py:32–33,139–157`) but **never enforced** by engine or broker. (2) Empty `input_labels` makes `input.any_integrity: untrusted` false → `no-tainted-egress` skipped → `email.send` falls through to `require_human` / allow paths (probed live). (3) `require_human_and_mfa` sets `requires_mfa=True` but MFA is not broker-enforced |
| 4 | Capability + audit | **PRESENT & COMPLETE** | `CapabilityMinter.one_use`/`verify` HMAC one-use (`capability.py`); `AuditLog` JSONL append/read (`audit.py`); `tests/test_capability_audit.py` | Consumed-token set is process-local memory only (`capability.py:33`) — acceptable for library v1, not multi-process revocation |
| 5 | Broker `secure_execute` | **PRESENT BUT WEAK** | `ToolBroker.secure_execute` (`broker.py:90–157`): known-tool gate, schema hook, policy, audit, deny, approval, capability mint; tests unknown/tainted/require_human (`tests/test_broker.py`) | (1) **`privileged_sink_fail_closed` / `fail_closed_privileged` not called from broker** (no import of cascade in `broker.py`). (2) `default_schema_validator` only checks non-empty tool + `Mapping` (`broker.py:29–48`) — not per-tool JSON Schema. (3) Does not bind `action.plan_step` via `Plan.step_by_id` or verify step.tool == action.tool. (4) Does not check `plan.expiry_unix`. (5) Approval hook ignores `requires_mfa` / rule `display`. (6) `known_tools=None` disables explicit unknown-tool gate |
| 6 | Stage-0 rules | **PRESENT BUT WEAK** | `scan_stage0` / `RulesDetector` (`detectors/rules.py`): NFKC, invisible/control, base64 blob, size limit; `tests/test_stage0_rules.py` | Plan: “basic encoding discovery.” **Only base64** implemented. Live probe: `encoded_rot13_hint.txt` / `encoded_url_escape.txt` → `risk_score=0.0`, no findings; hex fixture mis-attributed as `base64_blob`. No markup/MIME strip (Kirill Stage0 depth) |
| 7 | Detector cascade | **PRESENT & COMPLETE** | `DetectorCascade` Stage0→1→optional Stage2 (`detectors/cascade.py`); `NoOpContextualDetector` returns `inconclusive` (`base.py:90–109`); cascade does not import/call policy/broker (docstring contract `cascade.py:4–5`); `tests/test_cascade.py` | Fail-closed for privileged sinks is **advisory helper only** (`privileged_sink_fail_closed`, `cascade.py:44–57`) — integration is broker’s job and is missing (see step 5 / done-predicate) |
| 8 | PIGuard adapter | **PRESENT & COMPLETE** | `PIGuardDetector.try_load`, `RulesOnlyDetector`, `FakeStage1Detector`, `select_stage1` (`detectors/piguard.py`); optional `[ml]` in `pyproject.toml`; Prompt Guard 2 gated skip (`prompt_guard2.py` + DECISIONS); StackOne optional (`stackone.py` + DECISIONS ADOPT optional) | Default offline path is rules-only with `fail_closed_privileged=True` metadata — flag unused by broker |
| 9 | Quarantine + typed extract | **PRESENT & COMPLETE** | `extract` closed schema via jsonschema, `additionalProperties` forced false, instruction-like free text reject (`quarantine.py`); `tests/test_quarantine.py` | — |
| 10 | Datamarking | **PRESENT & COMPLETE** | `mark` / `unwrap` / `generate_marker` (`datamark.py`); per-call random marker; `tests/test_datamark.py` | — |
| 11 | Ingestion pipeline | **PRESENT BUT WEAK** | `ingest` wires label → cascade → quarantine (`ingest.py`); e2e fixtures in `tests/test_ingest.py` | `default_ingest_cascade()` uses `FakeStage1Detector` (`ingest.py:52–54`) — keyword-elevating CI double, **not** production `RulesOnly`/`select_stage1` fail-closed path. Cascade risk not automatically attached to broker decisions |
| 12 | Moltbook reader | **PRESENT & COMPLETE** | `fetch_posts` / `read_posts` / `MOLTBOOK_SUMMARY_SCHEMA` (`moltbook.py`); untrusted label; no auth; mocked unit tests + optional live smoke env `CONTAINMENT_LIVE_MOLTBOOK` (`tests/test_moltbook.py`) | — |
| 13 | CLI eval | **PRESENT BUT WEAK** | `containment.cli eval` + `eval_runner.run_eval` prints ASR/FPR/utility; control `--no-policy` raises ASR (`cli.py`, `eval_runner.py`; PROGRESS_LOG Step 13–14 metrics) | ASR with policy ON is **dominated by a static untrusted→`email.send` deny simulation** (`eval_runner.py:116–147,186–192`): live probe showed `privileged_denied=True` for **all 38** attacks (12 not even `high_risk`). Metrics therefore overstate detector efficacy; control experiment still valid |
| 14 | Fixture corpus | **PRESENT & COMPLETE** | 38 attack + 34 benign under `fixtures/`; coverage categories in PROGRESS_LOG Step 14; `tests/test_fixtures_corpus.py` | — |
| 15 | Docs + SKILL | **PRESENT & COMPLETE** | `README.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `docs/AGENT_INSTALL.md`, `SKILL.md`; honest non-proof claim; rg-clean per PROGRESS_LOG Step 15 | — |
| 16 | Release gate script | **PRESENT & COMPLETE** | `scripts/release_gate.sh`: venv, `pip install -e ".[dev]"`, ruff, pytest, eval, placeholder scan; exit 0 recorded in PROGRESS_LOG Step 16/18 | Gate `rg` pattern omits `pass  #` that done-predicate #5 includes (script L24 vs plan L21) — minor |
| 17 | Deep-research spot-checks | **PRESENT & COMPLETE** | `DECISIONS.md` 2026-10-07 entries: PIGuard ADOPT, StackOne ADOPT optional, Microsoft AGT SKIP, Invariant SKIP — URLs + fetch dates; adapters wired only for adopt path | — |
| 18 | Final prove-it | **PRESENT & COMPLETE** | Version `1.0.0` (`__init__.py:15`, `pyproject.toml`); release gate OK; measured eval in PROGRESS_LOG Step 18; known limits listed | Classifier metadata mis-nested (step 1) does not affect version claim |

### Step tally

| Status | Count |
| --- | --- |
| PRESENT & COMPLETE | 13 |
| PRESENT BUT WEAK | 5 |
| MISSING | 0 |
| INTENTIONALLY OUT | 0 (as whole steps) |

---

## B. In-scope bullets (DEVELOPMENT_PLAN § Scope v1.0)

| In-scope item | Status | Evidence / gap |
| --- | --- | --- |
| Framework-neutral Python library `containment` | **PRESENT & COMPLETE** | Package name `containment`, `src/` layout, no framework lock-in |
| Core types: `SecurityLabel`, `IntentEnvelope`, `Plan`, `ProposedAction`, `PolicyDecision`, `TraceEvent` | **PRESENT & COMPLETE** | Exported from `__init__.py` |
| Default-deny YAML policy (allow / deny / require_human) | **PRESENT BUT WEAK** | Works; limits/display/MFA flag gaps (see step 3) |
| Tool broker `secure_execute` with schema validation, taint check, one-use capability, audit | **PRESENT BUT WEAK** | Taint + capability + audit yes; schema validation minimal; fail-closed detector path not integrated |
| Ingestion: label → normalize → Stage0 → Stage1 → quarantine → provenance | **PRESENT BUT WEAK** | Present; default Stage1 is Fake, not RulesOnly/PIGuard selection |
| Datamarking / spotlighting helpers | **PRESENT & COMPLETE** | `datamark.py` |
| Detector adapters: PIGuard, optional PG2, optional StackOne; null/fail-closed CI stub | **PRESENT & COMPLETE** | `piguard.py`, `prompt_guard2.py`, `stackone.py`, `RulesOnlyDetector` / Fake |
| Quarantined reader API for Moltbook (no tools, fixed schema) | **PRESENT & COMPLETE** | `moltbook.py` |
| Eval harness + committed fixtures | **PRESENT BUT WEAK** | Present; ASR attribution weak (see step 13) |
| Agent skill / install docs | **PRESENT & COMPLETE** | `SKILL.md`, `docs/AGENT_INSTALL.md` |
| Progress log + decision trail | **PRESENT & COMPLETE** | `PROGRESS_LOG.md`, `DECISIONS.md` |

### Out of v1.0 (confirmed INTENTIONALLY OUT)

| Item | Cite |
| --- | --- |
| Full Microsoft Agent Framework / FIDES | DEVELOPMENT_PLAN Out of v1.0; DECISIONS SKIP Microsoft AGT |
| Full CaMeL research runtime port | DEVELOPMENT_PLAN Out of v1.0 |
| Hosted Lakera / Azure Prompt Shields | DEVELOPMENT_PLAN Out of v1.0 |
| Live AgentDojo CI | DEVELOPMENT_PLAN Out of v1.0 |
| TypeScript SDK | DEVELOPMENT_PLAN Out of v1.0 |
| Meta gated weights inside package | DEVELOPMENT_PLAN non-goals; DECISIONS skip PG2 by default |
| Adaptive-attack immunity / OS sandbox replacement | DEVELOPMENT_PLAN non-goals; THREAT_MODEL residual risk |
| Invariant Guardrails as Stage-1 | DECISIONS SKIP |
| Stage-2 contextual ML (beyond no-op hook) | Plan step 7 defers; `NoOpContextualDetector` is intentional |
| Stage-4 postcondition checks (Kirill cascade) | Not in DEVELOPMENT_PLAN v1 steps |

---

## C. Done-predicate items

| # | Predicate | Status | Evidence / gap |
| --- | --- | --- | --- |
| 1 | `pip install -e ".[dev]"` on Python 3.12+ | **PRESENT & COMPLETE** | PROGRESS_LOG; `requires-python = ">=3.12"`; box uses 3.13 venv |
| 2a | Unknown tools denied by default | **PRESENT & COMPLETE** | `broker.py:99–106`; `tests/test_broker.py::test_unknown_tool_denied` (when `known_tools` set). Default policy also denies unmatched tools |
| 2b | Untrusted data cannot reach privileged sink without policy allow + approval | **PRESENT BUT WEAK** | Tainted egress denied when labels present (`test_tainted_egress_denied`). **Gap:** empty `input_labels` bypasses `no-tainted-egress` for `email.send` → `require_human` only |
| 2c | Detector failure / timeout fails closed for privileged tools | **PRESENT BUT WEAK** → effectively **integration MISSING** | Helper + Stage1 error→`label=error` + unit tests (`test_cascade.py`, `test_piguard.py`). **No broker wiring, no timeout wrapper, no contract test that `ToolBroker` denies on detector error/timeout** |
| 2d | Quarantined extract returns only schema-allowed keys | **PRESENT & COMPLETE** | `quarantine.py` + tests |
| 3 | CLI eval prints measured ASR/FPR/utility (not placeholders) | **PRESENT BUT WEAK** | Numbers are real floats from fixtures, but ASR methodology is policy-static (see §A.13) |
| 4 | SKILL.md + AGENT_INSTALL.md with zero TODO/TBD markers | **PRESENT & COMPLETE** | Files present; PROGRESS_LOG rg-clean |
| 5 | `rg` placeholder scan clean on src/tests/docs | **PRESENT & COMPLETE** | Release gate + PROGRESS_LOG; note gate pattern slightly narrower than plan (`pass  #`) |
| 6 | README threat model + refuses “injection-proof” | **PRESENT & COMPLETE** | `README.md:6–9`, threat table |

---

## D. Architectural vision alignment

Sources: `KIRILL_RESEARCH.md` (Best build-it-yourself architecture), `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, honest product claim in plan.

| Vision claim | Alignment | Evidence / gap |
| --- | --- | --- |
| Consequence containment over classifiers-only | **ALIGNED (primary)** | Policy + broker + labels + quarantine are central; detectors advisory (`ARCHITECTURE.md:49–51`, `cascade.py` docstring) |
| Default-deny broker | **ALIGNED** | `policies/default_deny.yaml` `default: deny`; `PolicyEngine` unmatched → `default_deny` |
| Labels / provenance | **ALIGNED** | `SecurityLabel` integrity/confidentiality/source/task_id/transformations; ingest sets them |
| Quarantine typed extract | **ALIGNED** | Closed JSON Schema extract; Moltbook fixed `{title,topic,summary}` |
| Stage-0 + Stage-1 cascade | **ALIGNED** | Implemented; Stage-2 no-op optional |
| Datamarking | **ALIGNED** | Helpers present (optional spotlighting) |
| Moltbook read-only | **ALIGNED** | No auth, no tools in reader, untrusted labels |
| Offline eval ASR/FPR/utility | **PARTIAL** | Harness exists; ASR attribution weak vs “measured detector+policy” story |
| Fail-closed privileged | **PARTIAL / WEAK** | Documented + helper; **not enforced in reference monitor** |
| Cascade never authorizes | **ALIGNED** | No policy/broker calls from cascade module |
| Immutable plan before untrusted content / plan binding | **PARTIAL** | `Plan` types exist; broker does not verify `plan_step`↔tool or plan expiry |
| Exact human approval + MFA for high-risk | **PARTIAL** | Approval hook exists (fail-closed default); MFA flag not enforced; `display` fields unused |
| Resolve/canonicalize / SSRF / sandbox egress | **INTENTIONALLY OUT / residual** | THREAT_MODEL + plan non-goals: does not replace OS/network controls; not in v1 step list |
| Signed IntentEnvelope | **INTENTIONALLY DEFERRED** | `plan.py` “unsigned in v0.1” |

---

## E. Counts summary

| Bucket | Count |
| --- | --- |
| Plan steps WEAK | **5** (steps 3, 5, 6, 11, 13; step 1 kept COMPLETE despite minor pyproject classifiers nesting) |
| Plan steps MISSING | **0** |
| In-scope WEAK | **4** |
| In-scope MISSING | **0** |
| Done-predicate WEAK | **3** (2b, 2c, 3) |
| Done-predicate MISSING (integration) | **1** (2c broker integration — counted under WEAK with MISSING integration note) |
| Vision PARTIAL/WEAK | **4** (eval, fail-closed, plan binding, MFA/display) |

**Combined WEAK items (unique themes):** **10**  
**Combined MISSING (should-have-been-v1 integrations):** **1** primary — detector fail-closed not wired into `ToolBroker` (plus empty-label / plan-binding integrity holes classified WEAK but production-critical).

---

## F. Harden candidates (REAL gaps vs gold-plating)

Ranked by **production integrity** (authority/taint/fail-closed), not feature expansion beyond plan.

| Rank | Severity | Gap | Why real (not gold) | Suggested harden locus |
| --- | --- | --- | --- | --- |
| 1 | **Critical** | Detector fail-closed not enforced by broker | Done-predicate §2 and plan steps 5/7/8 claim privileged sinks fail closed on detector failure/uncertainty; only advisory `privileged_sink_fail_closed` + `fail_closed_privileged` flag exist | `broker.py` `secure_execute`: accept cascade/`Stage1Selection` (or risk signals on action); deny privileged tools when flag/helper says so; add contract test |
| 2 | **Critical** | Empty / omitted `input_labels` bypasses taint deny on `email.send` | Confused-deputy: model can omit labels and reach `require_human`/`allow` paths; undermines “untrusted cannot acquire authority” | Policy predicate or broker pre-check: privileged sinks require non-empty labels; missing → deny |
| 3 | **High** | No `plan_step` ↔ `Plan` binding | Kirill + threat model: model proposals must match immutable plan; today wrong `plan_step` still evaluates | `broker.py`: `plan.step_by_id(action.plan_step)` and `step.tool == action.tool` else deny |
| 4 | **High** | `requires_mfa` not enforced in approval path | Policy ships `require_human_and_mfa`; broker treats MFA like ordinary approval | Approval hook contract: if `decision.requires_mfa`, require MFA-verified approval stub; default fail closed |
| 5 | **High** | Broker “schema validation” is structural only | Plan step 5 / Kirill: reject unknown fields via schema; current validator accepts any mapping | Per-tool JSON Schema registry; default deny extra properties |
| 6 | **High** | Policy `limits` / `display` dead fields | YAML promises redirects/max_bytes/network and approval display fields; silently ignored → false sense of control | Enforce limits in broker/adapters or strip from shipped policy until enforced; pass `display` into approval |
| 7 | **Medium** | No detector timeout | Done-predicate names timeout; Stage1 only has exception→error, no time bound | Wrap Stage1 `scan` with timeout → `label=error` → fail-closed privileged |
| 8 | **Medium** | Stage-0 encoding discovery incomplete | Plan step 6; fixtures include hex/url/rot13 that score 0 | Extend `rules.py` discovery (hex runs, percent-encoding, rot13 markers) without claiming decode-execute |
| 9 | **Medium** | Eval ASR not path-faithful | Done-predicate wants measured numbers; ASR≈0 because every attack uses the same static tainted-email deny | Drive `ToolBroker.secure_execute` (or fixture-declared proposed actions) per case; report detector-block vs policy-block separately |
| 10 | **Medium** | Production ingest default uses `FakeStage1Detector` | Fake elevates keywords for CI; production agents calling `ingest()` without override get test double, not RulesOnly/PIGuard selection | `default_ingest_cascade` → `select_stage1(prefer="rules_only")` or PIGuard when configured |

### Explicitly NOT harden candidates (gold-plating / out of v1)

- Porting CaMeL / FIDES / Microsoft AGT / Invariant / AgentDojo live CI  
- Shipping or auto-downloading Meta Prompt Guard 2 weights  
- Full SSRF DNS rebinding / OS sandbox / network egress proxy (documented residual)  
- Cryptographic signing of `IntentEnvelope` (deferred in code)  
- Stage-2 contextual LLM / Stage-4 postconditions  
- TypeScript SDK  
- Claiming adaptive-attack immunity  

---

## G. Bottom line

The v1 skeleton matches the approved plan’s module list and most verify steps: labels, default-deny policy, broker, cascade-as-advisor, quarantine, datamarking, Moltbook read-only, offline eval, docs/skill, release gate, and due-diligence decisions are real.

The integrity holes that matter for production are **integration and fail-closed authority**, not missing feature brands: wire detector uncertainty into the broker, refuse unlabeled privileged calls, bind actions to the immutable plan, and stop shipping unenforced policy fields / MFA flags. Eval numbers are reproducible but currently flatter the system via a static taint simulation.

**Matrix path:** `/workspace/prompt-injection-defense/AUDIT_PLAN_VS_CODE.md`
