# Code integrity audit — `containment` (`/workspace/prompt-injection-defense`)

**Date:** 2026-10-07 (Asia/Tokyo)  
**Scope:** Read-only review of `src/containment/**/*.py`, tests, docs, policy, fixtures. No code changes. No Cursor Cloud Agents.  
**Method:** Full source read; tests vs contracts; `.venv/bin/pytest -q`; placeholder `rg`; spot-checks (broker/taint, ingest cascade, quarantine, capability one-use, eval metrics, moltbook read-only); `__init__.py` export review.

**Test run:** 114 passed, 1 skipped (`test_live_moltbook_smoke`), exit 0.  
**Placeholder scan** (`TODO|FIXME|NotImplemented|placeholder|TBD` on `src tests docs README.md SKILL.md`): clean (no hits).  
**Ruff:** all checks passed.  
**release_gate today:** would still **PASS** (venv present; ruff/pytest/eval/placeholder all green).

---

## Summary counts

| Severity | Count |
| --- | ---: |
| CRITICAL | 0 |
| HIGH | 5 |
| MEDIUM | 6 |
| LOW | 3 |
| INFO | 4 |

---

## HIGH

### H1 — Empty `input_labels` bypasses taint deny on privileged email

**Evidence:** `src/containment/actions.py` `ProposedAction.any_untrusted` (lines 54–55) is false on `()`; `src/containment/policy.py` `input.any_integrity` / `no-tainted-egress` (lines 202–207, `policies/default_deny.yaml` 20–28); `args.body_confidentiality_lte` returns True when labels empty (policy.py 261–263). Reproduced: empty-label `email.send` to an approved recipient → `require_human` / `approved-email`, and with a no-op approval hook `ToolBroker.secure_execute` **mints a capability**.

**Why it matters:** Threat model / SKILL require attaching ingest labels so untrusted data cannot egress. Omitting labels (confused deputy / bug) skips `no-tainted-egress` and reaches the human-approval allow path as if nothing were tainted.

**Fix direction:** Fail closed when privileged sinks in `PRIVILEGED_SINKS` (or `tool_in` of no-tainted-egress) see `not action.input_labels`. Add a regression test for empty labels → deny.

---

### H2 — `privileged_sink_fail_closed` / `fail_closed_privileged` never wired into the broker

**Evidence:** Helper and docs in `src/containment/detectors/cascade.py` 7–12, 44–57; `Stage1Selection.fail_closed_privileged` in `piguard.py` 29, 195–217; DECISIONS.md (“broker/cascade integration blocks privileged sinks”); README threat table (“Detector failure / missing weights failing closed”); THREAT_MODEL.md control 6. `ToolBroker.secure_execute` (`broker.py` 90–157) takes no cascade / selection flag and never calls the helper. Tests only assert the helper in isolation (`test_cascade.py::test_privileged_sink_fail_closed_advisory`, `test_piguard.py`).

**Why it matters:** Stated fail-closed path for detector error / rules-only Stage-1 is advisory-only. Policy taint still helps when labels are correct, but detector uncertainty does not constrain the reference monitor as documented.

**Fix direction:** Thread optional `CascadeResult` (or `fail_closed_privileged`) into `secure_execute`; if `privileged_sink_fail_closed(tool, cascade)` and effect would otherwise allow/require_human, deny + audit. One broker integration test.

---

### H3 — Default ingest/Moltbook cascade uses CI `FakeStage1Detector`, not RulesOnly/`select_stage1`

**Evidence:** `ingest.default_ingest_cascade` (`ingest.py` 52–54, used at 93) → `FakeStage1Detector()`; `moltbook.ingest_post` defaults to that cascade (`moltbook.py` 160); README quickstart calls `ingest(...)` with no cascade. DECISIONS.md says default offline path is **RulesOnly** via `select_stage1` with `fail_closed_privileged=True`. Fake is documented as “offline CI” (`piguard.py` 53–54) and only elevates a small keyword set (`ignore previous|ignore all|system prompt`).

**Why it matters:** Production-looking API defaults to a test double. Attacks without those keywords (12/38 fixture attacks are not `high_risk` under Fake+eval heuristics) look benign at Stage-1 while Stage-0 may also be quiet.

**Fix direction:** Default to `DetectorCascade(stage1=select_stage1(prefer="rules_only").detector)` (or Passthrough/RulesOnly); keep Fake only behind an explicit test/eval helper. Document that real ML still needs `select_stage1(prefer="piguard", allow_download=...)`.

---

### H4 — Policy YAML `limits` / `display` are parsed then never enforced (scaffold)

**Evidence:** `PolicyRule.limits` / `display` stored in `policy.py` 32–33, 139–157; `default_deny.yaml` `read-public-web.limits` (redirects: 0, max_bytes, network) and `approved-email.display`. No reads in `broker.py` or `_predicate`. Schema validation is only the minimal `default_schema_validator` (tool non-empty + args mapping).

**Why it matters:** Operators reading the shipped policy believe redirects/size/network bounds and approval display fields are active. They are silent no-ops — classic “claims to work” scaffold relative to the YAML contract.

**Fix direction:** Either enforce limits in the broker (or a post-allow validator) and surface `display` to the approval hook, or strip unused keys from the shipped YAML until implemented. Prefer enforce for `max_bytes` / scheme already partially covered.

---

### H5 — Offline eval ASR with policy ON is almost entirely a constant synthetic taint deny

**Evidence:** `eval_runner._policy_denies_tainted_email` (`eval_runner.py` 116–147) always evaluates the same untrusted `email.send` action; with `default_deny.yaml` it always returns True. `evaluate_case` then sets `blocked = privileged_denied or (attack and high_risk)` (189–190). Measured: ON ASR=0.0, all 38 attacks `privileged_denied=True`; only 26 `high_risk`; 12 attacks not high_risk would succeed if taint deny were false. Control OFF forces `blocked=False` → ASR=1.0 (`test_fixtures_corpus.py::test_offline_eval_runs_and_control`).

**Why it matters:** Published ASR “with policy” does not measure per-fixture detector quality; it mostly measures “does default policy deny one fixed tainted email?” Threat-model eval text is honest about empiricism, but metric formulas over-claim defense coverage.

**Fix direction:** Derive privileged outcome from labels/cascade of **that case** (or require a proposed sink tied to fixture meta). Report separate detector-block rate vs policy-block rate. Keep control ablation.

---

## MEDIUM

### M1 — Broker never checks `plan_step` against `Plan`

**Evidence:** `ProposedAction.plan_step` required non-empty (`actions.py` 45–46) but `ToolBroker` / `PolicyEngine.evaluate` never call `plan.step_by_id` or require `plan.steps[i].tool == action.tool`. Reproduced: `plan_step="not_in_plan"` still matches `approved-email`.

**Why it matters:** Immutable plan steps are a stated control; step id is audit-only today, so models can propose tools under bogus step ids.

**Fix direction:** In `secure_execute` (or policy), `step = plan.step_by_id(action.plan_step)` and require `step.tool == action.tool`; deny + audit on mismatch.

---

### M2 — `requires_mfa` is recorded but not enforced by the broker

**Evidence:** `require_human_and_mfa` → `requires_mfa=True` (`policy.py` 21, 101–106); broker only calls `approval` for `require_human` (`broker.py` 140–142) with no MFA gate. Default approval fails closed for all human-required paths; a custom approval that ignores `decision.requires_mfa` still mints.

**Why it matters:** Wallet transfer rule advertises MFA; enforcement is entirely caller-dependent.

**Fix direction:** If `decision.requires_mfa`, require an explicit MFA-verified approval hook return/flag before mint; fail closed otherwise.

---

### M3 — `args.body_confidentiality_lte` ignores `arguments` and uses label confidentiality only

**Evidence:** Predicate name and YAML (`default_deny.yaml` 36) suggest an argument field; implementation uses `action.input_labels` max confidentiality (`policy.py` 257–265). Eval sets unused `body_confidentiality` in arguments (`eval_runner.py` 132).

**Why it matters:** API surface incoherence; callers setting args for confidentiality get no effect.

**Fix direction:** Rename predicate to `input.max_confidentiality_lte`, or take the max of labels and an optional args field with documented precedence.

---

### M4 — `Plan.expiry_unix` is never checked

**Evidence:** Field on `Plan` (`plan.py` 69); unused in policy/broker.

**Why it matters:** Expired task plans remain valid for `secure_execute`.

**Fix direction:** Deny when `expiry_unix` is set and `now > expiry_unix` at evaluate/broker time.

---

### M5 — Enabling default Stage-2 makes `privileged_sink_fail_closed` always true for privileged tools

**Evidence:** `NoOpContextualDetector` returns `inconclusive` (`base.py` 90–108); cascade includes it when `run_stage2=True` (`cascade.py` 157–169); `_aggregate_label` prefers inconclusive over benign; helper treats `inconclusive` as fail-closed (`cascade.py` 53–54). Reproduced: benign text + `run_stage2=True` → aggregate `inconclusive` → helper True for `email.send`.

**Why it matters:** Footgun once H2 is fixed (or for any caller of the helper): turning on Stage-2 without a real contextual model blocks all privileged sinks.

**Fix direction:** NoOp should not raise aggregate severity (omit from aggregate, or label `benign` with score 0 and document), or helper should ignore stage2-noop inconclusive.

---

### M6 — Detector `high_risk` misses a large slice of the attack corpus under default Fake path

**Evidence:** Under eval Fake+keyword heuristics, 12/38 attacks are not `high_risk` (e.g. `direct_you_are_now.txt`, `direct_shell.txt`, `direct_http_post.txt`, `encoded_rot13_hint.txt`, …). Fake keywords omit phrases that quarantine’s `_INSTRUCTION_RE` knows (`you are now`, etc.) — and eval sets `reject_instruction_text=False` (`eval_runner.py` 166).

**Why it matters:** With H3/H5, detector-side blocking is weaker than ASR suggests; quarantine defense is disabled in the eval loop.

**Fix direction:** Align Fake/eval keyword set with Stage-0/quarantine patterns for fixtures, or score attacks via RulesOnly + instruction scan; optionally set `reject_instruction_text=True` when measuring quarantine contribution separately.

---

## LOW

### L1 — Top-level `__init__` exports omit common quarantine/detector helpers

**Evidence:** `src/containment/__init__.py` exports ingest/broker/plan/policy/moltbook `read_posts` + schema, but not `ALLOWLIST_SUMMARY_SCHEMA`, `closed_object_schema`, `DetectorCascade`, `select_stage1`, `MoltbookError`, `MoltbookPostSummary`, `fetch_posts`. README reaches some via submodules; quickstart is fine, but public surface is incomplete vs package `__all__` discoverability.

**Fix direction:** Re-export the small closed set used in docs (`closed_object_schema`, `ALLOWLIST_SUMMARY_SCHEMA`, `MoltbookError`) or document submodule-only policy clearly in README.

---

### L2 — Capability MAC binds resources with comma-join (delimiter collision)

**Evidence:** `capability.py` `_mac` joins resources with `","` (lines 98–100).

**Why it matters:** Distinct resource tuples that differ only by comma placement can MAC-collide in theory.

**Fix direction:** Length-prefix or use a non-ambiguous separator / JSON array encoding.

---

### L3 — Audit “append-only” has no integrity sealing

**Evidence:** Threat model lists audit integrity as an asset (`docs/THREAT_MODEL.md`); `AuditLog` is file append + lock (`audit.py`) with no hash chain / signature. Truncation/rewrite by anyone with filesystem write is undetectable.

**Fix direction:** Optional hash-chained events or external WORM; document residual risk explicitly if deferred.

---

## INFO

### I1 — `IntentEnvelope` still “unsigned in v0.1” while package is `1.0.0` / Production/Stable

**Evidence:** `plan.py` 9–10 docstring; `pyproject.toml` version `1.0.0`, classifier Development Status :: 5 - Production/Stable.

**Note:** Not a silent no-op bug; cryptographic intent binding is unfinished relative to versioning claims.

---

### I2 — Quarantine instruction-reject branches are redundant

**Evidence:** `quarantine.py` 190–213: with `reject_instruction_text is None`, both auto_reject and the final `else` path reject instruction-like strings, so free-string vs allowlist distinction collapses except when explicitly `False`.

**Note:** Behavior matches `test_free_string_schema_still_rejects_instruction_phrase`; simplify control flow / docstring.

---

### I3 — Capability consume set is process-local memory

**Evidence:** `CapabilityMinter._consumed` (`capability.py` 33, 76–89). Multi-worker deployments do not share one-use state.

**Note:** Acceptable for single-process reference monitor; document or add shared store if claiming distributed one-use.

---

### I4 — Overengineering / dual Stage-1 “fake” types (Karpathy simplicity)

**Evidence:** `FakeStage1Detector` (piguard), local `FakeStage1` in `test_cascade.py`, `PassthroughStage1`, `RulesOnlyDetector` all mirror Stage-0 with slight differences; ingest defaults to Fake (see H3) while docs push RulesOnly.

**Note:** INFO only — simplify defaults and naming; do not add more adapters until broker wiring (H2) exists.

---

## Spot-check notes (no separate finding if already covered)

| Area | Result |
| --- | --- |
| Broker taint/policy | `no-tainted-egress` works when labels present (`test_broker.py::test_tainted_egress_denied`); empty labels hole = H1; limits = H4 |
| Ingest cascade | Label → cascade → quarantine wired; default Fake = H3; `high_risk` does not block extract success (by design — signals only) |
| Quarantine schema | Closed schema + instruction reject real; root must be object; allowlist tests pass |
| Capability one-use | Second `verify` fails (`test_capability_audit.py`); broker without executor leaves token unconsumed (documented in `test_allow_fetch_mints_capability`) |
| Eval metrics | ASR/FPR/utility formulas as coded; attribution issue = H5 |
| Moltbook read-only | GET-only urllib, no auth headers, untrusted ingest, closed `{title,topic,summary}`; tools not exposed — OK |
| Placeholder / NotImplemented | None on ship surfaces |

---

## release_gate

`scripts/release_gate.sh` runs: venv ensure → `pip install -e .[dev]` → `ruff check` → `pytest` → `python -m containment.cli eval --suite fixtures` → placeholder `rg`.

**Today:** would **PASS** (pytest 114 passed + 1 skip; ruff clean; eval runs; placeholder clean). Findings above are integrity/contract gaps, not gate failures.
