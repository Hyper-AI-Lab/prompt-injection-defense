# Slice A — EVAL_CARD_PLAN done-predicate vs shipped (Bar E audit)

**Base:** `d025cf2` / containment **1.6.0**  
**Executor:** local (box)  
**Verdict:** ISSUES (predicate 1–5 mostly PASS; one integrity GAP deferred to slice C as E1)

## Predicate matrix

| # | Plan requirement | Evidence | Verdict |
| --- | --- | --- | --- |
| 1 | Every Bar E ship step VERIFIED with PROGRESS_LOG | PROGRESS_LOG Bar E steps 1–6 + post-push | PASS |
| 2 | Package ships `containment.evals.card` **or equivalent** + CLI `containment-eval-card`; ON+OFF; MD+JSON under out-dir; version, git SHA, corpus, ASR/FPR/utility, detector/policy block rates, OFF ASR, UTC+JST | Flat `src/containment/eval_card.py` (PROGRESS_LOG step 2: intentional flat module); pyproject `containment-eval-card = containment.eval_card:main`; smoke wrote `/tmp/bar-e-audit-card/eval-card.{json,md}` with all fields | PASS (equivalent) |
| 3 | Gate helpers: ON ASR 0.0000 prove-it; OFF strictly worse; hermetic tests | `on_asr_is_ok` / `control_is_ok`; `tests/test_eval_card.py` 11 passed | PASS with note → **E1** (control compares raw floats; display rounds — see slice C) |
| 4 | `docs/EVAL_CARD.md` + README / AGENT_INSTALL / DECISIONS / SKILL / exports; no placeholders; no SOTA claims | Files present; explicit “not SOTA / leaderboard / AgentDojo”; placeholder scan clean on eval_card surfaces | PASS (ARCHITECTURE module row → slice D X1) |
| 5 | `release_gate.sh` exit 0; version 1.6.0 on origin/main; optionally wire card or document | Gate exit 0; version 1.6.0; gate comments document card **out** of CI | PASS |

## Soft notes (not ISSUES)

- Nested package `containment.evals.card` never created — plan’s “or equivalent” + laziness; flat module is the shipped shape.
- `--suite` is a card label only (always runs fixture corpus via `run_eval`) — acceptable until additional suites exist.

## ISSUES raised for aggregate

- **A→E1** — `control_is_ok` / displayed ASR coherence (detailed in slice C).
