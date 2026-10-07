# Audit: EVAL_CARD_PLAN + vision vs shipped Bar E (1.6.0)

**Date:** 2026-10-08 JST  
**Base SHA:** `d025cf2408d1bcc449c20628fc200e3f6b0c0a39`  
**Law:** `BAR_E_AUDIT_HARDEN_PLAN.md`  
**Swarm:** `swarm-reports/bar-e-audit/SWARM_AGGREGATE.md`

## EVAL_CARD_PLAN done-predicate

| # | Requirement | Result | Evidence |
| --- | --- | --- | --- |
| 1 | Steps VERIFIED in PROGRESS_LOG | **PASS** | Bar E steps 1–6 + post-push |
| 2 | Card module (or equivalent) + CLI; ON+OFF; MD+JSON; version/SHA/corpus/rates/UTC+JST | **PASS** | Flat `containment.eval_card`; `containment-eval-card`; smoke artifacts |
| 3 | Gate helpers ON ASR 0.0000; OFF worse; hermetic tests | **PASS** (E1 cleared) | `control_is_ok` rounds; 12 tests; display coherence locked |
| 4 | Docs + exports; no placeholders; no SOTA claims | **PASS** (X1/X2 cleared) | ARCHITECTURE + README name `eval_card`; claim scrub clean |
| 5 | release_gate OK; 1.6.0 on main; card optional-or-document | **PASS** | Gate exit 0; card documented **out** of gate |

**Counts (post-harden):** PASS **5** · GAP **0** · residuals per aggregate

## Vision / PROGRESS_LOG clarifications

| Clarification | Result | Evidence |
| --- | --- | --- |
| Reuse `run_eval` (no metric fork) | **PASS** | `generate_card` → `run_eval` ×2; `_slice_from_metrics` |
| Fail-closed CLI | **PASS** | `main` exit 1; fail-closed test |
| Card out of release_gate | **PASS** | gate comments + docs + DECISIONS |
| UTC + JST timestamps | **PASS** | `generated_at_*` fields |
| Version + git SHA | **PASS** | `_package_version` / `resolve_git_sha` |
| Flat module (laziness) | **PASS** | no `evals/` package |
| No SOTA / AgentDojo / leaderboard claims | **PASS** | MD scope + all docs |
| Circular-import avoidance | **PASS** | importlib.metadata version helper |

## GAP list — CLEARED (steps 4–6)

1. **E1** — cleared (`round_asr` in `control_is_ok` + tests).
2. **X1** — cleared (ARCHITECTURE row).
3. **X2** — cleared (README layout).

## Residuals accepted (not GAPs)

See `SWARM_AGGREGATE.md`: card out of gate; gitignored artifacts; `card_from_dict` trusts flags; suite label-only; threshold helpers not on package root; prior Bar C+D residuals.

## Post-harden target

After steps 4–6: all matrix rows PASS or residual; release_gate green; card smoke gate=PASS; version **1.6.1** iff E1 code lands (behavior change), else stay 1.6.0.
