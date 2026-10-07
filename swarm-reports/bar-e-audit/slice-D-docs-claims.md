# Slice D — docs / exports / claims drift

**Base:** `d025cf2` / **1.6.0**  
**Verdict:** ISSUES (docs LOW)

## Claim scrub (SOTA / leaderboard / AgentDojo)

| Surface | Status |
| --- | --- |
| `docs/EVAL_CARD.md` | Explicit non-claims + card out of gate | PASS |
| README eval card blurb | “not a public leaderboard or SOTA claim” | PASS |
| SKILL.md Eval honesty | no certification/SOTA/zero residual | PASS |
| AGENT_INSTALL §11 | fixture-only; not leaderboard | PASS |
| DECISIONS.md Bar E ADOPT | non-goals include SOTA/FedRAMP | PASS |
| Card Markdown/JSON `scope` | Not AgentDojo / shields / leaderboard | PASS |
| `release_gate.sh` comments | document card out + thresholds | PASS |

## ISSUE X1 (LOW) — ARCHITECTURE Modules omits `eval_card`

`docs/ARCHITECTURE.md` Modules table lists `cli / eval_runner` but not `eval_card` (Bar E scorecard). Same class of drift fixed for adapters/reference_host in Bar C+D audit.

**Fix:** Add row for `eval_card` (ON+OFF citable card; fail-closed CLI; reuses `run_eval`).

## ISSUE X2 (LOW) — README package layout omits eval_card module name

Layout bullet lists adapters / reference_host / CLI but not `eval_card`. Docs/ already says “eval card”. Align one word for discoverability.

## Soft

- Control_ok docs omit “after 4-decimal rounding” while on_asr includes it — fold into E1 docs scrub (not a separate X if E1 lands).
- Nested `containment.evals.card` never claimed in shipped docs (flat module named everywhere) — PASS.
