# Slice B — Vision / PROGRESS_LOG clarifications + architecture match

**Base:** `d025cf2` / **1.6.0**  
**Verdict:** PASS (one soft residual on suite label)

## Vision checklist

| Vision item | Evidence | Verdict |
| --- | --- | --- |
| Citable offline scorecard ON + OFF | `generate_card` calls `run_eval` twice; CLI smoke gate=PASS | PASS |
| Reuse `eval_runner.run_eval` (no metric fork) | `eval_card.py:310–319` `_slice_from_metrics` only; docstring “no metrics recomputation” | PASS |
| Fail-closed `on_asr_ok` + `control_ok` | `main` returns 1 when either false; `test_cli_fails_closed_when_thresholds_fail` | PASS |
| Card out of `release_gate` intentional | `scripts/release_gate.sh:46–51` comments; `docs/EVAL_CARD.md` “What it is not”; DECISIONS ADOPT | PASS |
| Timestamps UTC + JST | `generated_at_utc` / `generated_at_jst`; naive datetime coerced to UTC | PASS |
| Version + git SHA | `_package_version()` + `resolve_git_sha` → unknown on failure | PASS |
| Exports | `__init__.py` exports EvalCard, PolicySliceMetrics, build_card, generate_card, write_card_artifacts | PASS |
| No SOTA / leaderboard / AgentDojo claims | Markdown scope + JSON `scope` + docs | PASS |
| Flat module acceptable | PROGRESS_LOG step 2; plan “or equivalent” | PASS |

## PROGRESS_LOG clarifications mapped

- Circular-import fix (`_package_version` via importlib.metadata) still present — PASS.
- Artifacts gitignored (`artifacts/`) — PASS residual by design.
- Threshold constants `ON_ASR_REQUIRED` / `ASR_ROUND_DIGITS` — PASS; control rounding coherence → E1 in slice C.

## Soft residual

- **B-S1** — `--suite` does not select a different corpus; label only. Documented enough in CLI help (“Suite name recorded on the card”). Accept unless product wants multi-suite later (out of Bar E audit non-goals).

## ISSUES to clear

None unique to vision (E1 owned by slice C).
