# Bar E Audit + Integrity Harden Plan

**Date:** 2026-10-08 JST  
**Mode:** poteto-mode / figure-it-out / local swarm  
**Inputs:** K ask (confirm 1.6.0 Bar E matches EVAL_CARD_PLAN + development vision/clarifications from PROGRESS_LOG; full-scale code audit; fix to production-complete); `EVAL_CARD_PLAN.md`; `docs/EVAL_CARD.md`; `PROGRESS_LOG.md`; tree at `d025cf2` / containment **1.6.0**  
**Host:** box only (no Cloud Agents; standing rule); append-only `PROGRESS_LOG.md`  
**Version:** stay **1.6.0** if audit finds docs-only / no functional gaps; bump **1.6.1** only if code/behavior fixes land

## Done predicate

1. Written matrix: each EVAL_CARD_PLAN done-predicate item 1–5 → PASS / GAP with file+test evidence; vision/clarifications from PROGRESS_LOG Bar E steps mapped the same way (ON+OFF card, reuse `run_eval`, fail-closed gates, card out of release_gate by design, no SOTA claims).
2. Local swarm slices aggregated; every ISSUES item either fixed or explicitly accepted as in-scope residual with threat-model / plan language (no silent ignore).
3. Codebase integrity for Bar E surfaces: no ship-path TODO/FIXME/NotImplemented/placeholder in `eval_card.py` + tests + CLI; metrics never recomputed in card (slices from `EvalMetrics`); `on_asr_ok` / `control_ok` fail-closed; JSON↔Markdown↔dict roundtrip coherent; exports/docs claim scrub.
4. `scripts/release_gate.sh` exit 0; eval ASR not worse than 1.6.0 baseline (0.0000); pytest green; `containment-eval-card` smoke gate=PASS.
5. If fixes: commit + push `origin/main`; PROGRESS_LOG step evidence for each law step.

## Explicit non-goals

- Expanding beyond Bar E (no release ritual, bot playbook, AgentDojo live, hosted shields, corpus expansion unless a bug requires it)
- Rewriting Bar A–D surfaces that already pass unless audit proves a break caused by E
- Claiming “never needs more development” in absolute terms; claim is: Bar E law + audit findings closed
- Putting the eval card into `release_gate` (documented intentional residual unless audit proves the plan’s optional-or-document choice was never documented)
- Cloud Agents / remote swarm (standing box-only rule → local N=4 executors)

## Architecture vision check (from plan + logs)

Must confirm the shipped shape still matches:

- **Bar E:** citable offline scorecard — policy ON + OFF control via existing `eval_runner.run_eval`; typed `EvalCard` / `PolicySliceMetrics`; Markdown + JSON under caller out-dir; version + git SHA + UTC/JST; fail-closed CLI on `on_asr_ok` and `control_ok`; card stays out of CI gate (single ON eval in gate); no SOTA / leaderboard / AgentDojo claims.
- **Laziness:** no forked metrics path; flat `containment.eval_card` module (not a nested package) is acceptable if plan’s “or equivalent” is met.

## Execution steps (law)

1. **Baseline** — gate + pytest + eval + card smoke + HEAD SHA; no code changes. Record ASR/FPR/utility/test counts.
2. **Swarm coverage** — local N=4 executors: (A) EVAL_CARD_PLAN done-predicate 1–5 vs code + CLI, (B) vision/PROGRESS_LOG clarifications + architecture match (reuse run_eval, fail-closed, gate-out, timestamps, exports), (C) eval_card + eval_runner integrity (metric reuse, roundtrip, thresholds, bypass/placeholder/edge cases), (D) docs/exports/DECISIONS/SKILL/README/AGENT_INSTALL/pyproject claim drift + placeholder scan. Write slice reports + `swarm-reports/bar-e-audit/SWARM_AGGREGATE.md`.
3. **Plan-match report** — commit-ready `AUDIT_PLAN_VS_BAR_E.md` mapping law + vision clarifications to evidence; list GAP list that steps 4–6 must clear.
4. **Fix GAPs cluster E** — `eval_card.py` / CLI / harness / threshold helpers / tests from aggregate (only evidenced ISSUES).
5. **Fix GAPs cluster X** — docs/exports/examples/DECISIONS/SKILL/AGENT_INSTALL/pyproject coherence + claim scrub from aggregate.
6. **Integrity + regression** — add/adjust tests that lock audit findings; ruff/pytest/eval/card smoke; placeholder scan on Bar E surfaces.
7. **Final prove-it** — release_gate; version bump 1.6.1 iff behavior changed else keep 1.6.0; push if commits; hand back matrix + residuals.

After each step: verify, append PROGRESS_LOG, do not start next until VERIFIED.  
Do not alter this law on the fly unless execution would be poor; log any amendment in PROGRESS_LOG first.
