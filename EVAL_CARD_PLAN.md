# Eval Card Plan — Bar E (→ 1.6.0)

**Date:** 2026-10-08 JST  
**Mode:** poteto-mode / plan-as-law / local executors  
**Inputs:** K approval (Bar E as framed); containment **1.5.1**; existing `eval_runner` + `containment eval`  
**Bar:** E — Eval card: citable Markdown+JSON scorecard from offline fixtures (ON + OFF control)  
**Host:** box only; append-only `PROGRESS_LOG.md`  
**Version:** bump to **1.6.0** at final prove-it only

## Done predicate

1. Every step VERIFIED with PROGRESS_LOG evidence.
2. Package ships `containment.evals.card` (or equivalent) + CLI `containment-eval-card`: runs fixture suite policy ON and OFF; writes Markdown + JSON under a caller-chosen out dir (default `artifacts/eval-card/`); records version, git SHA (or `unknown`), corpus counts, ASR/FPR/utility, detector_block_rate, policy_block_rate, OFF ASR control, UTC+JST timestamp.
3. Gate helpers: ON ASR must be 0.0000 for prove-it; OFF ASR must be strictly worse than ON; hermetic unit tests cover schema + control inequality without network.
4. `docs/EVAL_CARD.md` + README / AGENT_INSTALL / DECISIONS / SKILL / exports updated; no placeholders; no SOTA/external-leaderboard claims.
5. `release_gate.sh` exit 0; version **1.6.0** on `origin/main`. Optionally wire card smoke into gate or keep gate on existing eval (document choice).

## Explicit non-goals

- Live AgentDojo / hosted shields / LLM round-trips in CI
- Release ritual / bot playbook (later)
- Expanding fixture corpus unless a bug requires it
- Claiming SOTA or FedRAMP

## Execution steps (law)

1. **Baseline** — gate + pytest + eval + HEAD SHA; no code.
2. **Card schema + writer** — typed card fields; JSON + Markdown renderers; tests.
3. **Harness** — ON/OFF runs via existing eval_runner; CLI `containment-eval-card`; pyproject script.
4. **Gate thresholds** — helpers/tests for ASR==0 ON and OFF worse; document in EVAL_CARD.md.
5. **Docs + exports** — EVAL_CARD.md; README/DECISIONS/SKILL/AGENT_INSTALL/__init__.
6. **Final prove-it** — version 1.6.0; release_gate; generate one committed or gitignored sample card per docs choice; push origin/main.

After each step: verify, append PROGRESS_LOG, do not start next until VERIFIED.
