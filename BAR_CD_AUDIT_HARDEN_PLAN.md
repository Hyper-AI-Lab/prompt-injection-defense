# Bar C + Bar D Audit + Integrity Harden Plan

**Date:** 2026-10-08 JST  
**Mode:** poteto-mode / figure-it-out / local swarm  
**Inputs:** K ask (confirm 1.5.0 Bar C+D match RUNTIME_ADAPTER_PLAN + REFERENCE_HOST_PLAN + development vision/clarifications; full-scale code audit; fix to production-complete); `RUNTIME_ADAPTER_PLAN.md`; `REFERENCE_HOST_PLAN.md`; `PROGRESS_LOG.md`; tree at `933ead2` / containment **1.5.0**  
**Host:** box only (no Cloud Agents); append-only `PROGRESS_LOG.md`  
**Version:** stay **1.5.0** if audit finds docs-only / no functional gaps; bump **1.5.1** only if code/behavior fixes land

## Done predicate

1. Written matrix: each RUNTIME_ADAPTER done-predicate item 1–6 and each REFERENCE_HOST done-predicate item 1–5 → PASS / GAP with file+test evidence; vision/clarifications from PROGRESS_LOG residuals mapped the same way.
2. Local swarm slices aggregated; every ISSUES item either fixed or explicitly accepted as in-scope residual with threat-model language (no silent ignore).
3. Codebase integrity for Bar C+D surfaces: no ship-path TODO/FIXME/NotImplemented/placeholder; adapters + reference_host imports coherent; BrokeredRegistry cannot bypass ToolBroker; Claude hook deny/allow/ask paths tested; reference scenarios attack/benign/human hermetic and CLI fail-closed for live Moltbook.
4. `scripts/release_gate.sh` exit 0; eval ASR not worse than 1.5.0 baseline (0.0000); pytest green.
5. If fixes: commit + push `origin/main`; PROGRESS_LOG step evidence for each law step.

## Explicit non-goals

- Expanding beyond Bars C+D (no eval card, release ritual, bot playbook, Kata/gVisor, iron-proxy MITM, Claude auto-wire, FedRAMP claims)
- Rewriting Bar A/B surfaces that already pass unless audit proves a break caused by C/D
- Claiming “never needs more development” in absolute terms; claim is: Bar C+D law + audit findings closed
- Cloud Agents / remote swarm (standing box-only rule)

## Architecture vision check (from plans + logs)

Must confirm the shipped shape still matches:

- **Bar C:** consequence containment at the tool boundary — register → ProposedAction → ToolBroker.secure_execute only; privileged sinks need labels; Claude PreToolUse is a thin host adapter (install ≠ wired residual accepted).
- **Bar D:** reference host is the wiring recipe — `build_enterprise_host` + signed intents + BrokeredRegistry + ingest; hermetic attack deny / benign allow / require_human→approve; live Moltbook opt-in fail-closed.

## Execution steps (law)

1. **Baseline** — gate + pytest + eval + HEAD SHA; no code changes.
2. **Swarm coverage** — local N=4 executors: (A) Bar C done-predicate matrix vs code, (B) Bar D done-predicate matrix vs code, (C) adapters/registry/hooks/broker integrity + bypass attempts, (D) placeholders/exports/docs/claim drift across C+D + PROGRESS_LOG vision residuals. Write slice reports + `swarm-reports/bar-cd-audit/SWARM_AGGREGATE.md`.
3. **Plan-match report** — commit-ready `AUDIT_PLAN_VS_BAR_CD.md` mapping both laws + vision clarifications to evidence; list GAP list that steps 4–7 must clear.
4. **Fix GAPs cluster C** — BrokeredRegistry / brokered_tool / claude_hook / policy map gaps from aggregate (only evidenced ISSUES).
5. **Fix GAPs cluster D** — reference_host / scenarios / CLI / fixtures / signed-intent gaps from aggregate.
6. **Fix GAPs cluster X** — docs/exports/examples/DECISIONS/THREAT_MODEL/SKILL coherence + claim scrub from aggregate.
7. **Integrity + regression** — add/adjust tests that lock audit findings; ruff/pytest/eval; placeholder scan.
8. **Final prove-it** — release_gate; version bump 1.5.1 iff behavior changed else keep 1.5.0; push if commits; hand back matrix + residuals.

After each step: verify, append PROGRESS_LOG, do not start next until VERIFIED.  
Do not alter this law on the fly unless execution would be poor; log any amendment in PROGRESS_LOG first.
