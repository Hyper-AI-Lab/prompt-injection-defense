# Bar B Audit + Integrity Harden Plan

**Date:** 2026-10-07 JST  
**Mode:** poteto-mode / figure-it-out / local swarm  
**Inputs:** K ask (confirm 1.3.0 matches LEFTOVERS plan + original leftovers vision; full-scale code audit; fix to production-complete); `LEFTOVERS_HARDEN_PLAN.md`; `PROGRESS_LOG.md`; tree at `bf14a69` / containment **1.3.0**  
**Host:** box only; append-only `PROGRESS_LOG.md`  
**Version:** stay **1.3.0** if audit finds docs-only / no functional gaps; bump **1.3.1** only if code/behavior fixes land

## Done predicate

1. Written matrix: each LEFTOVERS done-predicate item 1–12 → PASS / GAP with file+test evidence.
2. Local swarm slices aggregated; every ISSUES item either fixed or explicitly accepted as in-scope residual with threat-model language (no silent ignore).
3. Codebase integrity: no ship-path TODO/FIXME/NotImplemented/placeholder; imports coherent; broker gate order documented and tested; HostChecklist fields match HostGate behavior.
4. `scripts/release_gate.sh` exit 0; eval ASR not worse than 1.3.0 baseline (0.0000); pytest green.
5. If fixes: commit + push `origin/main`; PROGRESS_LOG step evidence for each law step.

## Explicit non-goals

- Expanding beyond Bar B (no Kata/gVisor, no iron-proxy MITM, no Claude Code auto-wire, no FedRAMP claims)
- Rewriting 1.2.0 Bar A surfaces that already pass unless audit proves a break
- Claiming “never needs more development” in absolute terms; claim is: Bar B law + audit findings closed

## Execution steps (law)

1. **Baseline** — gate + pytest + eval + HEAD SHA; no code changes.
2. **Swarm coverage** — local N=4: (A) done-predicate matrix vs code, (B) broker/host/enterprise integrity, (C) egress_resolve/proxy/http_egress/moltbook, (D) placeholders/exports/docs/claim drift. Write slice reports + `swarm-reports/bar-b-audit/SWARM_AGGREGATE.md`.
3. **Plan-match report** — commit-ready `AUDIT_PLAN_VS_BAR_B.md` mapping law + original leftovers vision to evidence; list GAP list that steps 4–7 must clear.
4. **Fix GAPs cluster H** — HostGate / checklist / SecretProvider / AuditShipper / enterprise compose gaps from aggregate (only evidenced ISSUES).
5. **Fix GAPs cluster E** — egress_resolve / proxy / pin / moltbook / CGNAT / bypass gaps from aggregate.
6. **Fix GAPs cluster D** — docs/exports/examples/DECISIONS/THREAT_MODEL coherence + claim scrub from aggregate.
7. **Integrity + regression** — add/adjust tests that lock audit findings; ruff/pytest/eval; placeholder scan.
8. **Final prove-it** — release_gate; version bump 1.3.1 iff behavior changed else keep 1.3.0; push if commits; hand back matrix + residuals.

After each step: verify, append PROGRESS_LOG, do not start next until VERIFIED.  
Do not alter this law on the fly unless execution would be poor; log any amendment in PROGRESS_LOG first.
