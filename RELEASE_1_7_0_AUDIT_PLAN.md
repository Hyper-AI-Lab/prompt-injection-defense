# Release 1.7.0 Audit + Harden Plan

**Date:** 2026-10-19 JST  
**Mode:** poteto-mode / figure-it-out / local swarm (box executors only)  
**Inputs:** K ask (separate audit of 1.7.0); `RELEASE_AND_PLAYBOOK_PLAN.md` (law for 1.7.0); `PROGRESS_LOG.md`; tag `v1.7.0` → release commit `8d18e31`; HEAD `6155a1f` (log only)  
**Host:** box only (no Cloud Agents; standing rule); append-only `PROGRESS_LOG.md`  
**Version:** stay **1.7.0** if the audit finds no defects (commit + push audit docs only); bump **1.7.1** only if code/behaviour/docs fixes land

## Done predicate

1. `AUDIT_PLAN_VS_1_7_0.md`: each RELEASE_AND_PLAYBOOK_PLAN law step 1–8 and done-predicate item 1–5 → PASS / GAP with file + test evidence.
2. Fresh baseline recorded from commands actually run: exact pytest count, `release_gate.sh` exit + ASR/FPR/utility, clean wheel + sdist build, throwaway-venv wheel install running `containment doctor` and `containment-eval-card`.
3. Slice reports + `SWARM_AGGREGATE.md` + `DECISION_LOG.tsv` under `swarm-reports/release-1-7-0-audit/`; every ISSUE fixed or accepted as residual with reason (no silent ignore).
4. Fixes are surgical, each locked by a test; `release_gate.sh` exit 0; ASR not worse than 0.0000; card gate=PASS.
5. If fixes: 1.7.1 cut per `docs/RELEASE.md` (`cut_release.sh` dry run then `--execute`), CI green, attestations verify bound to `refs/tags/v1.7.1`, shared skill + `/workspace/.venvs/containment` updated. Else: commit + push audit docs only.

## Explicit non-goals

- Publishing to PyPI or changing repo settings / variables / environments (G0 stays K's)
- Re-pinning actions by SHA, putting the card into `release_gate`, host-owned isolation / egress / secret rotation (accepted residuals) unless shown wrong
- New features, corpus expansion, refactors of Bars A–E surfaces
- Cloud Agents / remote swarm

## Execution steps (law)

1. **Plan-match** — compare RELEASE_AND_PLAYBOOK_PLAN steps 1–8 + done-predicate vs shipped files; write `AUDIT_PLAN_VS_1_7_0.md` with GAP list.
2. **Fresh baseline** — pytest + `release_gate.sh` + clean build (wheel + sdist) + throwaway-venv wheel install → `containment doctor` (install-only, full, JSON) + `containment-eval-card`. Record exact numbers.
3. **Code audit slices** (local) — (A) `cut_release.sh` fail-closed + edge cases; (B) `publish.yml` security (permissions, triggers, env gating, tag-name injection); (C) doctor correctness + JSON; (D) resources packaging (wheel + sdist contents); (E) BOT_PLAYBOOK vs real CLI/API; (F) README/ARCHITECTURE/docs consistency; (G) GitHub Release assets + `gh attestation verify --source-ref refs/tags/v1.7.0`. Slice reports + aggregate + decision log.
4. **Fix** — real defects only, each with a test; residuals kept unless wrong.
5. **Release** — iff fixes: bump 1.7.1, CHANGELOG, gate, commit, push, `cut_release.sh 1.7.1 --execute`, verify CI + attestations + assets; update shared skill pin + venv. Else push audit docs.
6. **Log** — append PROGRESS_LOG entry (append-only).

After each step: verify, append evidence, do not start the next until VERIFIED.  
Do not alter this law on the fly unless execution would be poor; log any amendment in PROGRESS_LOG first.
