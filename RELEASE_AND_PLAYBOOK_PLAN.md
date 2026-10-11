# Release Ritual + Bot Playbook Plan (→ 1.7.0)

**Date:** 2026-10-08 JST  
**Mode:** poteto-mode / figure-it-out / local swarm  
**Inputs:** K approval pending (plan mode); containment **1.6.1** at `aa788ca`; Bars A–E shipped + audited; deferred levers named in DECISIONS / EVAL_CARD_PLAN  
**Bars:** F — Release ritual (changelog, tags, GitHub Release, Trusted Publishing + PEP 740, runbook); G — Bot playbook (end-to-end agent wiring + host doctor)  
**Host:** box only (no Cloud Agents unless K asks); append-only `PROGRESS_LOG.md`  
**Version:** bump to **1.7.0** at final prove-it (new CLI surface + release automation)

## Done predicate

1. Every law step VERIFIED with PROGRESS_LOG evidence.
2. **Release ritual:** Keep-a-Changelog `CHANGELOG.md` through 1.6.1 (+ 1.7.0 Unreleased→Released at ship); `docs/RELEASE.md` runbook; annotated git tag `v1.7.0`; GitHub Release with notes from CHANGELOG; CI workflow `publish.yml` for tag-triggered build + `pypa/gh-action-pypi-publish` (OIDC Trusted Publishing, PEP 740 attestations by default); local `scripts/cut_release.sh` orchestrates gate → eval-card smoke → version sync check → tag push instructions (fail-closed if dirty tree / gate fail).
3. **Bot playbook:** `docs/BOT_PLAYBOOK.md` production end-to-end (install → policy → ingest → broker → adapters → reference host → eval card → host residuals); repo `SKILL.md` + `/home/box/agent-data/workflows/containment-untrusted-content/SKILL.md` refreshed for Bars A–E without placeholders; `containment doctor` (or `host-check`) CLI prints HostChecklist / residual status hermetically (no network); AGENT_INSTALL + README + DECISIONS + ARCHITECTURE updated; hermetic tests for doctor.
4. No ship-path TODO/FIXME/NotImplemented/placeholder; `release_gate.sh` exit 0; ASR not worse than 1.6.1 (0.0000); pytest green; eval-card smoke PASS.
5. Push `origin/main` + tag `v1.7.0` + GitHub Release. **PyPI upload** runs only if Trusted Publisher is already registered for this repo (see Gate G0); otherwise workflow is shipped and RELEASE.md documents the one-time PyPI registration, with no fake “published” claim.

## Explicit non-goals

- Expanding fixture corpus / AgentDojo live / hosted shields / FedRAMP / SOTA claims
- Auto-wire Claude.app settings; OS isolation from `isolation_declared`
- Renaming PyPI package away from `containment` (name checked available as of plan draft; `prompt-injection-defense` is taken by unrelated project)
- Cloud Agents / remote swarm (local N=4 for audit-style coverage only if a post-ship audit is requested separately)
- Publishing with long-lived PyPI API tokens (Trusted Publisher only)

## Architecture vision

- **F:** Reproducible cut of a known-good main: same gate humans already trust, plus citable card smoke, immutable tag, GitHub Release artifact story, optional attested PyPI publish without storing secrets in the repo.
- **G:** One playbook a bot/agent installer can follow without reading the whole tree; doctor encodes host residuals as a checkable surface (encode-lessons-in-structure), not more prose.

## Research locked into design (2026-10-08)

- PyPI Trusted Publishing + `pypa/gh-action-pypi-publish@release/v1` with `id-token: write` generates/uploads PEP 740 attestations by default (no long-lived token).
- Do not rebuild dists after attestation; build once, publish those files.
- Prefer GitHub Environment `pypi` (or `release`) as publisher environment for review protection.

## Gate G0 (operator, before or during Step 6)

K (or Hyper-AI-Lab owner) must once: create PyPI project `containment` (or claim name) and add Trusted Publisher → GitHub org `Hyper-AI-Lab`, repo `prompt-injection-defense`, workflow `publish.yml`, environment `pypi`. Until then Step 6 ships workflow + docs only; Step 7 prove-it does **not** claim PyPI presence.

## Execution steps (law)

1. **Baseline** — `release_gate.sh` + pytest + `containment-eval-card` smoke + HEAD SHA / version 1.6.1; no code. Record numbers in PROGRESS_LOG.
2. **Changelog + release docs** — author `CHANGELOG.md` (1.0.0→1.6.1 from git history / PROGRESS_LOG; honest, no SOTA); draft `docs/RELEASE.md` runbook (preflight, cut, tag, GitHub Release, Trusted Publisher setup, verify install).
3. **Cut-release script** — `scripts/cut_release.sh`: require clean tree; run gate; run eval-card smoke; verify `pyproject` version matches arg; print exact `git tag` / `gh release create` commands (or execute tag+release when `--execute` and GITHUB ok). Fail-closed. Tests or shellcheck-level smoke via running `--help` / dry-run in CI-safe mode.
4. **Publish workflow** — `.github/workflows/publish.yml`: on `push` tags `v*`; build sdist+wheel with `python -m build`; publish via Trusted Publisher + attestations; permissions least-privilege (`id-token: write`, `contents: read`); environment `pypi`. Document Environment creation in RELEASE.md.
5. **Bot playbook + skills** — write `docs/BOT_PLAYBOOK.md`; refresh repo `SKILL.md` and box workflow `containment-untrusted-content` for Bars A–E (broker, adapters, reference host, eval card, doctor pointer); update AGENT_INSTALL / README cross-links; DECISIONS ADOPT entries for F+G.
6. **Doctor CLI** — `containment doctor` subcommand: hermetic HostChecklist / residual report (JSON + human); wire existing host checklist types; tests; pyproject already has `containment` entrypoint via cli.py.
7. **Local swarm integrity (N=4)** — slices: (A) RELEASE.md + cut_release + publish.yml vs done-predicate F, (B) BOT_PLAYBOOK + skills vs vision G, (C) doctor CLI integrity / placeholders, (D) docs claim scrub. Write `swarm-reports/release-playbook/SWARM_AGGREGATE.md`; fix only evidenced ISSUES before prove-it (surgical).
8. **Final prove-it** — version **1.7.0**; CHANGELOG release section; gate + card smoke; commit + push main; annotated tag `v1.7.0`; GitHub Release; if G0 satisfied, confirm publish workflow run / PyPI files — else document pending G0 residual explicitly. Hand back matrix + residuals.

After each step: verify, append PROGRESS_LOG, do not start next until VERIFIED.  
Do not alter this law on the fly unless execution would be poor; log any amendment in PROGRESS_LOG first.
