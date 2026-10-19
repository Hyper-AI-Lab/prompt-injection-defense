# Audit: RELEASE_AND_PLAYBOOK_PLAN vs shipped 1.7.0

**Date:** 2026-10-19 JST  
**Base:** tag `v1.7.0` → `8d18e31f0362`; HEAD `6155a1ff1bf9` (PROGRESS_LOG only on top)  
**Law:** `RELEASE_1_7_0_AUDIT_PLAN.md`  
**Swarm:** `swarm-reports/release-1-7-0-audit/SWARM_AGGREGATE.md`

## Law steps 1–8

| # | Plan step | Result | Evidence |
| --- | --- | --- | --- |
| 1 | Baseline (gate + pytest + card at 1.6.1) | **PASS** | PROGRESS_LOG Release+Playbook step 1 |
| 2 | `CHANGELOG.md` 1.0.0→1.6.1 + `docs/RELEASE.md` runbook | **PASS** | Keep a Changelog 1.1.0 header, `[Unreleased]`, dated sections, compare links; runbook covers preflight, cut, publish, consumer verify, G0 |
| 3 | `scripts/cut_release.sh` fail-closed, dry run default, `--execute` | **PASS** | 9 ordered checks, `set -euo pipefail`, `die` on each; 10 hermetic tests in `tests/test_cut_release.py`; `--execute` tags only `head_sha`, verifies attestations before `gh release create` |
| 4 | `publish.yml`: tag trigger, build once, Trusted Publishing, least privilege, env `pypi` | **PASS** | `permissions: {}` top level; build `contents: read` + `id-token: write` + `attestations: write`; publish `id-token: write` only, env `pypi`, gated `vars.PYPI_PUBLISH == 'true'` + tag ref; tag name used only via `$GITHUB_REF_NAME` env (no `${{ }}` in `run:`); `actions/attest@v4` is GitHub's current successor of `attest-build-provenance` |
| 5 | Bot playbook + skills + cross-links + DECISIONS | **GAP (G6)** | Content and API calls match the code (wiring example runs as `tests/test_bot_playbook.py`), but §3 *Ingest* comes before §4 *Plan before reading* while the page says "follow the steps in order" |
| 6 | `containment doctor` hermetic, JSON + human, tests | **GAP (G1–G3)** | Works for documented inputs (wheel venv: install-only 2/2, full host 8/8, empty host 2/8 exit 1), but an unreadable secret file or a malformed proxy URL crashes with a traceback (no report, no JSON), `http://h:99999` passes, and a proxy URL with `user:pass@` is printed verbatim |
| 7 | Local swarm integrity | **PASS** (D-1 partially) | `swarm-reports/release-playbook/`; D-1 left three runtime ImportError hints unpinned (G4) |
| 8 | Final prove-it, tag, Release, no PyPI claim | **PASS** | Release `v1.7.0` not draft, 4 assets; wheel + sdist attestations verify with `--source-ref refs/tags/v1.7.0 --signer-workflow …/publish.yml`; PyPI `containment` still 404 (no claim made) |

## Done predicate 1–5

| # | Requirement | Result |
| --- | --- | --- |
| 1 | Every law step VERIFIED in PROGRESS_LOG | **PASS** |
| 2 | Release ritual artifacts | **PASS** (G5: sdist ships `tests/` but not `scripts/`, so 10 shipped tests error from the sdist) |
| 3 | Bot playbook + doctor hermetic, no placeholders | **GAP** → G1, G2, G3, G6 |
| 4 | No unfinished markers, gate 0, ASR 0.0000, pytest green, card PASS | **PASS** (fresh: 337 passed / 2 skipped, ASR 0.0000) |
| 5 | Push main + tag + Release; PyPI pending G0 documented | **PASS** |

## GAP list (steps 4–5 of the audit law must clear)

1. **G1 (MED)** doctor: unreadable secret file raises `PermissionError` → traceback, no report / JSON.
2. **G2 (MED)** doctor: proxy URL credentials (`http://user:pass@host`) printed in human + JSON output, contradicting "secret values are never printed".
3. **G3 (LOW)** doctor: malformed proxy URL (`http://[::1`, whitespace) → `ValueError` traceback; out-of-range port (`:99999`) reported PASS.
4. **G4 (LOW)** runtime hints for `[crypto]` (`intent.py` ×2) and `[redis]` (`capability_store_redis.py`) install from git `main`, not the running version's tag, so following them replaces a verified release with an unverified `main` build.
5. **G5 (LOW)** sdist omits `scripts/`; `pytest` from the unpacked 1.7.0 sdist → 327 passed, 2 skipped, 10 errors.
6. **G6 (LOW)** BOT_PLAYBOOK step order: plan must be declared before ingesting untrusted text, but §3 is ingest and §4 is plan.

## Residuals accepted (not GAPs)

Card not in `release_gate`; actions pinned by major tag (Dependabot); doctor sees declarations only (isolation, egress enforcement, WORM, secret rotation host-owned); PyPI unpublished until G0; earlier Bar C–E residuals. See aggregate for audit-specific notes.

## Post-harden

G1–G6 **CLEARED** in 1.7.1 (see aggregate). Matrix after harden: law steps 1–8 PASS; done-predicate 1–5 PASS.
