# Release + Playbook swarm aggregate (local N=4)

**Date:** 2026-10-11 JST · **Host:** box only (no Cloud Agents; slices run by the executor)
**Scope:** law step 7 of `RELEASE_AND_PLAYBOOK_PLAN.md`

| Slice | Report | ISSUES | Residuals |
| --- | --- | --- | --- |
| A release flow | `slice-A-release.md` | A-1 MEDIUM | A-R1 major-tag pins; A-R2 attest perms proven on GitHub at step 8 |
| B playbook + skills | `slice-B-playbook.md` | (folded into A-1, D-1) | — |
| C doctor | `slice-C-doctor.md` | C-1 LOW | — |
| D claim scrub | `slice-D-claims.md` | D-1 HIGH | — |

## Fix list (surgical, evidenced only)

1. **D-1** — replace PyPI-resolving extra hints with GitHub-sourced direct references
   (src messages, doctor hints, AGENT_INSTALL, BOT_PLAYBOOK, HOST_HARDENING).
2. **A-1** — bind `gh attestation verify` to `--source-ref refs/tags/vX.Y.Z` (+ `--signer-workflow`
   in the script); show `--source-ref` in RELEASE.md / BOT_PLAYBOOK / skills.
3. **C-1** — doctor JSON omits host residuals for `scope=install`.

## Status

ISSUES: 3 → fixed in step 7 (see PROGRESS_LOG step 7 entry). Residuals A-R1 accepted; A-R2 closes
at step 8 via a `workflow_dispatch` build on main before the tag is pushed.

## Cleared (step 7, 2026-10-11)

| ID | Fix | Proof |
| --- | --- | --- |
| D-1 | `intent.py` (docstring + 2 errors), `capability_store_redis.py`, doctor `extra_install_hint()` (pinned `@v<version>`), AGENT_INSTALL §7, BOT_PLAYBOOK §1/§3, HOST_HARDENING all name the GitHub source | `rg "containment\[" src docs` shows no bare PyPI install command; `test_extra_hint_never_points_at_pypi` |
| A-1 | `cut_release.sh` verifies with `--source-ref refs/tags/$TAG --signer-workflow $REPO/.github/workflows/publish.yml`; RELEASE.md, BOT_PLAYBOOK §1, box skill show `--source-ref` | shellcheck clean; playbook needle test |
| C-1 | `run_doctor` sets `residuals=()` for install scope | `test_install_only_passes_on_this_checkout` asserts `residuals == ()` |

Gate after fixes: `release_gate.sh` exit 0, 337 passed / 2 skipped, ASR 0.0000.
