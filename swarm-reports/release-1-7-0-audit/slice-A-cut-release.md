# Slice A — scripts/cut_release.sh (fail-closed + edge cases)

**Verdict:** PASS (no defects)

Read the whole script and `tests/test_cut_release.py` (10 hermetic cases: help, missing version, unknown option, non-semver, pyproject mismatch, `__version__` mismatch, empty CHANGELOG section, local tag exists, dirty tree, missing origin).

Checked:
- `set -euo pipefail`; every check calls `die` (exit 1) before any side effect; `--execute` tags the `head_sha` captured after `HEAD == origin/main`, not whatever HEAD is later.
- Version regex `^[0-9]+\.[0-9]+\.[0-9]+$` blocks shell/ref metacharacters before `$TAG` is used in git/gh.
- CHANGELOG awk header match is `## [X.Y.Z]` with the closing bracket, so `1.7.0` cannot match `1.7.01`.
- Remote tag checked with `ls-remote`; local tag with `rev-parse`.
- Run lookup filters `--event push --commit head_sha` and `headBranch == TAG`, so the earlier `workflow_dispatch` build on `main` for the same commit is never picked.
- Attestation verify bound to `--source-ref refs/tags/$TAG` and `--signer-workflow`; release created only after both dists verify; failure leaves tag without release (documented recovery).

Accepted (LOW, not defects): the script does not require `[Unreleased]` to be empty or the compare link to exist (runbook-owned); step 9 installs `build>=1.2` from the index into `.venv`.
