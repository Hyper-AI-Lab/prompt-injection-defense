# Slice A — RELEASE.md + cut_release.sh + publish.yml vs done-predicate F

**Method:** local executor (box, no Cloud Agents). Read all three surfaces side by side; ran
`tests/test_cut_release.py` (10 passed), shellcheck, actionlint, zizmor --offline, local
`python -m build` + `twine check --strict`; checked `gh` 2.102 flags.

## Predicate F matrix

| Item | Status | Evidence |
| --- | --- | --- |
| Keep-a-Changelog `CHANGELOG.md` through 1.6.1 | PRESENT | 10 versions, compare links; versions verified per release commit |
| `docs/RELEASE.md` runbook | PRESENT | preflight, 9 ordered checks, execute flow, workflow jobs, consumer verify, G0 setup, history |
| Annotated tag `v1.7.0` + GitHub Release with CHANGELOG notes | PENDING step 8 | script `--execute` path; notes = awk-extracted section |
| `publish.yml` tag-triggered build + Trusted Publishing + PEP 740 | PRESENT | build once, attest, artifact hand-off; publish gated `vars.PYPI_PUBLISH` + env `pypi` |
| `cut_release.sh` fail-closed (dirty/gate/card/version/tag) | PRESENT | order in script == order in RELEASE.md; 10 hermetic failure tests |
| No long-lived tokens; least privilege | PRESENT | top-level `permissions: {}`; per-job minimal; `persist-credentials: false` |

## Findings

| ID | Severity | Finding | Evidence | Fix |
| --- | --- | --- | --- | --- |
| A-1 | MEDIUM | `gh attestation verify -R` alone accepts any attestation for the digest from this repo (e.g. a `workflow_dispatch` build on a branch). The release script should bind the verify to the tag and to `publish.yml`. | `gh attestation verify --help`: `--source-ref`, `--signer-workflow` exist | Script verifies with `--source-ref refs/tags/vX.Y.Z --signer-workflow Hyper-AI-Lab/prompt-injection-defense/.github/workflows/publish.yml`; docs show `--source-ref` |
| A-R1 | residual | Actions pinned by major tag, not SHA (zizmor `unpinned-uses`) | zizmor --offline: only finding class | Accepted: K spec `release/v1`, consistent with ci.yml, Dependabot refresh |
| A-R2 | residual | `actions/attest@v4` permission set (no `artifact-metadata: write`) only provable on GitHub | README: storage records relate to registry pushes | Prove with `workflow_dispatch` run on main before tagging (step 8) |

Verdict: 1 ISSUE (A-1), 2 residuals.
