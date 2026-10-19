# Slice B — .github/workflows/publish.yml security

**Verdict:** PASS (no defects)

- Triggers: `push` tags `v*`, `workflow_dispatch`. Non-semver `v*` tags fail the version step (tag runs only).
- Permissions: top-level `permissions: {}`; build `contents: read`, `id-token: write`, `attestations: write`; publish `id-token: write` only. `actions/attest` README lists `artifact-metadata: write` only for storage records, which need `push-to-registry` (not used) → not needed.
- `actions/attest@v4`: per GitHub (attest-build-provenance v4 README, 2026-02), `attest-build-provenance` is now a wrapper and new workflows should use `actions/attest`. Correct choice.
- Injection: tag name reaches shell only as `${GITHUB_REF_NAME#v}` (env var expansion), no `${{ github.* }}` inside `run:`; `persist-credentials: false` on checkout.
- Build once: publish downloads the `dist` artifact; no rebuild after attestation.
- Gating: publish needs tag ref **and** `vars.PYPI_PUBLISH == 'true'`; environment `pypi` (reviewers recommended in RELEASE.md). Live state: repo has no variables and no environments (`gh api …/actions/variables`, `…/environments` empty) → publish job cannot run. PyPI `containment` → HTTP 404.
- `workflow_dispatch` on a tag ref also passes the publish condition once enabled: intentional, documented in RELEASE.md (back-fill upload).

Accepted residual: actions pinned by major tag (Dependabot). Note: three Dependabot PRs for `ci.yml` (checkout 7, setup-python 7, upload-artifact 7) are open and green since 2026-10-15 JST; merging is K's call.
