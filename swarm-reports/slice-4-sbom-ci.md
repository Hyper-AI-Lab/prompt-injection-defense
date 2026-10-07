# Slice 4 — SBOM / CI supply-chain gates

**Date:** 2026-10-07 JST  
**Repo:** `/workspace/prompt-injection-defense`  
**SHA:** `765a618ef258130d9523a50fc39e151bc74009e7` (`main`)  
**Bar A focus:** SBOM/CI supply-chain gates  
**Scope:** read-only audit (box only; no code edits)

## VERDICT: ISSUES

Local release quality gate exists and is coherent with Ruff/pytest config, but **enterprise supply-chain CI is absent**: no `.github/` workflows, no Dependabot, no SBOM/`pip-audit` job, no action pinning, no lockfile. Bar A SBOM/CI gates are **not met**.

---

## Evidence (what exists)

### CI / GitHub Actions
- **No `.github/` directory** (confirmed: no workflows, no Dependabot config, no CODEOWNERS).
- `git ls-files` shows **zero** tracked workflow/Dependabot/SBOM paths.
- Docs mention “CI stays offline” for detectors (`SKILL.md`, `docs/AGENT_INSTALL.md`, `docs/ARCHITECTURE.md`) — meaning offline detector stubs, **not** a GitHub Actions pipeline.

### `scripts/release_gate.sh` (present, local-only)
Path: `scripts/release_gate.sh` (executable, 32 lines).

Steps:
1. Ensure `.venv` + `source`
2. `python -m pip install -e ".[dev]"`
3. `ruff check src tests`
4. `pytest`
5. `python -m containment.cli eval --suite fixtures`
6. Placeholder `rg` over `src tests docs README.md SKILL.md` for `TODO|FIXME|NotImplemented|pass  #|placeholder|TBD`
7. Exit 0 on success

**Not wired to CI.** Depends on host `rg` and floating `pip install` (no hash/lock). Audits record gate green locally (`AUDIT_CODE_FINDINGS.md`, `AUDIT_PLAN_VS_CODE.md` step 16).

### `pyproject.toml` deps
| Surface | Content |
|--------|---------|
| Runtime | `pyyaml>=6.0`, `jsonschema>=4.0` (lower bounds only) |
| Dev | `pytest>=8.0`, `ruff>=0.6` |
| Optional | `ml`: transformers/torch; `stackone`: stackone-defender |
| Build | hatchling (unpinned in `[build-system].requires`) |
| Tooling | `[tool.pytest.ini_options]`, `[tool.ruff]` (+ lint/format) present |
| Lockfile | **None** (`requirements*.txt`, `uv.lock`, `poetry.lock`, `Pipfile.lock` absent) |

Version declared `1.1.0`; `license = "Apache-2.0"`; homepage/repo → `Hyper-AI-Lab/prompt-injection-defense`.

### LICENSE
- Full **Apache License 2.0** text present (`LICENSE`, 201 lines).
- Appendix copyright notice: `Copyright 2026 CryptoHamster`.
- Aligns with `pyproject.toml` SPDX/`classifiers`.

### SBOM / vulnerability scan
- **No** project CycloneDX/SPDX SBOM, **no** `pip-audit` / OSV / GitHub Dependency Review config.
- Only CycloneDX files found are vendored inside `.venv` package metadata (ruff/rpds_py) — not a project artifact.

### Related note (non-evidence for this repo)
- `DECISIONS.md` “Dependabot” refers to **microsoft/agent-governance-toolkit** upstream activity, not this repository’s Dependabot.

---

## Gaps vs Bar A (SBOM/CI supply-chain)

| Gap | Severity | Detail |
|-----|----------|--------|
| No GitHub Actions CI | **HIGH** | Gate never runs on PR/push; supply-chain / quality not enforced remotely |
| No SBOM generation | **HIGH** | No CycloneDX/SPDX artifact for releases or compliance |
| No dependency vulnerability gate | **HIGH** | No `pip-audit` / OSV / dependency-review failing the pipeline |
| No Dependabot | **MEDIUM** | No automated PR updates for pip or GitHub Actions |
| Unpinned Actions (N/A until CI exists) | **MEDIUM** | Future workflows must pin by full commit SHA |
| Floating Python deps / no lock | **MEDIUM** | `>=` only; CI installs non-reproducible trees |
| Gate not reusable as CI entry | **LOW** | Script assumes local venv + system `rg`; CI should call same steps with explicit installs |
| No action/permissions hardening | **LOW** | When CI lands: need `permissions:` least-privilege, no `pull_request_target` pitfalls |

**Not gaps for this slice:** LICENSE present and consistent; Ruff/pytest already configured; local `release_gate.sh` is a solid seed for the CI job body.

---

## Proposed minimal enterprise supply-chain (surgical)

Keep gold-plate out: one CI workflow that wraps the existing gate + SBOM/audit; Dependabot; pin actions by SHA.

### Surgical file list to **add**

1. **`.github/workflows/ci.yml`**
   - Triggers: `push`/`pull_request` to `main` (and tags if desired).
   - `permissions: contents: read` (default deny elevate).
   - Job matrix optional later; start single `ubuntu-latest`, Python 3.12 (matches `requires-python`).
   - Steps (pinned actions by **full commit SHA** + version comment):
     - `actions/checkout@<sha>`
     - `actions/setup-python@<sha>` with `python-version: "3.12"`
     - `pip install -e ".[dev]"` (+ `pip-audit`, `cyclonedx-bom` or `cyclonedx-python-lib` CLI — prefer tiny: `pip-audit` + `cyclonedx-py`)
     - `ruff check src tests`
     - `pytest`
     - `python -m containment.cli eval --suite fixtures`
     - Placeholder scan (install `ripgrep` via `apt` or use `grep -R` equivalent; prefer `rg` to match gate)
     - **OR** simply: `bash scripts/release_gate.sh` after ensuring `rg` + non-interactive venv (minor gate tweak later is out of swarm scope — document if CI needs `DEBIAN_FRONTEND`/`apt-get install ripgrep`)
   - SBOM step: `cyclonedx-py environment` or `cyclonedx-py pip` → upload `sbom.cdx.json` as artifact (`actions/upload-artifact@<sha>`).
   - Vuln gate: `pip-audit` (fail on known CVEs for installed env); optional `--strict`.

2. **`.github/dependabot.yml`**
   - `package-ecosystem: pip` — directory `/`, weekly.
   - `package-ecosystem: github-actions` — directory `/`, weekly.
   - Open PRs limited (e.g. `open-pull-requests-limit: 5`).

3. **Optional (still minimal, only if release publishing is in scope soon)**  
   - `.github/workflows/release.yml` on tag: build sdist/wheel + attach SBOM artifact. **Defer** unless Bar A release signing is required now — CI+SBOM+Dependabot satisfies the slice’s “minimal enterprise” bar.

### Explicit non-adds (avoid gold-plate)
- No SLSA provenance / cosign unless parent expands Bar A.
- No private PyPI mirror / `uv` migration in this slice.
- No pinning every transitive dep in `pyproject` yet (lockfile or `pip-compile` can follow); CI `pip-audit` + Dependabot is the first control.
- No changes to `LICENSE` / runtime code.
- Do **not** invent a second gate language — reuse `release_gate.sh` body.

### Follow-up harden (ranked backlog seed)
1. Add `.github/workflows/ci.yml` (ruff + pytest + eval + placeholder + `pip-audit` + CycloneDX artifact), actions pinned by SHA.  
2. Add `.github/dependabot.yml` (pip + github-actions).  
3. Small CI-friendly tweak to `release_gate.sh` (detect missing `rg`; allow `CI=1` to skip recreating venv oddly) — only if workflow invokes the script directly.  
4. Later: lockfile or hash-pinned constraints for reproducible installs.  
5. Later: `dependency-review-action` on PRs (needs GitHub Dependency graph).

---

## Summary for parent

| Item | Status |
|------|--------|
| Local gate (`scripts/release_gate.sh`) | Present |
| GitHub Actions CI | **Missing** |
| SBOM (CycloneDX/SPDX) | **Missing** |
| Vuln audit in CI | **Missing** |
| Dependabot | **Missing** |
| Pinned actions | **N/A** (no workflows) |
| LICENSE Apache-2.0 | Present / aligned |
| Dep declaration | Present, floating `>=` only |

**VERDICT: ISSUES** — implement surgical files above to close Bar A SBOM/CI.
