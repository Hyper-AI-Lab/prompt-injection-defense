# Changelog

All notable changes to `containment` (repo `Hyper-AI-Lab/prompt-injection-defense`) are
recorded here. Format: [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Eval numbers below are on the in-repo fixture suite only (`containment eval --suite fixtures`).
They are not a benchmark claim; see `docs/EVAL_CARD.md` for scope.

## [Unreleased]

## [1.7.1] - 2026-10-19

### Fixed
- `containment doctor` no longer crashes on an unreadable secret file or a malformed
  proxy URL (`http://[::1`, blank); both now report a failed check, including with `--json`.
  A proxy URL with an out-of-range or non-numeric port now fails instead of passing.
- `containment doctor` hides `user:password@` in proxy URLs (human and JSON output).
- Missing-extra errors from `Ed25519IntentSigner` and `RedisConsumeStore` pin the install
  hint to the running version's tag instead of the repository's `main` branch.
- The sdist now includes `scripts/`, so its shipped test suite runs (10 tests errored).

### Changed
- `docs/BOT_PLAYBOOK.md`: "Plan before reading" is now step 3 and "Ingest" step 4, matching
  the rule that the plan is declared before untrusted text is read. Install pins move to
  `v1.7.1`.

## [1.7.0] - 2026-10-11

### Added
- `containment doctor`: offline install and host-wiring report built on `HostChecklist`
  and `build_enterprise_host` (no network, secret values never printed). Human or `--json`
  output; exit 0 ready, 1 not ready, 2 usage; `--install-only` for package checks.
- `docs/BOT_PLAYBOOK.md`: end-to-end bot/agent procedure (attested install, policy, ingest,
  plan, enterprise broker + `BrokeredRegistry` + signed intents, reference host, doctor,
  host-owned residuals, eval card, upgrade). Its wiring example runs as a test.
- Release ritual: `CHANGELOG.md`, `docs/RELEASE.md`, fail-closed `scripts/cut_release.sh`
  (dry run by default), `.github/workflows/publish.yml` (build once, `twine check`,
  `actions/attest` build provenance; PyPI Trusted Publishing job opt-in via
  `vars.PYPI_PUBLISH`, disabled).
- `containment.resources`: one resolver for shipped `policies/` and `fixtures/`.
- CI wheel smoke: build the wheel, install it in a fresh venv, run eval, eval card and
  reference host outside the checkout.
- Annotated tags `v1.0.0`–`v1.6.1` on their release commits.

### Fixed
- `python -m build` failed: a duplicate hatch `force-include` added the reference-host
  fixtures twice to the wheel.
- Wheel installs could not find the default policy or eval fixtures, so `containment eval`,
  `containment-eval-card` and `containment-reference-host` failed outside a checkout and
  `containment-claude-hook` denied with "missing policy". Both directories now ship in the
  wheel under `containment/_data/`.
- Install hints for the `crypto` / `redis` / `ml` extras pointed at PyPI, where the name
  `containment` is not this project; they now name the GitHub source.

### Changed
- `README.md`, `SKILL.md`, `docs/AGENT_INSTALL.md` and the shared agent skill pin installs to
  the `v1.7.0` tag and state that releases are on GitHub, not PyPI.

## [1.6.1] - 2026-10-08

### Fixed
- `control_ok` in the eval card compares 4-decimal rounded ASR, so the card can no longer
  report `gate=PASS` while showing ON and OFF ASR as the same `0.0000` value.

### Changed
- `docs/ARCHITECTURE.md` and `README.md` name the `eval_card` module; threshold wording
  aligned across `docs/EVAL_CARD.md`, `SKILL.md`, `docs/AGENT_INSTALL.md`, `release_gate.sh`.

## [1.6.0] - 2026-10-08

### Added
- `containment-eval-card` CLI and `containment.eval_card` module (Bar E): citable policy-ON
  plus policy-OFF fixture scorecard as Markdown and JSON, stamped with version and git SHA.
- Fail-closed card gate: `on_asr_ok` (ON ASR == 0.0000) and `control_ok` (OFF ASR > ON ASR).
- `docs/EVAL_CARD.md`.

## [1.5.1] - 2026-10-08

### Fixed
- Bar C+D audit gaps C1–C5: `fs.*` privilege alignment, per-call broker executor,
  PreToolUse `dry_run`, tool schemas, `LABEL_REQUIRED_SINKS` export.
- Docs gaps X1–X3 (adapter and reference-host docs aligned with code).

## [1.5.0] - 2026-10-07

### Added
- `containment-reference-host` (Bar D): enterprise-wired hermetic demo with attack deny,
  benign allow and `require_human` → approve scenarios; `docs/REFERENCE_HOST.md`.

## [1.4.0] - 2026-10-07

### Added
- Runtime adapters (Bar C): `BrokeredRegistry`, `brokered_tool`, and
  `containment-claude-hook` (Claude Code PreToolUse); companion policy;
  `docs/RUNTIME_ADAPTER.md`.

## [1.3.1] - 2026-10-07

### Fixed
- `EgressProvider` on `HostChecklist`; secret bind and audit ship fail closed.
- IPv6 CONNECT handling in the egress proxy; `release_gate.sh` scan scrub.

## [1.3.0] - 2026-10-07

### Added
- Bar B host residual close: `HostGate` fail-closed enterprise checklist,
  `SecretProvider`, `AuditShipper`, broker `RateLimitGate`, `build_enterprise_host`.
- Resolve-pin egress with CGNAT deny and in-repo resolve-pin-forward egress proxy
  (`containment-egress-proxy`); pinned Moltbook/fetch paths.
- Optional Ed25519 intent signing (`containment[crypto]`) and Redis consume store
  (`containment[redis]`).
- `docs/HOST_HARDENING.md`, `scripts/microbench_host.py`.
- GitHub Actions CI: ruff, pytest, release gate, pip-audit, CycloneDX SBOM.

## [1.2.0] - 2026-10-07

### Added
- Enterprise Bar A: capability consume store, signed `IntentEnvelope` (HMAC), `url_guard`.
- `docs/OWASP_LLM_TOP10_MAP.md`; expanded red-team fixtures.
- `CONTAINMENT_STAGE1` / PIGuard-on docs and host residual checklist.
- Dependabot, pip-audit and CycloneDX documentation.

## [1.1.0] - 2026-10-07

### Fixed
- Authority-path hardening from the code audit: empty-label deny, detector fail-closed,
  RulesOnly ingest default, plan step binding and expiry, MFA/display approval,
  policy limits enforced.
- Confidentiality predicate, NoOp aggregate, encoding discovery, Stage-1 timeout as
  fail-closed error label, honest eval rates, tool schemas, MAC encoding,
  audit hash chain, packaging and exports.

## [1.0.0] - 2026-10-07

### Added
- First release: trust labels, default-deny policy broker, ingest/quarantine,
  detector cascade, Moltbook read-only helper, offline eval CLI, agent install skill.

[Unreleased]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.7.1...HEAD
[1.7.1]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.6.1...v1.7.0
[1.6.1]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/tree/v1.0.0
