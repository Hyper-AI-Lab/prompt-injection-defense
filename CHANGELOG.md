# Changelog

All notable changes to `containment` (repo `Hyper-AI-Lab/prompt-injection-defense`) are
recorded here. Format: [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Eval numbers below are on the in-repo fixture suite only (`containment eval --suite fixtures`).
They are not a benchmark claim; see `docs/EVAL_CARD.md` for scope.

## [Unreleased]

## [1.9.0] - 2026-11-07

Tightens the six blind spots reported for 1.8.0. The detector still never authorizes;
policy and capability containment remain the guarantee (`docs/THREAT_MODEL.md`).

### Added
- Held-out gap suite `fixtures/gaps/gaps.yaml` + `containment eval --suite gaps`: 40 items
  (multi-step staged intent, tool-metadata exfil, policy tampering, quoted/discussed
  injection, long-document planted payloads) with a frozen train/holdout split, committed
  before any detector change so its holdout partition is an honest measure.
- Cross-chunk / document-level **staged intent** (gap 1): a collect-step on a secret plus a
  transmit-step to a destination, aggregated across the whole document (EN/RU/JA), flags even
  when no single sentence is malicious.
- **Tool-metadata exfil** and **policy-tamper** structural rules (gap 2), caught in no-model
  mode: descriptions that ask to log/mirror/forward/CC conversation or user data to a sink,
  and imperatives that disable/erase/relax a named protection (default_deny, guardrails,
  allowlist, rate limiter, approval requirement, safety filters…), object-bound and
  negation/narrative-aware.
- **Quoted / discussed injection** surfacing (gap 4): `quoted_instruction` (low severity) and
  `embedded_obey_instruction` findings, plus `CascadeResult.contains_instruction_text`, so a
  host can treat quoted payloads as live instructions even when the article itself stays below
  the risk line. Benign security articles do not explode false positives.
- Whole-document ONNX scanning under a wall-clock budget (gap 3): the classifier now covers the
  entire document with overlapping sliding windows (no silent ~64 KB head cap). The budget is
  `CONTAINMENT_STAGE1_BUDGET_S` (default 45 s); if it is exhausted before every window is
  scored, the scan **fails closed** (error-labelled, elevated risk) rather than skipping the
  tail.
- LLM judge hardening (gap 5): untrusted text is **datamarked** (interleaved per-call marker)
  and spotlighted; the judge must return a strict JSON schema and echo a per-call **canary**;
  any parse failure, schema violation, or canary mismatch is treated as steering and fails
  closed. The judge can still only *raise* risk.

### Changed
- Destructive verbs (disable/turn off/erase/delete/remove…) moved from the override lexicon to
  the dedicated policy-tamper rule; override now requires an instruction qualifier or directive.
- `_DISCUSSION` recognises hyphenated "prompt-injection" and more article framings, so quoted
  payloads inside explainers are correctly treated as mentions.

### Eval (detector-only; see `docs/EVAL_CARD.md` for scope)
- Mutation paraphrase recall: **100.0%** train / **100.0%** holdout, both no-model and ONNX
  (hl-small). Up from 1.8.0's 90.2% / 97.9% holdout.
- Benign false positives: **2/263** no-model, **8/263** ONNX (down from a 12/263 no-model
  pre-fix baseline). Gap suite closed on holdout in both modes (long-document payloads are
  model-only by design).
- Attack success rate with policy on: **0**.
- Latency (loaded box): zero-dependency ~16–32 ms/KB; ONNX whole-document ~105–165 ms/KB.

## [1.8.0] - 2026-11-05

The detector now aims to catch prompt injection regardless of wording. **No detector
catches every injection**; policy and capability containment remain the guarantee
(`docs/THREAT_MODEL.md`).

### Added
- Detector-only paraphrase/mutation eval: `containment eval --suite mutations` — 64 attacks
  × 14 families (hand-written reword / indirect / Russian / Japanese paraphrases, synonym,
  split across chunks, base64, hex, percent-escape, ROT13, markdown, HTML comment, CSS class
  hiding), frozen train/holdout split (`fixtures/mutations/SPLIT.md`).
- Benign corpus 47 → 222 files (multilingual, HTML with real stylesheets, code, logs,
  CPython docstrings; provenance in `fixtures/benign/SOURCES.md`).
- Stage 0 (zero-dependency): multilingual structural intent (`injection_intent`),
  `override_phrase`, decode-and-rescan (`encoded_instruction`; base64, hex, percent, ROT13
  without a marker, Morse, nested), computed CSS hiding with `<style>` classes/ids and
  inheritance (`hidden_instruction`), invisible/homoglyph de-obfuscation
  (`obfuscated_instruction`), `encoded_invisible`; package swap for any phrasing.
- `DetectorCascade.scan_chunks` (chunks, adjacent pairs, whole document);
  `CascadeResult.high_risk`; `Stage0Result.views`.
- Optional ONNX Stage 1: `CONTAINMENT_STAGE1=onnx[:hl-small|hl-base]`, `LayeredDetector`
  fusion, `containment models list|fetch|verify` (pinned revision + SHA-256), fails closed.
- Optional Stage-2 LLM judge: `CONTAINMENT_STAGE2=llm` (OpenAI-compatible, raises risk only,
  fails closed).
- `containment doctor`: `stage1.model` check when the ONNX layer is configured.
- CI `ml-eval` job; wheel smoke runs the mutation suite.

### Changed
- `[ml]` extra is now `onnxruntime` + `tokenizers` + `numpy`; PIGuard moved to `[piguard]`.
- Presence-only `base64_blob` / `hex_run` / `percent_encoding` weigh 0.15 each, capped at
  0.3 together (hashes, JWTs and images no longer flag); inline-only CSS rule replaced by the
  computed one (`css_hidden_text` alone weighs 0.2).
- `eval_runner` no longer adds the eval-only instruction-hint regex: `detector_block_rate`
  is now the production cascade's verdict.
- Held-out paraphrase recall (detector only): 34.2 % → 90.2 % zero-dep, 97.9 % with ONNX
  hl-small. Benign flagged: 8/222 → 6/222 zero-dep, 8/222 with ONNX.
- Eval on `fixtures` (policy ON): 64 attacks / 222 benign; ASR 0.0000; detector block rate
  1.0000; FPR 6/222 = 0.0270 (1.7.2 on the same corpus: 13/222 with the hint).
- Zero-dep latency 11–23 ms/KB (was ~2 ms/KB); ONNX layer ~150 ms/KB on CPU.

### Security
- A configured model or judge that cannot be used fails closed instead of falling back.

## [1.7.2] - 2026-11-05

### Added
- Stage-0 detector rules for the techniques in the 2026-11 threat check. Each is a
  structured finding (weight 0.45, so one hit makes the cascade `suspicious`):
  `tool_call_directive` (text telling the agent to call a tool with conversation content,
  Log-To-Leak), `secret_exfil_directive` (send/upload/POST of `.env`, credentials, keys or
  passwords to a URL or email), `url_data_exfil_code` (code appending `to_json()`,
  `os.environ` and similar to a URL query), `package_swap_directive` (look-alike package
  substituted via "use X instead of Y" or `import X as Y`), `forged_role_tag` (`<think>`,
  `<reasoning>`, ChatML / Llama role tags), `approval_claim` (spoofed compaction summaries
  and "approval is already recorded"), `error_fallback_steering` (fake error or 403 followed
  by a fallback that uploads or posts), `agent_addressed_directive` ("AI assistant: …",
  "assistants must first …"), `refusal_suppression` (bans on refusal words, warnings or
  disclaimers) and `css_hidden_text` (HTML text hidden by `display:none`,
  `visibility:hidden`, zero font size or opacity, white text without a background,
  off-screen offsets). Directive rules scan NFKC text with invisible characters removed.
- Morse code in encoding discovery (`morse_run`, decoded preview in the finding).
- `containment.derive_label`: a label for derived content (summaries, compaction,
  translations) keeps the lowest integrity and highest confidentiality of its inputs.
  `ingest(..., derived_from=labels)` applies it, so a summary of untrusted text cannot be
  ingested as trusted.
- Fixtures: the 11 threat-check attacks and 11 benign near-misses (one per new rule), with
  regression tests that require the detector, with policy off, to flag each attack.

### Changed
- Eval on `fixtures`: 64 attacks / 47 benign (was 53 / 36). Policy-on ASR 0.0000;
  detector block rate 0.7812 (was 0.7358); FPR 1/47 = 0.0213 (was 1/36 = 0.0278, the same
  single false positive).
- Install pins in `README.md`, `SKILL.md` and `docs/` move to `v1.7.2`.

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

[Unreleased]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.8.0...HEAD
[1.8.0]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.7.2...v1.8.0
[1.7.2]: https://github.com/Hyper-AI-Lab/prompt-injection-defense/compare/v1.7.1...v1.7.2
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
