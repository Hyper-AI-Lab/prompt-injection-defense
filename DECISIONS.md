# Decisions

Append-only decision trail for the `containment` package. Each entry records a choice, rationale, date, and links when relevant.

---

## 2026-10-07 — Stage-1 detector: adopt PIGuard (optional), skip Prompt Guard 2 by default

### Choice
- **Adopt (optional):** `leolee99/PIGuard` via `transformers` as Stage-1 when
  `pip install 'containment[ml]'` and weights are available / `allow_download=True`.
- **Default offline path:** `RulesOnlyDetector` selected by `select_stage1`, with
  `fail_closed_privileged=True` so broker/cascade integration blocks privileged
  sinks (`email.send`, `http.post`, `wallet.transfer`, …) on detector uncertainty.
- **Skip by default:** Meta **Prompt Guard 2** (gated HF models such as
  `meta-llama/Prompt-Guard-86M` / `Llama-Prompt-Guard-2-*`). Adapter exists as
  `PromptGuard2Detector.try_load` → `None` when gated/unavailable; no weight
  download in CI; no NotImplemented stubs.

### Rationale
- PIGuard is openly downloadable on Hugging Face (`https://huggingface.co/leolee99/PIGuard`),
  Apache-friendly research release, and avoids Meta gating for the default path.
- Prompt Guard 2 requires Hugging Face license acceptance; shipping or auto-downloading
  gated weights would break offline CI and violate “no Meta gated weights in package.”
- Base install stays light: `transformers`/`torch` only under optional extra `[ml]`.
- FakeStage1Detector covers offline unit tests without model downloads.

### Links
- PIGuard model: https://huggingface.co/leolee99/PIGuard
- PIGuard code: https://github.com/leolee99/PIGuard
- Prompt Guard (Meta): https://huggingface.co/meta-llama (gated)

---

## 2026-10-07 — Deep-research spot-checks (step 17) — fetch 2026-10-07 10:17 JST

Fetched via GitHub API / commit atom feeds / raw LICENSE / PyPI / Hugging Face API.
No fabricated dates. Default RulesOnly/PIGuard Stage-1 selection unchanged.

### PIGuard (`leolee99/PIGuard`) — **ADOPT** (optional Stage-1; already wired)

| Field | Value |
|-------|-------|
| License | **MIT** (repo LICENSE + HF card `mit`) |
| GitHub last commit | **2025-12-04T02:40:08Z** (atom / API: `1b5751e` "update huggingface eval") |
| Repo `pushed_at` | 2025-12-04T02:40:14Z |
| HF model `lastModified` | **2025-08-03T06:13:10.000Z** (`leolee99/PIGuard`, transformers, text-classification) |
| GitHub releases | none tagged (uses HF weights) |
| Installability on this box | Requires optional `containment[ml]` (`transformers`+`torch`). Base `.venv` has neither; `PIGuardDetector.try_load()` returns `None` → RulesOnly fail-closed. Weights downloadable when `[ml]` + `allow_download=True`. |

**URLs:** https://github.com/leolee99/PIGuard — https://huggingface.co/leolee99/PIGuard — https://aclanthology.org/2025.acl-long.1468/

**Wire:** keep existing `detectors/piguard.py` + `select_stage1` (default offline = rules-only).

### StackOne Defender / defender-py — **ADOPT optional** (complementary Tier-1; not default Stage-1)

| Field | Value |
|-------|-------|
| License | **Apache-2.0** (raw LICENSE on `StackOneHQ/defender-py`; PyPI `license_expression=Apache-2.0`) |
| PyPI | `stackone-defender==0.8.2` uploaded **2026-08-19T16:28:27.504012Z** |
| GitHub last commit (`defender-py` main atom) | **2026-08-19T16:28:03Z** |
| Requires-Python | >=3.11 |
| Installability on this box | **Verified:** installed into throwaway `/tmp/dd-venv` on Python 3.13; `import stackone_defender` OK. Dry-run into project `.venv` succeeds. |

API fit notes: primary product surface is `create_prompt_defense().defend_tool_result` (tool-result sanitization). Also exposes `analyze(text) -> Tier1Result` which maps cleanly to Stage-1 risk signals. Does **not** replace RulesOnly/PIGuard default path.

**URLs:** https://github.com/StackOneHQ/defender-py — https://pypi.org/project/stackone-defender/ — https://github.com/StackOneHQ/defender (TS upstream)

**Wire:** added optional `detectors/stackone.py` + `[project.optional-dependencies] stackone`; `try_load` returns `None` when unset. Default `select_stage1` unchanged.

### Microsoft Agent Governance Toolkit — **SKIP** (v1.0)

| Field | Value |
|-------|-------|
| License | **MIT** (raw LICENSE; PyPI license MIT) |
| PyPI | `agent-governance-toolkit==4.1.0` uploaded **2026-06-11T02:24:50.760120Z** |
| GitHub last commit (main atom) | **2026-10-07T00:44:14Z** (active; Dependabot) |
| Installability | Dry-run into `.venv` would pull pydantic/click/etc. (`Would install agent_governance_toolkit-4.1.0 …`). Installable, but heavy governance/runtime surface. |

**Rationale:** DEVELOPMENT_PLAN outs full Microsoft Agent Framework / FIDES-style lock-in for v1.0. Toolkit is complementary fleet/runtime governance, not a drop-in Stage-1 classifier for our broker.

**URLs:** https://github.com/microsoft/agent-governance-toolkit — https://pypi.org/project/agent-governance-toolkit/

**Wire:** none in v1.0.

### Invariant Guardrails (`invariantlabs-ai/invariant`) — **SKIP** (v1.0)

| Field | Value |
|-------|-------|
| License | **Apache-2.0** (raw LICENSE) |
| PyPI | `invariant-ai==0.3.5` uploaded **2025-07-28T10:08:02.586587Z** (no SPDX classifier on PyPI metadata) |
| GitHub last commit (main atom) | **2026-01-12T12:50:28Z** |
| Installability | Verified in `/tmp/dd-venv`: `pip install invariant-ai==0.3.5` → `import invariant` OK. Pulls openai/nltk/sdk stack. |

**Rationale:** Architecture is LLM/MCP proxy guardrailing language + analyzer, not an in-process Stage-1 adapter for our policy broker. Would broaden deps and claim surface without fitting current cascade.

**URLs:** https://github.com/invariantlabs-ai/invariant — https://pypi.org/project/invariant-ai/ — https://invariantlabs.ai

**Wire:** none in v1.0.

---

## 2026-10-07 — Policy YAML limits enforcement (AUDIT harden step 8 / H4)

### Choice
**Enforce** all three keys shipped under `read-public-web.limits` in
`policies/default_deny.yaml` inside `ToolBroker.secure_execute` via
`_limits_violation` (no silent pass-through):

| Key | Enforcement |
|-----|-------------|
| `max_bytes` | Deny when argument payload fields (`body`/`content`/`data`/`payload`/`text`) exceed the byte cap. Cap is also attached on `PolicyDecision.limits` for executors. |
| `redirects` | Deny when args request `redirects`/`max_redirects` above the cap, or `allow_redirects: true` when cap is `0`. |
| `network: public_only` | Deny when `url` host is a literal loopback/private/link-local/unspecified/multicast/reserved IP (or `localhost`). No DNS resolution / no full SSRF stack. |

Unknown limit keys fail closed (`unenforced limit keys present`). No keys were stripped from YAML this step because all three are enforceable without inventing a network fetch stack.

### Rationale
AUDIT H4: parsed-then-ignored scaffold. Prefer enforce over strip when possible (plan step 8). Response-body download capping still requires the executor to honor `decision.limits["max_bytes"]` at fetch time; the broker enforces argument-side overflows and binding metadata.

### Links
- Plan: `AUDIT_HARDEN_PLAN.md` step 8
- Finding: `AUDIT_CODE_FINDINGS.md` H4

---

## 2026-10-07 — Web deep-research spot-check (AUDIT harden step 18)

**Date researched:** 2026-10-07 (JST)

### PIGuard (`leolee99/PIGuard`) — **KEEP optional** (`containment[ml]`)

| Field | Value |
|-------|-------|
| Paper | ACL 2025 long — Mitigating Overdefense for Free (MOF) |
| HF model | https://huggingface.co/leolee99/PIGuard (DeBERTa-v3-base; ~0.2B; renamed from InjecGuard) |
| Code | https://github.com/leolee99/PIGuard |
| Demo | https://injecguard.github.io/ |
| Anthology | https://aclanthology.org/2025.acl-long.1468/ |

**Adopt/skip:** Keep as optional Stage-1 via `select_stage1(prefer="piguard", allow_download=...)`. Still requires `transformers`+weights — **not** default offline CI. No new heavy dep. Existing adapter remains valid; no API break observed in HF deploy snippet (`trust_remote_code=True`, text-classification pipeline).

**Note:** Third-party Rust/ONNX CLI (`misteral/piguard`) exists for ~10ms local inference — interesting for future optional backend, **skip for 1.x** (would add ONNX runtime to default path).

### StackOne Defender — **KEEP optional** (`containment[stackone]`); do not promote to default

| Field | Value |
|-------|-------|
| PyPI | `stackone-defender==0.8.2` (Apache-2.0; uploaded 2026-08-19) — https://pypi.org/project/stackone-defender/ |
| Repo | https://github.com/StackOneHQ/stackone-defender |
| Product | https://www.stackone.com/platform/prompt-injection-guard/ (page `dateModified` 2026-06-04) |
| Docs | https://docs.stackone.com/secure/defender |
| npm | `@stackone/defender` (TS primary; Python aligned) |

**Adopt/skip:** Remains optional Stage-1/tool-result scanner. Wheel with `[onnx]` is ~18MB+ — fine as extra, **breaks offline CI** if made required. Relevant 2026 notes for fail-closed integration:
- `require_tier2=True` fails closed when ONNX Tier-2 cannot load (else degrades to Tier-1).
- Tier-3 provider timeout/error is **fail-open** to Tier-2 (cascade) or allow (`tier3_only`) — opposite of our privileged-sink posture; do not mirror Tier-3 fail-open into broker mint.
- Tool-result scanning complements our ingest cascade; does not replace policy/broker authority.

### Stage-1 timeout → fail-closed — **ADOPT (already step 12)**

Industry pattern (2026): bind failure posture to control severity — timeouts on safety-critical detectors fail closed; advisory checks may fail open.

| Source | URL |
|--------|-----|
| Guardrails contract (timeout/unavailability → fail closed for protected ops) | https://github.com/Accelerated-Innovation/governed-ai-delivery/blob/main/extensions/llm-application/docs/backend/architecture/MODEL_GUARDRAILS_CONTRACT.md |
| Fail-open vs fail-closed by severity + per-detector timeout budget | https://znyx.ai/blog/designing-for-llm-reliability |
| liteLLM: distinguish `on_error` (timeout) vs `on_fail` (policy) | https://docs.litellm.ai/docs/proxy/guardrails/policy_flow_builder |
| Guardrail DoS / fail-open vs fail-closed tradeoff | https://arxiv.org/abs/2606.14517 |

**Wire:** `DetectorCascade.stage1_timeout_s` (default 5s) → Stage-1 `label=error` → `privileged_sink_fail_closed` (step 12). No new deps. Aligns with “timeout is a failure; privileged sinks fail closed.”

### Heavy deps decision
No new packages added to default/`[dev]`. PIGuard and StackOne stay optional extras. Offline CI remains RulesOnly + Stage-0.

---

## 2026-10-07 — Enterprise Bar A adopt notes (1.2.0)

### Capability consume store — **ADOPT**
- **Protocol** `CapabilityConsumeStore` with **Memory** (default) and **Sqlite** backends.
- SQLite enables cross-process one-use consume; Memory remains the default for single-process hosts.
- **Skip:** Redis as a required dependency (out of Bar A).

### Signed IntentEnvelope (HMAC) — **ADOPT**
- `IntentSigner` / `SignedIntent` bind `task_id`, principal, scope, issued/expiry, `plan_hash`.
- Broker flags: `require_signed_intent` and `enterprise_profile` verify before mint.
- **Skip:** Ed25519 as required (optional future); HMAC is the Bar A binding.

### url_guard — **ADOPT**
- Shared helpers for scheme/userinfo/literal metadata & private IP rejection; wired into policy, broker, and moltbook.
- Moltbook: no-follow redirects + max read + base_url check.
- **Residual:** not DNS-rebinding-complete SSRF; host egress proxy still required.

### OWASP map + red-team expansion — **ADOPT**
- `docs/OWASP_LLM_TOP10_MAP.md` (OWASP LLM Top 10 **2025**).
- ≥10 surgical attack fixtures from slice-5; corpus category asserts extended.

### PIGuard-on path — **ADOPT (docs + thin env)**
- `CONTAINMENT_STAGE1` + `CONTAINMENT_PIGUARD_ALLOW_DOWNLOAD`; `make_stage1_cascade` / `stage1_from_env`.
- Default ingest remains RulesOnly unless env set.
- Host residual checklist in `docs/AGENT_INSTALL.md` §8.

### CI / SBOM — **ADOPT**
- `.github/workflows/ci.yml` + `.github/dependabot.yml`; `pip-audit` + CycloneDX (`cyclonedx-bom`) in CI.
- Local commands documented in README.

### Explicit non-goals (unchanged)
Full CaMeL/FIDES; Meta PG2 default download; OS sandbox; DNS-rebinding-complete SSRF; Redis required; FedRAMP/SOC2 certification claims.

---

## 2026-10-07 — Leftovers Bar B adopt notes (Host Residual Close + egress proxy)

### HostGate / HostChecklist — **ADOPT**
- Enterprise / `require_host_gate` refuses mint + privileged execute unless
  `HostChecklist.ok()` (isolation declared, `SecretProvider`, egress configured,
  `AuditShipper`).
- `build_enterprise_host()` fails closed with `ValueError` before returning a
  broker if isolation/egress are missing.

### SecretProvider — **ADOPT**
- Protocol + `EnvSecretProvider` + `FileSecretProvider`.
- Install / README examples use providers; no hardcoded production HMAC bytes
  in factory defaults.

### AuditShipper — **ADOPT**
- Protocol + `FileAuditShipper` (JSONL export / tamper-evidence).
- WORM / SIEM shipping remains host-owned.

### Resolve-pin + in-repo egress proxy — **ADOPT**
- `egress_resolve` deny CIDRs include CGNAT `100.64/10`; pinned connect helpers.
- `containment-egress-proxy`: resolve-pin-forward HTTP (CONNECT + absolute-URI).
- **Skip:** Go iron-proxy clone; TLS MITM / credential injection.

### Ed25519 intents — **ADOPT (optional)**
- `Ed25519IntentSigner` behind `containment[crypto]`; broker `IntentVerifier`.
- HMAC remains the default enterprise binding.

### Redis consume store — **ADOPT (optional)**
- `RedisConsumeStore` behind `containment[redis]`; hermetic fake-client tests.
- Memory / Sqlite unchanged; Redis not required.

### RateLimitGate — **ADOPT (optional)**
- `TokenBucketRateLimit` on privileged broker mint when configured.
- Model API quotas outside the library remain host residual (LLM10).

### Docs — **ADOPT**
- `docs/HOST_HARDENING.md`; AGENT_INSTALL / THREAT_MODEL / README / SKILL updated.

### Explicit non-goals (Bar B)
Kata/gVisor images; auto-wiring Claude Code / ChatGPT / Cursor product;
FedRAMP/SOC2 claims; zero residual when host skips checklist/proxy/isolation.

---

## 2026-10-07 — Leftovers Bar B prove-it (1.3.0)

### Release — **SHIP 1.3.0**
- Host residual close + in-repo resolve-pin-forward egress proxy landed under LEFTOVERS_HARDEN_PLAN.md.
- Prove-it: `scripts/microbench_host.py` (sub-ms mean for resolve_and_pin / checklist / rate gate with injected resolver); `./scripts/release_gate.sh` OK; ASR=0.0000, FPR=0.0278; 251 passed, 2 skipped.
- Push to `origin/main` owned by parent after review (executor did not push).

### Microbench interpretation
- Numbers measure stdlib `perf_counter` around pure CPU paths (injected DNS, checklist bools, token bucket). They are **not** end-to-end agent latency and exclude LLM round-trips and real DNS.


---

## 2026-10-07 — Bar B audit harden (EgressProvider + secret bind)

### EgressProvider — **ADOPT**
- `HostChecklist.egress_provider` required (`ProxyEgressProvider` /
  `PinnedEgressProvider`). Bool-only `egress_configured` on the checklist removed;
  compat property remains. `build_enterprise_host` accepts `egress_provider=`,
  `proxy_url=`, or `egress_configured=True` (pinned).

### Secret bind + audit ship — **ADOPT**
- HostGate compares `SecretProvider` capability secret to minter via
  `CapabilityMinter.matches_secret` (constant-time). Mismatch →
  `host_secret_mismatch`.
- `ship_audit` (default on under HostGate) calls `AuditShipper.ship_file` after
  each recorded decision; ship failure fail-closed → `host_audit_ship_failed`.
- `FileAuditShipper.export_hmac_tip` for tip HMAC export.

### Accepted residuals
- Rate limit still optional on enterprise compose.
- `isolation_declared` honor system; opener DI; proxy-wins-over-pin.

---

## 2026-10-07 — Runtime adapters Bar C (→ 1.4.0)

### BrokeredRegistry + brokered_tool + Claude PreToolUse — **ADOPT**
- In-process `BrokeredRegistry`: register name→callable; invoke only via
  `ToolBroker.secure_execute`; unknown deny; privileged sinks need labels.
- `brokered_tool` decorator for OpenAI-style wrappers (no full OpenAI SDK).
- `containment-claude-hook` CLI maps Bash|Write|Edit|Read → containment tools;
  `permissionDecision` allow|deny|ask; fail closed on unmapped/malformed.
- Docs: `docs/RUNTIME_ADAPTER.md`. Version bump to 1.4.0 deferred to final prove-it.

### Explicit non-goals
LangGraph-only plugin; full MCP server product; auto-install into Claude without
user settings; claiming hooks cannot be disabled by the host.
