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
