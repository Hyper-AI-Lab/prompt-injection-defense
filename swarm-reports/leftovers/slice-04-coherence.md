# Slice 04 — Coherence / non-regression / docs surface (Bar B vs 1.2.0)

**Date:** 2026-10-07 JST  
**Repo:** `/workspace/prompt-injection-defense`  
**SHA audited:** `0c17a98a42b7911a0031e6b9d0b36f08a5a2a52c` (`containment==1.2.0`)  
**Bar:** B — Host Residual Close + in-repo Python egress proxy → **1.3.0**  
**Plan:** `LEFTOVERS_HARDEN_PLAN.md`  
**Prior bar:** A — `ENTERPRISE_HARDEN_PLAN.md` done predicate (1.2.0 sealed)  
**Scope:** Read-only coherence: what must stay green, doc coupling, claim risks, new export/CLI surface. **No product code changes.**

---

## VERDICT: PASS

Bar B plan is coherent with sealed 1.2.0. Done predicate + non-goals correctly extend (not rewrite) Bar A: HostGate / SecretProvider / resolve-pin / in-repo egress proxy / AuditShipper / optional Ed25519+Redis / rate-spend / `build_enterprise_host()` / `docs/HOST_HARDENING.md`, while preserving library-vs-host boundary and explicit refusal of FedRAMP / zero-residual / auto-wire of Claude Code.

No blockers to execution. Issues below are **watch-items for implementers** (doc sync + placeholder scan + claim discipline), not plan defects.

---

## What must stay green (non-regression)

### 1. Eval ASR / FPR / utility (fixtures suite)

| Mode | Must hold | 1.2.0 prove-it baseline (PROGRESS_LOG) |
| --- | --- | --- |
| Policy **ON** | **ASR = 0.0000** (all attacks blocked) | ASR=0.0000, FPR=0.0278, utility=0.9722; detector_block_rate≈0.7358; policy_block_rate=1.0 (**53** attacks / **36** benign) |
| Policy **OFF** (`--no-policy`) | **ASR rises** (control); typically ASR=1.0000 on this corpus | ASR must be **strictly worse** than ON |

**Regression rules for 1.3.0:**

- Do **not** weaken default-deny policy, empty-label deny, plan binding, or broker privileged-sink fail-closed such that ASR > 0 under policy ON.
- Do **not** drop or rename attack fixtures without updating `tests/test_fixtures_corpus.py` category asserts.
- FPR may drift slightly if benign corpus grows; keep utility high and document any FPR increase in PROGRESS_LOG. Do not “fix” FPR by deleting hard benign cases.
- HostGate / egress_proxy / SecretProvider must not change offline eval path (eval stays hermetic; no live proxy required for `containment eval --suite fixtures`).

### 2. `scripts/release_gate.sh` checks (must exit 0)

Order today (do not drop steps; may **add** hermetic checks for new modules):

1. Ensure `.venv` + `pip install -e ".[dev]"`
2. `ruff check src tests`
3. `pytest` (full suite; 1.2.0: **171 passed, 1 skipped**)
4. `python -m containment.cli eval --suite fixtures`
5. Placeholder `rg` scan on `src tests docs README.md SKILL.md` for:  
   `TODO|FIXME|NotImplemented|pass  #|placeholder|TBD` → **fail on any hit**

**1.3.0 watch:** new files under `docs/` (e.g. `HOST_HARDENING.md`) are covered by the `docs` path already. New CLI modules / comments must not introduce those markers. Optional Redis tests must **skip with real reasons**, not `NotImplemented` stubs in ship paths.

### 3. Bar A sealed surfaces (must remain true under Bar B)

From `ENTERPRISE_HARDEN_PLAN.md` done predicate — still required:

| Bar A item | Coherence note |
| --- | --- |
| HMAC `IntentSigner` + `require_signed_intent` / enterprise | Keep; Ed25519 is **alongside**, not a replacement of HMAC |
| `CapabilityConsumeStore` Memory + SQLite | Keep; Redis is **optional** `[redis]` extra only |
| `url_guard` literal SSRF helpers | Keep; `egress_resolve` / proxy **extend** beyond literals |
| CI workflow + dependabot + SBOM/pip-audit docs | Keep; extend CI only if new hermetic jobs needed |
| OWASP map + expanded fixtures | Keep corpus; do not regress category coverage |
| PIGuard-on recipe + AGENT_INSTALL §7–§8 | Keep; §8 checklist evolves into HostGate + HOST_HARDENING without deleting PIGuard text |
| No FedRAMP/SOC2 claims | Unchanged non-goal |

### 4. Version / packaging coherence

- Tree today: `pyproject.toml` + `containment.__version__` = **1.2.0**
- Bump to **1.3.0** only at final prove-it (plan step 11), both places + any docs that pin version strings
- Existing console script: `containment = containment.cli:main` must keep working (`containment eval`)

---

## Doc files that must update together (step 10 coupling)

Plan item 11 / step 10 lists docs. Treat as a **single atomic doc set** — merge or gate fails claim consistency:

| File | Required 1.3.0 change |
| --- | --- |
| **`docs/HOST_HARDENING.md`** | **New.** HostGate checklist, SecretProvider, EgressProvider / `containment-egress-proxy`, AuditShipper, rate/spend, `build_enterprise_host()`, what still requires OS isolation |
| **`docs/AGENT_INSTALL.md`** | Evolve §8 residual checklist → point at HostGate + HOST_HARDENING; replace inline `CapabilityMinter(secret=b"...")` examples with SecretProvider; document proxy env (`HTTP(S)_PROXY`) / enterprise profile |
| **`docs/THREAT_MODEL.md`** | Update residual bullets: resolve-pin + proxy close *part* of SSRF residual; document residual if host bypasses pin/proxy; AuditShipper vs WORM; Ed25519 optional; Redis optional; rate gate; **still** no OS sandbox claim |
| **`DECISIONS.md`** | Append Bar B adopt notes (HostGate fail-closed, Env/File secrets, resolve-pin, Python HTTP forward proxy ≠ iron-proxy MITM, Ed25519 optional, Redis optional) |
| **`README.md`** | Honest claim table: library + optional in-repo proxy; not FedRAMP; link HOST_HARDENING; enterprise quickstart via `build_enterprise_host()`; keep “not injection-proof” |
| **`SKILL.md`** | Agent procedure: HostGate when enterprise; run/use egress proxy when required; SecretProvider; no zero-residual claim; link HOST_HARDENING |
| **`docs/ARCHITECTURE.md`** | Module map: `host`, `egress_resolve`, `egress_proxy`, rate gate, composition helper (plan implies via exports; keep diagram coherent) |
| **`docs/OWASP_LLM_TOP10_MAP.md`** | Touch only if LLM10 rate/spend or SSRF rows need “library now provides X / host still Y” — do not invent new certifications |
| **`PROGRESS_LOG.md`** | Append-only per step (law); final prove-it records microbench + gate + eval |

**Sync rule:** Any sentence that says “hosts must provide egress proxy” must acknowledge the **in-repo** `containment-egress-proxy` as an option **and** that OS isolation / real network policy remain host duties. Do not leave AGENT_INSTALL §8 contradicting HOST_HARDENING.

---

## Placeholder / claim risks

### Placeholder scan traps (release_gate fail)

- Comments like `# TODO: pin DNS`, `NotImplementedError` in Protocol defaults that ship, `pass  # stub`, docs saying “placeholder”, “TBD”, or “scaffold”
- Example secrets in docs: prefer `EnvSecretProvider` / file path prose — avoid suggesting committed raw HMAC bytes as production-ready (README/AGENT_INSTALL still show `b"replace-me..."` — **must update** in step 10)
- Redis / Ed25519: if unavailable, **pytest.skip("reason")**, never empty `NotImplemented` ship paths

### Forbidden / overclaim language (plan non-goals)

Do **not** write in README / SKILL / THREAT_MODEL / HOST_HARDENING / marketing:

- FedRAMP, SOC2, ISO, or any **certification** claim
- “Zero residual”, “injection-proof”, “DNS-rebinding proof forever”, “covers every side channel”
- “Auto-wires Claude Code / ChatGPT / Cursor”
- Equating our Python HTTP resolve-pin-forward proxy with Hermes **iron-proxy** (Go) or credential-injection TLS MITM
- Claiming Kata/gVisor/microVM isolation from this package

### Honest residual language (must remain)

- Library constrains **authority** in-process; not a kernel sandbox
- Residual if host bypasses broker, pin, or proxy (DNS-rebinding TOCTOU)
- AuditShipper / file hash chain = tamper-*evidence*, not WORM
- Detectors can FN/FP; policy/broker remain authority
- Measured ASR/FPR are corpus-empirical, not certification

### Scope honesty vs “production-complete”

Bar B “production-grade in-repo” means: fail-closed HostGate + working resolve-pin + hermetic-tested proxy + providers + docs + green gate. It does **not** mean the pip package alone is a complete host security program. Docs must say that explicitly so Bar B does not contradict the user’s earlier Q&A (“one-click shield is impossible”).

---

## Export / CLI entrypoint list for new modules

### Existing (must keep)

**`[project.scripts]`**

| Entry | Target |
| --- | --- |
| `containment` | `containment.cli:main` |

**Public package exports today** (`src/containment/__init__.py`): actions, audit, broker, capability(+store), datamark, detectors helpers, ingest, intent (HMAC), labels, moltbook, plan, policy, quarantine, url_guard, `__version__`.

### New for Bar B (plan → wire in step 10 / exports)

**Modules (expected)**

| Module | Role |
| --- | --- |
| `containment.host` | `SecretProvider`, `EnvSecretProvider`, `FileSecretProvider`, `HostChecklist`, `AuditShipper`, `FileAuditShipper`, `RateLimitGate`, `TokenBucketRateLimit`, (and related types) |
| `containment.egress_resolve` | DNS resolve → deny-CIDR → pinned address; pinned connect helper |
| `containment.egress_proxy` | HTTP forward proxy resolve-pin-forward daemon implementation |
| Composition | `build_enterprise_host()` (location per implementer: `host` or top-level — **must** be in `__all__`) |
| Intent | Ed25519 signer/verify **alongside** existing HMAC `IntentSigner` |
| Capability store | `RedisConsumeStore` behind optional import / `[redis]` |

**Suggested `__all__` additions** (names may match implementation; all ship symbols used in HOST_HARDENING / AGENT_INSTALL must be importable):

- `SecretProvider`, `EnvSecretProvider`, `FileSecretProvider`
- `HostChecklist` (and any `HostGate` / checklist result type)
- `AuditShipper`, `FileAuditShipper`
- `RateLimitGate`, `TokenBucketRateLimit`
- `build_enterprise_host`
- Resolve/pin: e.g. `resolve_pin`, `pinned_connect`, deny-CIDR helpers / errors as documented
- Ed25519: e.g. `Ed25519IntentSigner` (or equivalent) + any verify helper
- `RedisConsumeStore` (importable when `[redis]` installed; clear error otherwise)

**New `[project.scripts]` entry (plan done predicate §6)**

| Entry | Target (expected) |
| --- | --- |
| `containment-egress-proxy` | `containment.egress_proxy:...` (module `__main__` or `main`) |

Also keep `python -m containment.egress_proxy` runnable if that is the documented module path.

**New optional dependency**

```toml
[project.optional-dependencies]
redis = ["redis>=..."]   # exact pin chosen at implement time
```

Do not add Redis to default/`[dev]` required deps (Bar A non-goal preserved).

**CLI / scripts that must remain documented**

- `containment eval --suite fixtures` (+ `--no-policy` control)
- `containment-egress-proxy` (listen / allowlist / deny-CIDR flags as implemented)
- Latency **microbench script** (plan step 11) — path TBD by implementer; record invocation in PROGRESS_LOG; prefer `scripts/` not a second console entry unless useful

---

## Coherence summary (Bar A → Bar B)

| Dimension | 1.2.0 (Bar A) | 1.3.0 (Bar B) |
| --- | --- | --- |
| Authority core | Labels, policy, broker, HMAC intents, url_guard | Unchanged + HostGate fail-closed |
| SSRF depth | Literal IP / scheme / userinfo | + resolve-pin + in-repo HTTP proxy |
| Secrets | Inline bytes in examples | SecretProvider Env/File |
| Audit | Local JSONL hash chain | + AuditShipper protocol/export |
| Multi-process consume | Memory + SQLite | + optional Redis |
| Intent crypto | HMAC required for enterprise | HMAC + optional Ed25519 |
| Rate/spend | Doc residual only | Broker hook when configured |
| Claims | No FedRAMP / no zero residual | Same — reinforced in HOST_HARDENING |

---

## Verdict rationale

**PASS** — plan law matches sealed 1.2.0 integrity: non-goals prevent overclaim; done predicate lists concrete modules/tests; release_gate + ASR=0 ON / ASR↑ OFF remain the prove-it bar; doc set is enumerated; export/CLI additions are bounded. Implementers must treat doc coupling and placeholder/claim discipline as first-class to avoid gate or honesty regressions.
