# Slice B — Broker / host / enterprise integrity (Bar B / 1.3.0)

**Slice:** B (HostGate · enterprise · secrets · fail-open hunt)  
**Tree:** `/workspace/prompt-injection-defense` @ containment **1.3.0**  
**Law:** `LEFTOVERS_HARDEN_PLAN.md` done-predicate §3–4, §8, §10 + HostGate step 3/10  
**Mode:** analysis only (no product code edits)  
**Sources read:** `broker.py`, `host/{checklist,secrets,audit_ship,rate_limit,__init__}.py`, `enterprise.py`, `tests/test_broker_host_gate.py`, `test_enterprise_compose.py`, `test_broker_rate_limit.py`, `docs/HOST_HARDENING.md`, plan done-predicate  
**Empirical:** `.venv/bin/python` gate-order probe (HostGate → intent → rate → mint)

## Verdict: **ISSUES**

HostGate order and `build_enterprise_host` fail-closed are sound. Three integrity gaps are proven: (1) done-predicate names `EgressProvider` but checklist only holds `egress_configured: bool` (declaration, not a provider); (2) HostGate treats `SecretProvider` / `AuditShipper` as presence-only and never binds or invokes them on the execute path; (3) enterprise profile does not require a rate gate (optional by plan wording, but leaves LLM10 residual open under “enterprise”).

---

## 1. HostGate order vs signed intent / rate / mint — **PASS**

`ToolBroker.secure_execute` order (proven in source + runtime):

| # | Gate | Location | Before mint? |
|---|------|----------|--------------|
| 0a | HostGate (`require_host_gate` / enterprise) | `broker.py` L135–153 | Yes (first) |
| 0 | Signed intent | L155–183 | Yes |
| 1–7 | known_tools → schema → labels → plan → policy → detector → limits → audit → deny → human/MFA | L185–320 | Yes |
| 7b | RateLimitGate (if set) on `PRIVILEGED_SINKS` | L322–335 | Yes |
| 8 | Capability mint (+ optional executor) | L337–350 | — |

Empirical (`.venv/bin/python`):

- enterprise, no checklist → `host_gate_required` (never reaches intent)
- complete checklist, no intent → `signed_intent_required`
- valid intent + `TokenBucketRateLimit(0,1)` → first mint OK, second → `rate_limit_exceeded`

So HostGate cannot be skipped by presenting a signed intent, and rate cannot mint after budget exhaustion. Correct.

`enterprise_profile=True` implications (`broker.py` L117–121):

- forces `require_signed_intent=True`
- forces `require_host_gate=True`
- does **not** force `rate_limit`, `intent_signer` at construct, or egress env/pin

Missing `intent_signer` under enterprise still fail-closes at execute (`signed_intent_required` / `intent_signer not configured`). Construct-time omission is OK.

---

## 2. HostChecklist.ok vs done-predicate (`EgressProvider` vs bool) — **ISSUE**

**Plan done-predicate §3 (verbatim):** checklist must pass with `isolation_declared`, `SecretProvider`, **`EgressProvider` or proxy URL**, `AuditShipper`.

**Code (`host/checklist.py`):**

```python
isolation_declared: bool
secret_provider: SecretProvider | None
egress_configured: bool          # ← not EgressProvider
audit_shipper: AuditShipper | None
```

There is **no** `EgressProvider` Protocol/type anywhere under `src/containment`. Docstring admits: “`egress_configured` is a bool in this step…”. `docs/HOST_HARDENING.md` documents the bool.

`build_enterprise_host` maps `egress_configured or non-empty proxy_url` → checklist `egress_configured=True` (`enterprise.py` L100–117). Factory fail-closes if neither is set (`ValueError` / tests `test_rejects_missing_egress`). Good for composition.

**Proven lie path:** `HostChecklist(..., egress_configured=True, ...)` with no proxy, no pin, no provider → `ok() is True`, `failures() == ()`. HostGate will mint. Same honor-system pattern as `isolation_declared` (docs call lying “operator fraud”). Relative to plan wording that named an **`EgressProvider`**, the bool is a weaker semantic — declaration theater, not a held egress object the broker can call.

**Severity:** medium (plan naming / integrity). Documented residual; not a silent bypass of HostGate itself.

---

## 3. `build_enterprise_host` fail-closed — **PASS**

Rejects before returning a broker when:

- no secret backend (`secret_provider` / `secrets_dir` / `secrets_env_prefix`) — exclusive-or
- `isolation_declared` is False
- neither `egress_configured` nor non-empty `proxy_url`
- (redundant) `checklist.ok()` false after construction

Sets `enterprise_profile=True`, wires `host_checklist`, loads capability + intent secrets via `SecretProvider.get_bytes`, builds HMAC `IntentSigner` unless caller passes one. Tests: `test_rejects_missing_*`, `test_build_enterprise_host_checklist_and_gate`, `test_proxy_url_sets_egress_and_hint`.

No fail-open in the factory path for the checklist fields it owns.

---

## 4. SecretProvider used correctly — **ISSUE** (presence vs use)

**Implementations (`host/secrets.py`) — PASS:**

- `EnvSecretProvider`: missing/empty env → `SecretError`
- `FileSecretProvider`: basename-only names, resolve + `relative_to` traversal reject, missing/empty file → `SecretError`

**`build_enterprise_host` — PASS:** capability/intent bytes come only from the provider (no hardcoded production HMAC).

**HostGate / checklist — ISSUE:**

- `ok()` only checks `secret_provider is not None`
- `ToolBroker.secure_execute` never calls `host_checklist.secret_provider.get_bytes`
- Manual wiring can pass HostGate with a live `SecretProvider` while `CapabilityMinter(secret=b"...")` / intent signer use **independent** inline material

Proven shape: enterprise HostGate tests use `FileSecretProvider` on the checklist **and** `CapabilityMinter(secret=b"x"*32)` separately (`test_broker_host_gate.py`). Checklist presence ≠ secret use. Integrators who skip `build_enterprise_host` can satisfy HostGate while still embedding HMAC in source.

Same pattern for **AuditShipper**: presence required under HostGate; broker/`AuditLog` never call `ship_file`. Docs correctly say host must schedule export — so checklist only proves “you held a shipper object,” not that audit left the box. Plan §8 “file/HMAC export helper” is covered as `FileAuditShipper` + AuditLog SHA-256 chain (slice A note); no separate HMAC-MAC shipper — soft naming, not re-raised as a hard bug here.

---

## 5. Fail-open / residual paths (catalog)

| Path | Fail-open? | Assessment |
|------|------------|------------|
| `require_host_gate=False` / non-enterprise skips checklist | Yes, intentional | Default agent profile; tests assert skip |
| `egress_configured=True` without proxy/pin | Declaration lie | Documented residual; **ISSUE vs `EgressProvider` wording** |
| `isolation_declared=True` without sandbox | Declaration lie | Documented residual (HOST_HARDENING) |
| SecretProvider on checklist unused by minter/signer | Yes on manual `ToolBroker` | **ISSUE**; factory path OK |
| AuditShipper never auto-invoked | Presence theater | Documented; host-owned |
| `enterprise_profile` with `rate_limit=None` | Unlimited privileged mint rate | Plan §10 is “hook … when configured”; factory leaves optional. Empirical: enterprise without rate still mints. Residual LLM10 stays open unless host passes a gate |
| Rate only on `PRIVILEGED_SINKS` (not `social.publish`) | By design | `social.publish` is label-required egress, not privileged sink set |
| Rate after human approval, before mint | Not fail-open | Correct: budget charged only on path that would mint |

No evidence of: HostGate after mint; intent skipping HostGate; enterprise execute with incomplete checklist; factory returning incomplete checklist.

---

## 6. What matched the vision

- Fail-closed HostGate before mint under enterprise / `require_host_gate`
- Signed intents forced with enterprise
- Rate hook before mint on privileged sinks when configured
- `build_enterprise_host` composition + docs acknowledging library vs host
- Secret backends that refuse empty/missing material

## 7. Recommended fixes (for parent audit plan — not applied here)

1. Replace or augment `egress_configured: bool` with a held egress handle (e.g. `proxy_url: str | None` and/or `EgressProvider` Protocol / pinned-client flag) so `ok()` cannot pass without a concrete egress object — aligns checklist with done-predicate wording.
2. On HostGate (or enterprise factory only, if intentional): require that capability/intent secrets were loaded from `checklist.secret_provider` (e.g. minter secret fingerprint / refuse independent inline secret when `require_host_gate`).
3. Optionally auto-`ship_file` on audit rotate, or document checklist field as “shipper *configured*” only (already partly true) and rename to avoid implying shipping happened.
4. Decide product stance: either force a default `RateLimitGate` under `enterprise_profile`, or keep optional and state clearly that enterprise ≠ spend-capped.

---

## Evidence index

- Gate order source: `src/containment/broker.py` L135–350  
- Checklist: `src/containment/host/checklist.py`  
- Secrets: `src/containment/host/secrets.py`  
- Compose: `src/containment/enterprise.py` L68–158  
- Tests: `tests/test_broker_host_gate.py`, `test_enterprise_compose.py`, `test_broker_rate_limit.py`  
- Docs: `docs/HOST_HARDENING.md` §§ HostChecklist / SecretProvider / residuals  
- Runtime probe: HostGate → intent → rate sequence; `lie_ok True`; `enterprise_no_rate` mints  

**End slice B.**
