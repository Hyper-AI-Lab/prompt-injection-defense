# Slice 1 — Signed intents / IntentEnvelope

**Date:** 2026-10-07 JST  
**Repo:** `/workspace/prompt-injection-defense` @ `765a618` (`containment==1.1.0`)  
**Scope:** Bar A item — signed intents. Read-only audit of `IntentEnvelope` / plan signing vs enterprise needs.  
**Sources read:** `src/containment/plan.py`, `broker.py`, `actions.py`, `capability.py`, `policy.py`, `docs/THREAT_MODEL.md`, `DECISIONS.md`, plus cross-checks in `AUDIT_*.md`, `ARCHITECTURE.md`, `KIRILL_RESEARCH.md`, `tests/test_core_types.py`, `tests/test_broker.py`.

## VERDICT: ISSUES

Bar A requires **signed intents**. At SHA `765a618`, `IntentEnvelope` is a frozen field bag with **no cryptographic binding**, is **unused by the broker/policy control plane**, and `Plan` is likewise unsigned. Structural plan-step / task_id / expiry checks exist, and capability tokens use HMAC — but those do not satisfy “signed intents.” Not BLOCKED: evidence is complete and the gap is intentional for 1.x (now in scope for enterprise harden).

---

## Evidence (paths)

| Claim | Path / locus |
| --- | --- |
| Docstring admits no crypto | `src/containment/plan.py:9–14` — “fields only in 1.x; no crypto binding”; “Cryptographic intent signing remains out of scope for 1.x” |
| Intent fields only | `plan.py:17–22` — `task_id`, `tenant`, `user`, `scope`, `risk_budget`, `principal_authenticated`; **no** `mac`/`signature`/`key_id`/`nonce`/`issued_at`/`alg` |
| Plan unsigned | `plan.py:59–70` — frozen steps/capabilities/allowlists/limits/`expiry_unix`; no signature fields |
| Broker never takes IntentEnvelope | `broker.py:110–119` — `secure_execute(..., plan: Plan, principal_authenticated: bool = True, ...)`; no `intent=` param |
| Auth is caller bool | `broker.py:115`, `195`; `policy.py:84`, `99` — loose `principal_authenticated` default **True**, not derived from a verified envelope |
| task_id string match only | `policy.py:86–91` — `action.task_id != plan.task_id` → `task_mismatch`; no intent hash |
| Plan step structural bind (M1) | `broker.py:168–189` — `plan_step_unknown` / `plan_step_tool_mismatch` |
| Plan expiry structural (M4) | `broker.py:158–166` — `plan_expired` |
| Capability HMAC ≠ intent signing | `capability.py:29–105` — HMAC-SHA256 over `token_id\|tool\|resources_json\|expiry`; **not** task/tenant/user/scope/plan_step/intent |
| IntentEnvelope dead at runtime | Only refs: `plan.py`, `__init__.py` export, `tests/test_core_types.py:63–94`. **Zero** uses in `broker`/`policy`/`actions` call paths |
| Threat model assumes signed intent | `docs/THREAT_MODEL.md:27` — trust zone “Operator / **signed** task intent \| trusted” |
| Architecture omits intent verify | `docs/ARCHITECTURE.md:19–25` — broker pipeline: tool/schema/policy/approval/capability/audit; no intent verify step |
| Vision sketch requires signed envelope | `KIRILL_RESEARCH.md:150` — “[Intent & identity envelope] ---- **signed** task ID, tenant, user, scope, risk budget” |
| 1.x deferred crypto | `AUDIT_HARDEN_PLAN.md:33` — non-goal “IntentEnvelope cryptography”; `AUDIT_PLAN_VS_CODE.md:136,179` — “INTENTIONALLY DEFERRED”; `AUDIT_CODE_FINDINGS.md:170–174` (I1) |
| DECISIONS.md | No entry adopting intent/plan crypto; Stage-1/detector and limits decisions only — confirms signing never landed |
| Version | `pyproject.toml` `version = "1.1.0"`; docstring already updated from “v0.1” wording but still “no crypto” |

---

## Gaps vs Bar A signed intents

1. **No signature scheme on `IntentEnvelope`** — Bar A “signed intents” unmet; type is “signed-**style**” naming only.
2. **No verify locus in the reference monitor** — nothing in `ToolBroker.secure_execute` / `PolicyEngine.evaluate` verifies an intent MAC/signature before mint.
3. **Envelope not wired into authorization** — tenant/user/scope/risk_budget never constrain plan capabilities or proposed actions; `scope` is unenforced.
4. **`principal_authenticated` is forgeable metadata** — default-True kwarg; envelope flag unused; no binding to real authn.
5. **`Plan` authenticity gap** — immutable ≠ authentic; in-process attacker (or confused host) can construct any `Plan` the broker will honor.
6. **Broken trust-model promise** — THREAT_MODEL lists signed task intent as the trusted zone; implementation does not deliver crypto proof of that zone.
7. **Incomplete binding chain** — Capability MAC does not bind `task_id`, `plan_step`, intent digest, tenant, or approved_* sets; replay/substitution across tasks is out of MAC scope.
8. **No enterprise key/ops surface** — no `key_id`, alg negotiation, rotation, multi-tenant public keys, or fail-closed “unsigned intent denied” mode.
9. **No issued-at / intent-level expiry / nonce** — Plan has `expiry_unix`; IntentEnvelope has neither freshness nor anti-replay fields.
10. **Docs/decision lag** — AUDIT still lists intent crypto as 1.x non-goal; Bar A / enterprise harden needs an explicit DECISIONS adopt + threat-model residual update once shipped.

---

## Proven issues (complete list)

| ID | Severity (enterprise) | Issue |
| --- | --- | --- |
| SI-1 | **High** | `IntentEnvelope` has no cryptographic fields or verify API (`plan.py:9–40`). |
| SI-2 | **High** | Broker/policy never accept or require a verified intent (`broker.py`, `policy.py`). |
| SI-3 | **High** | Threat-model “signed task intent” trust zone is aspirational, not enforced (`THREAT_MODEL.md:27` vs code). |
| SI-4 | **High** | `principal_authenticated: bool = True` is caller-asserted; fails open to “authenticated” if omitted (`broker.py:115`, `policy.py:84`). |
| SI-5 | **Med** | `IntentEnvelope.scope` / `tenant` / `user` / `risk_budget` unused by policy predicates and broker gates. |
| SI-6 | **Med** | `Plan` unsigned; only structural checks (non-empty steps, tools ⊆ capabilities, step bind, expiry). |
| SI-7 | **Med** | Capability HMAC payload omits task/intent/plan_step (`capability.py:_mac`) — orthogonal to intent signing and insufficient as a substitute. |
| SI-8 | **Med** | No intent freshness: missing `issued_at`, intent `expiry`, `nonce`/`jti` on envelope. |
| SI-9 | **Low** | IntentEnvelope is export + unit-test only (scaffold / vision gap); hosts may think importing it equals control. |
| SI-10 | **Low** | Doc/decision debt: AUDIT non-goals still defer crypto while Bar A demands it; DECISIONS has no adopt entry. |

No silent “verify always returns True” stub was found — signing simply **does not exist**. That is cleaner than a fake verifier, but still fails Bar A.

---

## Surgical harden proposals (no gold-plate)

### Algorithm options

| Option | Fit | Notes |
| --- | --- | --- |
| **A. HMAC-SHA256** (prefer for 1.x→enterprise incremental) | Matches existing `CapabilityMinter` (`capability.py`); stdlib only; shared secret per deployment | Good for single-trust-domain brokers; secret distribution = trust boundary |
| **B. Ed25519** (prefer when operator ≠ broker process) | Asymmetric: planner/operator signs, broker verifies with public key; multi-tenant `key_id` map | Needs `cryptography` (or PyNaCl) optional extra; better audit story and key separation |

Recommendation: ship **HMAC first** behind `IntentSigner` / `IntentVerifier` with the same canonical-encoding discipline as capability MAC (JSON array / sorted keys, `hmac.compare_digest`); add **Ed25519** as `alg=ed25519` without changing the bound field set. Do not invent a third alg in the first PR.

### What to bind (canonical payload)

Stable, order-independent encoding of at least:

1. `alg`, `key_id`
2. `task_id`, `tenant`, `user`
3. `scope` (sorted tuple/list)
4. `risk_budget`
5. `principal_authenticated`
6. `issued_at_unix`, `expiry_unix`
7. `nonce` (or `jti`) — unique per intent
8. Optional but strongly recommended for Bar A completeness: **`plan_hash`** = hash of canonical Plan (steps, capabilities, approved_*, transaction_limit, plan.expiry_unix) so intent commits to the exact capability set

Separate **Plan signature** (same alg family) is acceptable instead of embedding `plan_hash` in the intent, but then broker must verify **both** and check `plan.task_id == intent.task_id`.

Also extend capability mint MAC (small follow-on, same PR or immediate next) to include `task_id` + `plan_step` + `intent_digest` so minted tokens cannot be replayed across tasks.

### Verify locus

1. **Primary (fail-closed enterprise mode):** start of `ToolBroker.secure_execute` **before** schema/policy/mint — or a single `attach_intent(intent, plan) -> VerifiedSession` called once when the plan is committed, then `secure_execute` requires a live `VerifiedSession`.
2. Checks at verify: signature valid; `now <= expiry`; `plan.task_id == intent.task_id`; `plan.capabilities ⊆ intent.scope`; if `plan_hash` present, recompute and match; reject missing/unsigned intent when `require_signed_intent=True` (default True for enterprise profile).
3. **Do not** verify only in the host app outside the library — Bar A is a library control; the reference monitor must own the gate.
4. **Do not** put verify inside detectors — detectors never authorize (`ARCHITECTURE.md` / THREAT_MODEL).
5. Propagate verified `tenant`/`user` into audit `TraceEvent.detail` for forensics; keep secrets/MACs out of logs (log `key_id` + intent digest only).

### Minimal API sketch (implementation later — not in this swarm)

- `SignedIntent(envelope: IntentEnvelope, issued_at, expiry_unix, nonce, alg, key_id, signature, plan_hash: str | None)`
- `IntentSigner.sign(...)` / `IntentVerifier.verify(signed, *, plan, now) -> IntentEnvelope`
- `ToolBroker(..., require_signed_intent: bool = False)` → enterprise profile sets `True`
- Tests: tamper field → deny; expired → deny; scope subset fail → deny; unsigned with require → deny; capability still one-use

### Explicit non-goals for the surgical PR

- Full PKI / certificate chain
- Cross-language JWT stack (optional later; raw HMAC/Ed25519 payload is enough)
- Replacing capability one-use store (slice 2)
- Claiming adaptive-injection immunity

---

## Ranked backlog feed for `ENTERPRISE_HARDEN_PLAN.md`

1. **P0** — Add signed IntentEnvelope (HMAC) + broker verify locus + `require_signed_intent` (SI-1, SI-2, SI-3, SI-4).
2. **P0** — Enforce `plan.capabilities ⊆ intent.scope` and task_id bind to verified intent (SI-5).
3. **P1** — Bind capability MAC to `task_id`/`plan_step`/`intent_digest` (SI-7).
4. **P1** — Plan authenticity: `plan_hash` in intent or separate Plan MAC (SI-6, SI-8).
5. **P2** — Ed25519 alg + `key_id` map for multi-tenant operators.
6. **P2** — DECISIONS adopt entry + THREAT_MODEL residual rewrite (“signed intent required when enterprise profile on”) (SI-10).

---

## Summary

**VERDICT: ISSUES** — structural plan binding and capability HMAC exist; **cryptographic signed intents do not**. `IntentEnvelope` is an unused, unsigned dataclass relative to Bar A. Harden by adding HMAC (then optional Ed25519), binding the fields above, and verifying at the broker/plan-attach locus before capability mint.
