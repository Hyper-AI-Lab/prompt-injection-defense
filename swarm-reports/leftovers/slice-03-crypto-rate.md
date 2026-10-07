# Slice 03 — Ed25519 intents + Redis consume store + rate/spend

**Repo:** `/workspace/prompt-injection-defense`  
**Slice:** Plan steps 7–9 (`LEFTOVERS_HARDEN_PLAN.md`)  
**Date:** 2026-10-07 JST  
**Scope:** Coverage only — no product code changes

## Verdict

**PASS**

Steps 7–9 fit the existing surfaces without architectural blockers. HMAC intent path, `CapabilityConsumeStore` Protocol, and broker `secure_execute` already have the right seams. Work is additive: optional alg/signer, optional Redis backend behind an extra, optional rate hook on the broker. Minor type/wiring widenings required (listed below); none invalidate the plan law.

---

## Current HMAC-only surface

### Intents (`src/containment/intent.py`)

| Piece | Behavior |
|-------|----------|
| `SignedIntent` | Frozen dataclass; `alg: str = "hmac-sha256"`, `key_id`, `mac` (hex), bound envelope + timestamps + nonce + `plan_hash` |
| `IntentSigner` | Constructed with raw `secret: bytes`; `sign` / `verify` |
| Verify gate | `if signed.alg != "hmac-sha256": raise IntentError` — hard reject of any other alg |
| MAC payload | Canonical JSON over alg, key_id, envelope fields, issued/expiry (6 dp), nonce, plan_hash → HMAC-SHA256 hex |
| Tests | `tests/test_intent.py` — round-trip, tamper, expiry, broker `require_signed_intent` |

### Capabilities (out of Ed25519 scope; stay HMAC)

- `CapabilityMinter` / `CapabilityToken` remain HMAC-SHA256 over `token_id|tool|resources_json|expiry` (`capability.py`).
- Plan step 7 is **intent** signer only; do not dual-alg capability tokens in 1.3.0.

### Consume ledger (`capability_store.py`)

- Protocol: `CapabilityConsumeStore.try_consume(token_id, *, expiry_unix) -> bool`
- Backends today: `MemoryConsumeStore`, `SqliteConsumeStore` (UNIQUE insert = first wins)
- Wired via `CapabilityMinter(..., store=...)`; default memory
- Tests: `tests/test_capability_store.py`

### Broker (`broker.py`)

- `__init__`: `require_signed_intent`, `intent_signer: IntentSigner | None`, `enterprise_profile`
- Gate **#0** in `secure_execute`: if required → require `intent` + `intent_signer` → `intent_signer.verify(intent, plan=plan)` → `IntentError` → deny `signed_intent_invalid`
- No rate/spend hook today
- No host gate yet (steps 2–3); irrelevant to this slice except composition later

### Packaging (`pyproject.toml`)

- Version `1.2.0`; extras: `dev`, `ml`, `stackone` only — **no `[redis]`**, no crypto extra
- Core deps: `pyyaml`, `jsonschema` only (stdlib `hmac`/`hashlib` for current intents)

---

## How to add Ed25519 without breaking HMAC path

### Design (additive)

1. **Keep `SignedIntent` shape.** Reuse `alg`, `key_id`, `mac` (for Ed25519: hex or base64url of signature bytes; pick **hex** to match HMAC field naming, or document `sig` synonym — prefer keep field name `mac` as opaque authenticator to avoid dataclass churn).
2. **Do not mutate `IntentSigner` into a dual-alg monster.** Add:
   - `Ed25519IntentSigner` (sign with private key, verify with public key), same `sign(...)` / `verify(...)` method signatures and same canonical **payload bytes** as `_mac` JSON (swap HMAC for Ed25519 sign/verify over that UTF-8 blob).
   - Or extract shared `_intent_payload_bytes(signed) -> bytes` used by both.
3. **Alg constants:** `"hmac-sha256"` (existing) and `"ed25519"`.
4. **HMAC path unchanged:** `IntentSigner.verify` continues to reject non-HMAC algs. Ed25519 class rejects non-`ed25519`. Cross-alg verify of an HMAC-signed envelope with Ed25519 verifier → fail closed.
5. **Broker typing widen (smallest break-free change):**
   - Introduce `@runtime_checkable` Protocol `IntentVerifier` with `verify(signed, *, plan, now=...) -> IntentEnvelope` (and optionally `sign` for hosts that mint).
   - Change `ToolBroker.intent_signer` type to `IntentVerifier | None` (or union `IntentSigner | Ed25519IntentSigner | None`).
   - Runtime still calls `.verify(...)` only — no HMAC-specific branches in broker.
6. **Key material:** Ed25519 uses asymmetric keys; wire later via `SecretProvider` (step 2) loading PEM/raw 32-byte seeds — not inline secrets in examples. Signing host holds private key; broker verify can hold **public-only** verifier (preferred enterprise shape).
7. **Dependency:** prefer optional extra e.g. `[crypto]` → `cryptography>=42` (Ed25519 hazmat). Avoid pulling crypto into core wheel. Lazy import inside `Ed25519IntentSigner.__init__` with clear `IntentError` if missing. Stdlib has no Ed25519 sign API on 3.12.
8. **Tests:**
   - Round-trip Ed25519 sign/verify
   - Tamper fails
   - HMAC-signed intent rejected by Ed25519 verifier and vice versa
   - Broker with `Ed25519IntentSigner` + `require_signed_intent` allow/deny parity with existing HMAC broker tests
   - Existing `tests/test_intent.py` must stay green with zero behavior change for `IntentSigner`

### Explicit non-break rules

- Default examples and `enterprise_profile` may keep HMAC; Ed25519 is opt-in by constructing the Ed25519 signer.
- Do not change default `SignedIntent.alg` default away from `"hmac-sha256"`.
- Do not require `[crypto]` for base install / release_gate core tests.

---

## RedisConsumeStore shape + skip-if-no-redis tests

### Shape (match Protocol exactly)

```text
CapabilityConsumeStore
  try_consume(self, token_id: str, *, expiry_unix: float) -> bool
```

**`RedisConsumeStore`** (new module e.g. `containment.capability_store_redis` or behind lazy import in `capability_store.py` to keep core import free of redis):

| Concern | Recommendation |
|---------|----------------|
| Atomic first-wins | `SET containment:cap:{token_id} 1 NX EX <ttl_sec>` — success ⇒ True; key exists ⇒ False |
| TTL | `ttl_sec = max(1, ceil(expiry_unix - now))` so Redis GC aligns with token expiry; pass `now` injectable for tests |
| Connection | `__init__(self, url: str | None = None, *, client=None)` — url from env/`SecretProvider` later; inject fake client in unit tests |
| Errors | Connection failure: fail **closed** for consume (raise or return False consistently — prefer raise `CapabilityError`/`OSError` wrapped so broker does not treat outage as “already used”; document choice). Plan: production-grade → **fail closed** (deny second path is wrong; deny execute on store error is right) |
| Optional purge | Not required by Protocol; skip `purge_expired` unless useful |

### Packaging

```toml
[project.optional-dependencies]
redis = ["redis>=5.0"]
```

Core install must not require redis. Export `RedisConsumeStore` from package `__init__` only if import-safe (lazy), or document `from containment.capability_store_redis import RedisConsumeStore`.

### Skip-if-no-redis test pattern

Mirror hermetic optional-extra style (same spirit as ml/stackone skips):

```python
redis = pytest.importorskip("redis")  # module missing → skip

@pytest.fixture
def redis_url():
    url = os.environ.get("CONTAINMENT_REDIS_URL", "redis://127.0.0.1:6379/15")
    try:
        client = redis.Redis.from_url(url, socket_connect_timeout=0.25)
        client.ping()
    except Exception as exc:
        pytest.skip(f"redis unavailable: {exc}")
    return url

def test_redis_try_consume_unique(redis_url):
    store = RedisConsumeStore(url=redis_url)
    assert store.try_consume("t", expiry_unix=time.time() + 60) is True
    assert store.try_consume("t", expiry_unix=time.time() + 60) is False
```

Also add a **unit** test with a fake/in-memory redis mock (fakeredis optional, or hand-rolled client stub implementing `set(..., nx=True, ex=...)`) so CI without Redis still covers logic when `redis` package is installed under `[redis]` / dev. Minimum for plan: “tests skip if redis unavailable” with **real skip reasons** (`importorskip` message + ping skip).

Wire through minter like sqlite:

```python
minter = CapabilityMinter(secret=..., store=RedisConsumeStore(url=...))
```

Cross-process semantics = Redis NX; document vs Sqlite file share.

---

## RateLimitGate placement in broker (smallest hook)

### Plan alignment

- Step 2 introduces `RateLimitGate` Protocol + `TokenBucketRateLimit` in `containment.host` (not yet on tree — expected when step 2 runs).
- Step 9: enforce when configured on privileged path (LLM10 residual).

### Protocol shape (expected; confirm against step-2 delivery)

```text
RateLimitGate
  allow(self, *, tool: str, cost: float = 1.0) -> bool
  # or check() raising / returning reason — prefer bool + broker maps to deny
```

Spend variant: `cost` from action args (e.g. transaction amount) or fixed per-tool weights; TokenBucket can track tokens as “spend units.”

### Smallest broker hook

1. Add optional ctor arg only:
   - `rate_limit: RateLimitGate | None = None`
2. Call site: **after** policy allow / fail-closed detector / limits checks, **before** human approval mint — i.e. after block that ends at “5) Audit append” / deny raise, and **before** “7) Human approval” **or** immediately before “8) Mint”.

**Recommended placement: immediately before step 8 (mint), after require_human MFA succeeds.**

Rationale:

- Denied / schema / label failures never burn rate budget.
- Human-denied MFA never burns budget.
- Privileged allow that reaches mint is exactly the LLM10 residual (tool/model spend).
- One call site; no need to sprinkle checks earlier.

```text
# after require_human / MFA pass
if self.rate_limit is not None and action.tool in PRIVILEGED_SINKS:  # or all tools if configured
    if not self.rate_limit.allow(tool=action.tool, cost=_spend_hint(action)):
        decision = PolicyDecision(effect="deny", rule_id="rate_limit", reason=...)
        self.audit.append_decision(...)
        raise SecurityViolation(...)
# then mint
```

Narrowest default: enforce only when `rate_limit` is not None; apply to `PRIVILEGED_SINKS` (already imported) so read-only tools stay unbounded unless host passes a gate that applies globally.

3. Do **not** require enterprise_profile for the hook — optional composition; `build_enterprise_host()` (step 10) can attach a default bucket.
4. Tests: mock gate returning False → deny `rate_limit`; True → mint; `None` → behavior identical to 1.2.0.

### What not to do

- No global monkeypatch of executors
- No async queue inside broker
- No Redis-backed rate store in step 9 unless already available — in-process `TokenBucketRateLimit` is enough; Redis rate can be a later backend implementing the same Protocol

---

## Step mapping (7–9)

| Plan step | Coverage conclusion |
|-----------|---------------------|
| 7 Ed25519 intents | Feasible via parallel signer + Protocol widen; HMAC untouched |
| 8 Redis consume store | Feasible via Protocol + `[redis]` extra + importorskip/ping skip |
| 9 Rate/spend on broker | Feasible via optional `rate_limit` before mint; depends on step-2 Protocol existing first (law order already correct) |

## Dependencies / ordering note for executor

Execute step 2 (`RateLimitGate` Protocol) before step 9. Steps 7 and 8 are independent of each other and of the egress proxy. Step 7 should land after HMAC tests remain the regression baseline.

## Risks (non-blocking)

1. Broker currently annotates `IntentSigner` concretely — widen before accepting Ed25519 instance in typed hosts.
2. Fail-mode for Redis outage must be documented (fail closed on execute, not “treat as consumed”).
3. Ed25519 extra must not become a hard dependency of `release_gate` core path.

---

**Artifact:** `/workspace/prompt-injection-defense/swarm-reports/leftovers/slice-03-crypto-rate.md`  
**Product code changed:** none
