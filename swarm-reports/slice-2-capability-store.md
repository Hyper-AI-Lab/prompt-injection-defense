# Slice 2 — Multi-process capability store interface

**Date:** 2026-10-07 JST  
**Repo:** `/workspace/prompt-injection-defense` @ `765a618ef258130d9523a50fc39e151bc74009e7`  
**Bar A item:** multi-process capability store interface  
**Scope:** read-only audit of `CapabilityMinter` + broker usage; no code edits.

## VERDICT: ISSUES

Single-process HMAC one-use mint/verify works and is tested. There is **no** pluggable consume-store interface; `_consumed` is process-local memory only. That blocks enterprise multi-worker one-use guarantees without a surgical refactor. Not BLOCKED: library v1 behavior is coherent for in-process brokers; Bar A needs the interface + default in-memory + optional shared backends.

---

## Evidence

### CapabilityMinter (`src/containment/capability.py`)

| Line | Fact |
| --- | --- |
| 32–34 | `__init__` keeps `self._secret` and `self._consumed: set[str] = set()` — private, in-memory, no lock |
| 36–63 | `one_use` mints `CapabilityToken` (token_id, tool, resources, expiry_unix, mac); does **not** register id in `_consumed` |
| 65–90 | `verify` checks `token_id in self._consumed` → MAC → tool → resources → expiry → **then** `self._consumed.add(token_id)` |
| 77–78, 90 | One-use semantics entirely depend on this set; second verify raises `CapabilityError("capability already used")` |
| 92–105 | MAC is HMAC-SHA256 over `token_id\|tool\|json(resources)\|expiry`; secret defaults to `os.urandom(32)` if unset |

### Broker usage (`src/containment/broker.py`)

| Line | Fact |
| --- | --- |
| 14, 95, 104 | `ToolBroker` takes a concrete `CapabilityMinter`, stores as `self.minter` — no Protocol / store injection |
| 257–263 | After allow / approval, mints via `self.minter.one_use(tool=..., resources=_resource_hints(action), expiry_seconds=...)` |
| 265–268 | **Only if** `self.executor is not None`: calls `self.minter.verify(...)` then `executor(action, token)` |
| 270 | Returns `BrokerResult(..., capability=token, ...)`. With no executor, token is **minted but unconsumed** (caller must verify) |

Confirmed by `tests/test_broker.py::test_allow_fetch_mints_capability` (lines 149–154): comment “Token not yet consumed when no executor is wired,” then explicit `broker.minter.verify(...)`.

### Tests (`tests/test_capability_audit.py`)

- `test_one_use_second_verify_fails` — same-process second use fails (happy path for `_consumed`).
- Tool mismatch / expiry / tampered MAC covered.
- MAC resource encoding collision fixed (JSON array) — orthogonal to store.
- **No** test for cross-process, shared store, concurrent consume, or TTL eviction of `_consumed`.

### Prior audits (consistent)

- `AUDIT_CODE_FINDINGS.md` **I3**: “Capability consume set is process-local memory… Multi-worker deployments do not share one-use state.”
- `AUDIT_PLAN_VS_CODE.md` step 4 caveat: “Consumed-token set is process-local memory only (`capability.py:33`) — acceptable for library v1, not multi-process revocation.”

### Dependencies (`pyproject.toml`)

Runtime deps: `pyyaml`, `jsonschema` only. No `redis`. Stdlib `sqlite3` available. Detector code already uses `typing.Protocol` (`detectors/base.py`) — pattern exists in-tree.

---

## Gaps vs Bar A

1. **No store interface** — Bar A asks for a multi-process capability store *interface*. Today consume state is an opaque private `set` inside `CapabilityMinter`.
2. **Multi-worker replay** — Worker A mints + verifies (consumes locally). Worker B with the same HMAC secret and a copied/forged token can `verify` successfully because B’s `_consumed` is empty. HMAC authenticity ≠ distributed one-use.
3. **Secret without shared consume** — Sharing `CapabilityMinter(secret=...)` across processes (README / `docs/AGENT_INSTALL.md` pattern) is necessary for MAC verify but **insufficient** for one-use without a shared consume ledger.
4. **Check-then-act race (threads)** — Even in one process, `in` then `add` on an unlocked `set` is not atomic under concurrent `verify` of the same `token_id` (two threads can both pass the membership check).
5. **Unbounded growth** — `_consumed` never evicts expired ids → long-lived broker memory growth (ops concern, secondary to correctness).
6. **Broker coupling** — `ToolBroker` hard-types `CapabilityMinter`; cannot inject a store-backed minter without changing the type or adding a Protocol that `CapabilityMinter` satisfies.
7. **Docs under-claim** — `docs/ARCHITECTURE.md` / `THREAT_MODEL.md` say “one-use” without stating process-local scope; enterprise readers may over-trust.

---

## Assessment: process-local `_consumed` vs enterprise multi-worker

| Deployment | One-use guarantee today? |
| --- | --- |
| Single process, sequential `verify` | Yes (tested) |
| Single process, concurrent threads | Weak — race on check/add |
| Multi-process / multi-worker same secret | **No** — each worker has its own set |
| Horizontally scaled API + shared executor | **No** — mint on one node, replay on another |

HMAC binding still prevents forging tool/resources/expiry without the secret. The missing property is **distributed consume-once**, which Bar A’s store interface is meant to supply.

Acceptable for library reference-monitor demos; **not** acceptable if enterprise docs claim multi-worker one-use without a shared store.

---

## Surgical interface proposal (no gold-plate)

Keep mint/MAC on `CapabilityMinter`; extract **only** consume bookkeeping behind a small Protocol. Default remains in-memory (zero new deps). Optional Redis/SQLite sketches stay behind extras or stdlib — **do not** add `redis` to default `dependencies`.

### 1) Protocol + default in-memory

```python
# sketch — capability_store.py (or bottom of capability.py)
from typing import Protocol, runtime_checkable
import threading
import time

@runtime_checkable
class CapabilityConsumeStore(Protocol):
    def try_consume(self, token_id: str, *, expiry_unix: float) -> bool:
        """Atomically mark token_id consumed.
        Return True if this call won (first consume), False if already used.
        Implementations may ignore expiry_unix or use it for TTL/GC.
        """
        ...

class InMemoryConsumeStore:
    """Process-local default; thread-safe; optional lazy GC of expired ids."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._consumed: dict[str, float] = {}  # token_id -> expiry_unix

    def try_consume(self, token_id: str, *, expiry_unix: float) -> bool:
        with self._lock:
            if token_id in self._consumed:
                return False
            self._consumed[token_id] = expiry_unix
            return True

    def purge_expired(self, now: float | None = None) -> int:
        stamp = time.time() if now is None else now
        with self._lock:
            dead = [k for k, exp in self._consumed.items() if stamp > exp]
            for k in dead:
                del self._consumed[k]
            return len(dead)
```

### 2) Wire into CapabilityMinter (minimal diff)

```python
class CapabilityMinter:
    def __init__(
        self,
        secret: bytes | None = None,
        *,
        store: CapabilityConsumeStore | None = None,
    ) -> None:
        self._secret = secret if secret is not None else os.urandom(32)
        self._store: CapabilityConsumeStore = store or InMemoryConsumeStore()

    def verify(self, token: CapabilityToken, *, tool: str, ...) -> None:
        # MAC / tool / resources / expiry checks first (fail closed without consume)
        ...
        if not self._store.try_consume(token.token_id, expiry_unix=token.expiry_unix):
            raise CapabilityError("capability already used")
```

**Ordering note:** Prefer validating MAC/expiry **before** consume so garbage tokens do not pollute the store; for shared stores use atomic `try_consume` only after crypto checks. Under concurrent identical valid tokens, only one `try_consume` wins.

### 3) Optional Redis sketch (extra, not default dep)

```python
# optional: containment[redis] or host-provided client
class RedisConsumeStore:
    """SET key NX + EX — atomic first-writer-wins across workers."""

    def __init__(self, client, *, key_prefix: str = "cap:used:") -> None:
        self._r = client
        self._prefix = key_prefix

    def try_consume(self, token_id: str, *, expiry_unix: float) -> bool:
        ttl = max(1, int(expiry_unix - time.time()) + 60)  # grace past token expiry
        # SET NX returns True if set, None/False if exists
        return bool(self._r.set(f"{self._prefix}{token_id}", "1", nx=True, ex=ttl))
```

Ship as documented snippet or `src/containment/stores/redis_consume.py` gated by `optional-dependencies.redis = ["redis>=5"]` — **not** imported from `__init__` by default.

### 4) Optional SQLite sketch (stdlib, no new dep)

```python
class SqliteConsumeStore:
    """Single-file / shared-FS workers; UNIQUE insert = first consume."""

    def __init__(self, path: str) -> None:
        import sqlite3
        self._path = path
        with sqlite3.connect(path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS consumed ("
                "token_id TEXT PRIMARY KEY, expiry_unix REAL NOT NULL)"
            )

    def try_consume(self, token_id: str, *, expiry_unix: float) -> bool:
        import sqlite3
        try:
            with sqlite3.connect(self._path) as db:
                db.execute(
                    "INSERT INTO consumed(token_id, expiry_unix) VALUES (?, ?)",
                    (token_id, expiry_unix),
                )
            return True
        except sqlite3.IntegrityError:
            return False
```

Caveat: network FS SQLite locking is fragile; prefer Redis for true multi-host. Fine for multi-process same-host or sticky local disk.

### 5) Broker / exports (tiny)

- Keep `ToolBroker.minter: CapabilityMinter` (or widen to a Protocol with `one_use` + `verify` only if needed).
- Document: multi-worker hosts **must** pass a shared `store` (and shared secret).
- Export `CapabilityConsumeStore`, `InMemoryConsumeStore` from `containment` / docs; Redis/SQLite as optional.

### 6) Tests to add (when implementing — not this swarm slice)

- In-memory: second `try_consume` False; thread barrier double-verify → one success.
- Sqlite temp path: two `CapabilityMinter` instances, shared store → second verify fails.
- Redis: skip-unless-extra / fakeredis.
- Broker with executor still consumes exactly once.

---

## Ranked harden backlog (feeds ENTERPRISE_HARDEN_PLAN)

1. **P0** — Introduce `CapabilityConsumeStore.try_consume` + `InMemoryConsumeStore` (thread-safe); migrate `_consumed` off the minter.  
2. **P0** — Document process-local default and multi-worker requirement (shared secret **and** shared store) in ARCHITECTURE / THREAT_MODEL / AGENT_INSTALL.  
3. **P1** — Stdlib `SqliteConsumeStore` for same-host multi-process without new deps.  
4. **P1** — Optional Redis `SET NX EX` backend behind extra; example in docs only if not shipping module yet.  
5. **P2** — Lazy purge / TTL on in-memory map keyed by `expiry_unix`.  
6. **P2** — Optional `CapabilityMinter`-shaped Protocol for broker typing (only if hosts need alternate minters).

---

## Out of scope this slice

- Code changes, dependency adds, Redis installs.  
- Intent signing, SSRF helpers, SBOM/CI, red-team fixtures, PIGuard (other slices).
