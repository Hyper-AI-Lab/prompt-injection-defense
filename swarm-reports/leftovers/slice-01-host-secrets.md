# Slice 01 — HostGate + SecretProvider + AuditShipper gaps

**Repo:** `/workspace/prompt-injection-defense`  
**Package:** containment **1.2.0**  
**Scope:** LEFTOVERS_HARDEN_PLAN.md steps **2–3**, **10** (and done-predicate items 3, 4, 8, 10, 11 as they bind those steps)  
**Mode:** analysis only — no product code changes  

## Verdict: ISSUES

Host residual controls exist only as **prose checklist** (AGENT_INSTALL §8 / THREAT_MODEL residuals). There is **no** `containment.host` module, **no** `SecretProvider` / `AuditShipper` / `HostChecklist` / `RateLimitGate` types, and **no** broker `require_host_gate` fail-closed path. Enterprise profile today only forces signed intents. Install/README examples still pass **inline raw HMAC secrets**. Steps 2–3 and 10 are entirely unimplemented relative to Bar B.

---

## What already exists

| Area | Status | Where |
| --- | --- | --- |
| Local append-only audit JSONL + hash chain | Present (tamper-*evidence*, not WORM/ship) | `src/containment/audit.py` `AuditLog` |
| Broker + capability mint / verify | Present | `broker.py`, `capability.py` |
| HMAC signed intents + `enterprise_profile` → `require_signed_intent` | Present | `intent.py`, `broker.py` `__init__` |
| Pluggable capability consume store | Present | `capability_store.py` (Memory/Sqlite) |
| Partial LLM10 (size caps) | Present | Stage0 / policy `max_bytes`; **not** rate/spend gate |
| Host residual **documentation** | Present (checklist only) | `docs/AGENT_INSTALL.md` §8; `docs/THREAT_MODEL.md` residual § |
| `containment.host` / HostGate APIs | **Absent** | no `host.py`; `__init__.py` exports omit host types |
| `build_enterprise_host()` / `HOST_HARDENING.md` | **Absent** | plan step 10 |

Evidence — enterprise today is signed-intent only:

```101:114:src/containment/broker.py
        require_signed_intent: bool = False,
        intent_signer: IntentSigner | None = None,
        enterprise_profile: bool = False,
    ) -> None:
        ...
        self.require_signed_intent = bool(require_signed_intent or enterprise_profile)
        self.intent_signer = intent_signer
        self.enterprise_profile = bool(enterprise_profile)
```

Evidence — secrets are raw `bytes`, no provider:

```34:41:src/containment/capability.py
    def __init__(
        self,
        secret: bytes | None = None,
        *,
        store: CapabilityConsumeStore | None = None,
    ) -> None:
        self._secret = secret if secret is not None else os.urandom(32)
```

```52:59:src/containment/intent.py
class IntentSigner:
    def __init__(self, secret: bytes, *, key_id: str = "default") -> None:
        if not secret:
            raise IntentError("secret must be non-empty")
        self._secret = secret
```

Evidence — audit is local file only; docstring denies WORM/shipping:

```20:26:src/containment/audit.py
class AuditLog:
    """Thread-safe append-only JSONL writer/reader for TraceEvent records.
    ...
    a filesystem writer can still truncate or replace the file (see
    ``docs/THREAT_MODEL.md``). Not WORM.
    """
```

Evidence — THREAT_MODEL residual still out-of-package for vault / WORM / rate:

> External WORM / signed log shipping remains out of scope for this package.  
> … Compromised signer secrets forge intents — keep secrets in a vault.  
> (`docs/THREAT_MODEL.md` residual §, lines ~52–61)

Evidence — AGENT_INSTALL §8 is checklist-only (isolation, egress, vault, WORM, HF review, rate/spend) with **no** typed APIs:

> This library is not a sandbox. Independently of PIGuard-on, hosts **must** still: … Secret vault … External WORM … Rate limits / spend caps  
> (`docs/AGENT_INSTALL.md` §8)

---

## Concrete ISSUES

### I1 — Missing `containment.host` foundation (plan step 2)

**Missing types (none exist under `src/containment/`):**

- `SecretProvider` Protocol + `EnvSecretProvider` + `FileSecretProvider`
- `HostChecklist` (fields at minimum: `isolation_declared`, secret provider present, egress provider/proxy URL, audit shipper)
- `AuditShipper` Protocol + `FileAuditShipper` (and/or HMAC export helper)
- `RateLimitGate` Protocol + `TokenBucketRateLimit` (foundation for step 9 / done-predicate 10)
- Unit tests for the above

Fail-open implication: hosts can claim “enterprise” while omitting vault, shipper, egress, and isolation declaration; library cannot refuse.

### I2 — No broker HostGate (plan step 3)

**Missing on `ToolBroker`:**

- `require_host_gate: bool` (or equivalent) and/or expanding `enterprise_profile` so mint + privileged `secure_execute` **fail closed** unless `HostChecklist.passes`
- Constructor wiring for `host_checklist: HostChecklist | None`, optional `rate_limit: RateLimitGate | None`
- Deny `rule_id`s such as `host_gate_required` / `host_checklist_failed` before capability mint
- Tests: enterprise / `require_host_gate` denies when checklist incomplete; allows when complete

**Current fail-open path:** `enterprise_profile=True` only sets `require_signed_intent`; mint proceeds with no host checklist (`broker.py` steps 0→8). Privileged execute has no host-gate check.

### I3 — Plaintext secret examples in install docs (done-predicate 4 / step 10)

| File | Issue |
| --- | --- |
| `docs/AGENT_INSTALL.md` §2 | `CapabilityMinter(secret=b"set-a-real-32-byte-secret-here!!!")` |
| `README.md` (~line 84) | `CapabilityMinter(secret=b"replace-me-with-32-byte-secret!!")` |

These contradict AGENT_INSTALL §8 (“never commit plaintext secrets”) and plan done-predicate 4 (“install examples use providers, not inline raw HMAC secrets”). Test fixtures using `secret=b"..."` are acceptable for hermetic tests; **docs/examples** should use `EnvSecretProvider` / `FileSecretProvider`.

### I4 — No AuditShipper / export path (done-predicate 8 / step 2)

`AuditLog` appends locally only. No Protocol to ship/export chained events (file sidecar, HMAC-signed export blob, hook for external WORM). Residual remains “filesystem writer can truncate” with no in-package shipper interface for hosts to satisfy HostChecklist.

### I5 — No RateLimitGate on broker (plan step 2 types + step 9 enforce; slice notes step 10 docs)

LLM10 residual documented as host-must (`OWASP_LLM_TOP10_MAP.md`, AGENT_INSTALL §8 item 6). Package has size limits only — **no** token-bucket / spend gate Protocol, and broker does not call any rate gate before mint/execute. Step 2 must add types; step 9 enforces; step 10 documents composition.

### I6 — Step 10 composition/docs absent

Missing:

- `build_enterprise_host()` (or equivalent factory composing policy, broker, providers, checklist, shipper, rate gate, egress)
- `docs/HOST_HARDENING.md`
- Updates to AGENT_INSTALL / THREAT_MODEL / DECISIONS / README / SKILL / `__init__.py` exports for host APIs
- Version remains **1.2.0** (`__init__.py`, `pyproject.toml`) — bump is step 11, noted only

---

## Exact files/APIs to add (steps 2–3; step 10 composition) — analysis only

### Step 2 — Host foundation

| Add | Role |
| --- | --- |
| **`src/containment/host.py`** (new) | Core module |
| `SecretProvider` (typing.Protocol) | `get_bytes(name: str) -> bytes` (or `get(key) -> bytes`); raise on missing |
| `EnvSecretProvider` | Read from env var name(s); fail closed if empty/missing |
| `FileSecretProvider` | Read secret bytes from path (mode-check optional); fail closed if missing |
| `HostChecklist` (frozen dataclass) | `isolation_declared: bool`; `secret_provider: SecretProvider`; `egress_ok: bool` or `egress_provider` / `proxy_url: str \| None`; `audit_shipper: AuditShipper`; method `assert_ready()` / `ok() -> bool` listing failures |
| `AuditShipper` (Protocol) | e.g. `ship(events: Sequence[Mapping] \| path) -> None` or `export_chain(audit: AuditLog) -> Path/bytes` |
| `FileAuditShipper` | Copy/export JSONL (+ optional HMAC over tip hash) to ship path |
| `RateLimitGate` (Protocol) | e.g. `allow(tool: str, *, cost: float = 1.0) -> None` raise on exceed |
| `TokenBucketRateLimit` | In-memory token bucket implementing Protocol |
| **`tests/test_host.py`** (new) | Unit tests: env/file providers, checklist pass/fail, shipper write, token bucket deny |
| Optional thin helpers | `secret_for_minter(provider, name) -> bytes` used by examples |

Do **not** put vault network clients in-tree; Env/File backends satisfy plan.

### Step 3 — Broker HostGate

| Change | Role |
| --- | --- |
| **`src/containment/broker.py`** | Add `require_host_gate: bool = False`, `host_checklist: HostChecklist \| None = None`, optionally `rate_limit: RateLimitGate \| None = None` |
| Enterprise wiring | `enterprise_profile=True` ⇒ `require_signed_intent` **and** `require_host_gate` (or document explicit `require_host_gate=True` required with enterprise — prefer OR-into gate for fail-closed) |
| Gate placement | Before mint (and before privileged execute path): if `require_host_gate` and checklist missing/failed → `PolicyDecision(effect="deny", rule_id="host_gate_...")`, audit, `SecurityViolation` |
| **`tests/test_broker_host_gate.py`** (new) or extend `test_intent.py` / `test_broker.py` | Deny without checklist; deny incomplete checklist; allow complete + signed intent |

Capability/Intent constructors may keep `secret: bytes` but enterprise examples must obtain bytes **via** `SecretProvider` (adapter, not required API break).

### Step 10 — Docs + composition (related to this slice)

| Add/update | Role |
| --- | --- |
| **`src/containment/enterprise.py`** or function in `host.py`: `build_enterprise_host(...)` | Compose PolicyEngine + AuditLog + FileAuditShipper + Env/File secrets + HostChecklist + ToolBroker(`enterprise_profile=True`, `require_host_gate=True`, …) |
| **`docs/HOST_HARDENING.md`** | Map AGENT_INSTALL §8 items → concrete types; how to declare isolation; proxy URL; shipper; rate gate |
| **`docs/AGENT_INSTALL.md`** | Replace plaintext `secret=b"..."` with provider; link HostGate |
| **`docs/THREAT_MODEL.md`** | Residual §: vault/WORM/rate now have **in-package interfaces**; residual remains if host skips checklist / proxy |
| **`README.md` / `SKILL.md` / `DECISIONS.md`** | Same example fix + HostGate mention |
| **`src/containment/__init__.py`** | Export new public types |

Rate **enforcement** on broker remains plan **step 9**; step 2 only ships Protocol + `TokenBucketRateLimit`; step 10 documents the hook.

---

## Evidence summary (paths + brief quotes)

1. **Plan law** — `LEFTOVERS_HARDEN_PLAN.md` steps 2–3, 10; done predicate 3–4, 8, 10–11: HostGate, SecretProvider Env/File, AuditShipper, RateLimitGate, `build_enterprise_host()`, HOST_HARDENING.md.
2. **No host module** — `ls src/containment/` has no `host.py`; search for `SecretProvider|AuditShipper|HostChecklist|require_host_gate|RateLimitGate|build_enterprise` → hits only plan/docs residual prose, not implementations.
3. **Broker enterprise = signed intent only** — `broker.py`: `self.require_signed_intent = bool(require_signed_intent or enterprise_profile)` — no host checklist.
4. **Raw secrets** — `CapabilityMinter(secret: bytes | None)`, `IntentSigner(secret: bytes)`.
5. **Audit not shippable** — `AuditLog` “Not WORM”; THREAT_MODEL: “External WORM / signed log shipping remains out of scope”.
6. **Plaintext install example** — AGENT_INSTALL: `CapabilityMinter(secret=b"set-a-real-32-byte-secret-here!!!")`; README: `secret=b"replace-me-with-32-byte-secret!!"`.
7. **§8 checklist only** — AGENT_INSTALL §8 lists isolation / egress / vault / WORM / rate — no typed HostGate.
8. **LLM10** — OWASP map: “Host must rate-limit model/API spend”; no broker rate gate.

---

## Slice handoff

- **Verdict:** **ISSUES** (expected pre-step-2 state; not BLOCKED — sources readable, plan clear).
- **Implementers:** execute plan step 2 (`host.py` + tests) → step 3 (broker HostGate) → later step 9 (rate enforce) → step 10 (composition/docs). Do not treat AGENT_INSTALL §8 prose as satisfying done-predicate HostGate.
