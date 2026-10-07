# Host hardening (Bar B)

How to close residuals the library cannot own alone: OS isolation, egress,
secrets, audit shipping, and rate limits. Pair with
[AGENT_INSTALL.md](AGENT_INSTALL.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Library vs host

| Layer | What containment provides | What the host still owns |
| --- | --- | --- |
| Agent loop | Labels, ingest, quarantine, default-deny broker, capabilities | Wiring every privileged path through the broker |
| Secrets | `SecretProvider` (env / file) | Vault rotation, ACLs, never commit secret bytes |
| Egress | `url_guard`, resolve-pin helpers, in-repo forward proxy | Run the proxy or pinned client; OS/network policy |
| Audit | Append-only JSONL + hash chain; `AuditShipper` export | WORM / SIEM; filesystem adversary resistance |
| Isolation | `HostChecklist.isolation_declared` (declaration only) | Containers, gVisor/Kata, process sandbox |
| Spend | Optional `RateLimitGate` on privileged broker mint | Model/API quotas beyond the broker |

This package is not a FedRAMP or SOC2 product. It is not an OS sandbox.
Skipping the checklist or proxy leaves documented residuals.

## Quick composition

```python
from pathlib import Path
from containment.enterprise import build_enterprise_host

ROOT = Path("...")
host = build_enterprise_host(
 policy_path=ROOT / "policies" / "default_deny.yaml",
 audit_path=ROOT / "audit.jsonl",
 audit_ship_destination=ROOT / "audit-shipped.jsonl",
 secrets_dir=ROOT / "secrets", # files: capability, intent
 isolation_declared=True, # you run a real sandbox
 egress_configured=True, # or pass proxy_url=
 known_tools=frozenset({"web.fetch", "email.send"}),
)
# host.broker.require_host_gate is True; signed intents required
# host.proxy_url is None unless you passed proxy_url=
```

Production path: put HMAC material in `secrets_dir` or env
(`secrets_env_prefix="CONTAINMENT_SECRET_"`), never inline `secret=b"..."` in
source. Tests may use a temp `FileSecretProvider`.

## Run `containment-egress-proxy`

Resolve-pin-forward HTTP proxy (CONNECT + absolute-URI). No TLS MITM. No
credential injection. Not a clone of Hermes iron-proxy.

```bash
# listen (port 0 = ephemeral; prints listening URL)
containment-egress-proxy --host 127.0.0.1 --port 8888

# point fetch / moltbook at it
export CONTAINMENT_EGRESS_PROXY=http://127.0.0.1:8888
# or pinned client without proxy:
export CONTAINMENT_EGRESS_PINNED=1
```

Denied destinations (loopback, link-local/IMDS, RFC1918, ULA, CGNAT
`100.64/10`, IPv4-mapped privates) return HTTP 403. Public allowlisted hosts
connect only to the pinned IP.

## HostChecklist / HostGate

Under `enterprise_profile=True` or `require_host_gate=True`, the broker refuses
mint and privileged execute unless `HostChecklist.ok()`:

- `isolation_declared` - operator asserts process/container isolation
- `secret_provider` - non-None `SecretProvider`
- `egress_configured` - True when proxy URL or pinned egress is configured
- `audit_shipper` - non-None `AuditShipper`

Incomplete checklist → deny `host_checklist_failed`. Missing checklist →
`host_gate_required`.

`build_enterprise_host` fails closed with `ValueError` if isolation/egress are
not declared before returning a broker.

## SecretProvider

```python
from containment.host import EnvSecretProvider, FileSecretProvider

# Env: CONTAINMENT_SECRET_CAPABILITY / CONTAINMENT_SECRET_INTENT
env = EnvSecretProvider(prefix="CONTAINMENT_SECRET_")

# File: <root>/capability and <root>/intent (no path traversal)
files = FileSecretProvider("/var/run/containment/secrets")
```

`CapabilityMinter` and HMAC `IntentSigner` load bytes via the provider inside
`build_enterprise_host`. Optional Ed25519: pass `intent_signer=Ed25519IntentSigner(...)`
(requires `pip install "containment[crypto]"`).

## AuditShipper

`FileAuditShipper(destination)` appends JSONL lines from an `AuditLog` path.
Export is tamper-evidence only, not WORM. Schedule `ship_file(audit.path)` from
your host cron/SIEM pipeline.

## Pinned egress / env

| Knob | Effect |
| --- | --- |
| `CONTAINMENT_EGRESS_PINNED=1` | moltbook / `fetch_url` use resolve-pin |
| `CONTAINMENT_EGRESS_PROXY=http://...` | urllib via the forward proxy (wins over pin) |
| `use_pinned_egress=` / `proxy_url=` kwargs | same, per call |

DNS rebinding residual remains if the host bypasses both pin and proxy and uses
raw sockets after a separate check.

## Optional: Ed25519, Redis, rate limit

- **Ed25519 intents:** `containment[crypto]`; broker accepts any `IntentVerifier`.
- **Redis consume store:** `containment[redis]` + `RedisConsumeStore`; pass as
 `consume_store=` into `build_enterprise_host`.
- **Rate / spend:** `TokenBucketRateLimit(rate, capacity)` as `rate_limit=`;
 charges privileged sinks only before capability mint.

## Explicit residuals

- No FedRAMP / SOC2 certification claim.
- In-repo proxy is resolve-pin-forward HTTP, not iron-proxy MITM / vault inject.
- Declaring `isolation_declared=True` without a real sandbox is operator fraud,
 not a library failure.
- Filesystem writers can still rewrite audit JSONL; ship to external WORM.
- Adaptive injection and novel attacks: policy + broker limit authority, not
 model immunity.
