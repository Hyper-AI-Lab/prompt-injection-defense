# Slice C — egress_resolve / egress_proxy / http_egress / moltbook wiring

**Repo:** `/workspace/prompt-injection-defense` (1.3.0)  
**Slice:** Bar B audit — egress path  
**Date:** 2026-10-07 JST  
**Worker:** local swarm slice C (analysis only; no product code changes)  
**Sources read:** `src/containment/egress_resolve.py`, `egress_proxy.py`, `http_egress.py`, `moltbook.py`, `url_guard.py` (`is_blocked_ip_literal`); `tests/test_egress_resolve.py`, `test_egress_proxy.py`, `test_http_egress.py`, `test_moltbook.py` (egress sections); `docs/HOST_HARDENING.md`, `docs/THREAT_MODEL.md` SSRF residual; `LEFTOVERS_HARDEN_PLAN.md` steps 4–6 / done-predicates 5–7; CLI help via `containment-egress-proxy --help`  
**Verify this session:** injected-resolver prove (CGNAT + any-blocked); pytest on the four modules — all green (1 skipped elsewhere in moltbook live).

---

## Verdict: **ISSUES**

Core Bar B egress surface matches the law: CGNAT deny, any-blocked pin semantics, CONNECT + absolute-URI forward, enterprise env flags, opener bypass for DI, TOCTOU residual documented. **Not BLOCKED.** One concrete operator-facing defect (HOST_HARDENING CLI flags) plus minor residuals below.

---

## Checklist vs mission

| Claim | Evidence | Status |
| --- | --- | --- |
| **CGNAT deny** | `DENY_NETWORKS` includes `100.64.0.0/10`; `ip_is_denied("100.64.1.1")` True while `is_private` False; tests `test_deny_table_includes_cgnat`, `test_resolve_denies_cgnat`, `test_literal_cgnat_denied_by_resolve`, `test_connect_denied_cgnat_via_mock_dns`; `url_guard.is_blocked_ip_literal` routes through `ip_is_denied` | **PROVEN** |
| **Pin semantics (any-blocked)** | `resolve_and_pin` sets `any_denied` if any answer denied → raises before picking pin; `test_resolve_denies_mixed_public_and_private` (8.8.8.8 + 10.0.0.1); connect dials `pinned_ip` only (`test_pinned_connect_uses_ip_not_hostname`) | **PROVEN** |
| **Proxy CONNECT** | `_handle_connect` → resolve-pin → 200 tunnel or 403; hermetic tests deny IMDS/CGNAT; allow + tunnel (`test_connect_allow_then_tunnel_http`) | **PROVEN** |
| **Proxy HTTP forward** | Absolute-URI required; Host = original hostname; POST body; deny private; allow mock public via connector redirect | **PROVEN** |
| **Enterprise env flags** | `CONTAINMENT_EGRESS_PINNED=1`, `CONTAINMENT_EGRESS_PROXY`; kwargs; proxy wins over pin; `test_fetch_posts_honors_pinned_env` / `_proxy_env` / `test_read_posts_passes_pinned_flag` | **PROVEN** |
| **Bypass if opener supplied** | `fetch_url` / `fetch_posts`: explicit `opener` first (no pin); `test_fetch_url_opener_wins_over_pinned`; documented in docstrings | **PROVEN (intentional)** |
| **TOCTOU residuals documented** | `THREAT_MODEL.md` SSRF residual; `HOST_HARDENING.md` “DNS rebinding residual remains if the host bypasses both pin and proxy…”; plan non-goal | **DOCUMENTED** |

---

## Architecture match (law steps 4–6)

1. **`egress_resolve`** — parse → (literal or DNS) → deny table + `is_*` flags → `ResolvedPin` → `pinned_socket_connect` / `open_pinned_urllib` (Host + SNI = hostname). Shared deny with `url_guard` via lazy import. Fail-closed on empty answers / `gaierror`.
2. **`egress_proxy`** — stdlib listen; CONNECT and absolute-form HTTP; no TLS MITM on CONNECT (blind tunnel); HTTPS absolute-form wraps upstream with SNI; CLI entrypoint `containment-egress-proxy = containment.egress_proxy:main` in `pyproject.toml`.
3. **`http_egress.fetch_url`** — priority: opener → proxy_url → use_pinned → default urllib; no redirects.
4. **`moltbook`** — when opener unset and pinned/proxy: calls `fetch_url`; else legacy urllib. Host allowlist + `public_only` still applied before fetch.

Plan wording mentioned ambient `HTTP(S)_PROXY`; shipping uses **dedicated** `CONTAINMENT_EGRESS_PROXY` (avoids inheriting ambient proxies). Slight plan drift; security-positive; not a functional gap vs done-predicate 7.

---

## ISSUES

### I1 — HOST_HARDENING CLI flags wrong (operator defect)

`docs/HOST_HARDENING.md` shows:

```bash
containment-egress-proxy --host 127.0.0.1 --port 8888
```

Actual CLI (verified `--help`): only `--listen HOST:PORT` (default `127.0.0.1:18080`), plus `--allow-host`, `--timeout`. Following the doc verbatim fails. **Severity: medium (docs).** Fix: replace with e.g. `containment-egress-proxy --listen 127.0.0.1:8888`.

### I2 — IPv6 CONNECT edge (fail-closed, incomplete)

CONNECT target parsing uses `rpartition(":")`. Bracketed `[ipv6]:port` works and denies loopback/CGNAT-mapped correctly. Bare `[::1]` (no port) → 400; bare `::1` → empty_host. Unbracketed IPv6 authority is non-RFC for CONNECT; residual is incomplete IPv6 UX, not an allow-bypass. **Severity: low.** Optional harden: parse bracketed authority per RFC 7230 before defaulting port 443.

### I3 — Opener / default urllib bypass pin (intentional residual)

Production hosts that pass a custom `opener`, or leave pin/proxy unset, still connect-by-name. Enterprise `HostGate.egress_configured` is checklist-level, not a hard bind inside `fetch_posts`. Documented; opener DI is required for hermetic tests. **Severity: residual (documented).** Do not “fix” by removing opener; optional later: warn/audit when enterprise profile + opener.

### I4 — Proxy-wins semantics vs dual env

If both `CONTAINMENT_EGRESS_PINNED=1` and `CONTAINMENT_EGRESS_PROXY` are set, pin is disabled (`use_pinned=False`). Correct when the proxy is `containment-egress-proxy`; silent downgrade if PROXY points at a non-pinning corporate proxy. Documented in tests/HOST_HARDENING table. **Severity: low (ops clarity).** Optional: doc one-liner “PROXY implies trust the proxy’s resolve-pin; do not assume PINNED still applies.”

---

## Non-issues (checked)

- **CGNAT via `is_private` alone:** closed; explicit CIDR + dual-check in `ip_is_denied`.
- **IPv4-mapped IMDS/CGNAT:** denied (`test_ipv4_mapped_cgnat_denied`).
- **CONNECT 403 on deny:** body includes `denied_network`.
- **Host header / SNI:** forward path sets `Host: pin.hostname`; CONNECT does not MITM TLS.
- **Redirects:** blocked on fetch_url / moltbook default openers; proxy does not follow redirects.
- **TOCTOU after pin:** connecting to IP (not re-resolving name) is the intended close; residual only if host bypasses pin+proxy — already in THREAT_MODEL / HOST_HARDENING.

---

## Test coverage snapshot (this session)

| Suite | Result |
| --- | --- |
| `test_egress_resolve.py` | green (CGNAT, any-blocked, IMDS, pin dial) |
| `test_egress_proxy.py` | green (CONNECT/forward deny+allow, CLI help) |
| `test_http_egress.py` | green (pinned, proxy, opener-wins) |
| `test_moltbook.py` egress cases | green (pinned path, env flags, passthrough) |

---

## Recommendation to parent

Treat **I1** as a required doc fix in the bar-b audit harden plan. **I2–I4** are residuals/clarity, not blockers to calling egress “production-complete” relative to Bar B. No code placeholder or missing module on this slice.
