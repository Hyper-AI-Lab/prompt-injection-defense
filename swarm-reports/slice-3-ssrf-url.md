# Slice 3 — SSRF / URL allowlist helpers vs `web.fetch` / `http.post`

**SHA:** `765a618ef258130d9523a50fc39e151bc74009e7`  
**Bar A item:** SSRF/URL allowlist helpers  
**Scope:** Read-only audit of `policies/default_deny.yaml` `limits`/`network`, broker limit enforcement, moltbook `fetch_posts` URL handling.  
**Date:** 2026-10-07 JST

---

## VERDICT: ISSUES

Partial controls exist for `web.fetch` (policy scheme + host allowlist + broker `limits`), but **Bar A “URL allowlist helpers” are absent** as a reusable module. Several SSRF-shaped gaps remain (literal-IP-only `public_only`, arg-only redirect checks, unconstrained moltbook `base_url`, no `http.post` allow-path URL gates). Not BLOCKED: enough surface to harden surgically without a full egress proxy.

---

## Evidence (what exists today)

### 1. Policy — `policies/default_deny.yaml`

`read-public-web` (only allow path for network GET):

| Control | YAML | Notes |
| --- | --- | --- |
| Scheme | `args.url.scheme: https` | Predicate in `policy.py` via `urlparse(...).scheme` |
| Host allowlist | `args.url.host_in: approved_public_hosts` | Exact hostname ∈ `plan.approved_public_hosts` |
| Redirects | `limits.redirects: 0` | Enforced only on **request args** (see broker) |
| Size | `limits.max_bytes: 2000000` | Arg payload fields only; response body left to executor |
| Network | `limits.network: public_only` | Literal private/loopback/… IPs + `localhost` |

`http.post` appears only under `no-tainted-egress` (deny when `input.any_integrity: untrusted`). **There is no allow / require_human rule for `http.post`.** Trusted `http.post` → `default_deny` (confirmed by evaluating PolicyEngine at this SHA).

### 2. Policy predicates — `src/containment/policy.py`

- `args.url.scheme` (≈220–224): string scheme equality after `urlparse`.
- `args.url.host_in` (≈226–234): `urlparse(url).hostname` exact membership in named plan set.
- Unknown predicates fail closed (do not match).
- No shared helper: parse/normalize/reject-userinfo/block-non-http(s) live inline only.

### 3. Broker limit enforcement — `src/containment/broker.py`

Post-policy gate `4c` calls `_limits_violation` when `decision.limits` is set (≈215–225, 274–348). Documented in `DECISIONS.md` (H4 enforce, 2026-10-07).

| Limit key | Enforced? | How |
| --- | --- | --- |
| `max_bytes` | Partial | Denies oversized **arg** strings in `body`/`content`/`data`/`payload`/`text`. Response download cap is executor-side (`decision.limits` attached). |
| `redirects` | Partial | Denies if args `redirects`/`max_redirects` > cap, or `allow_redirects: true` when cap ≤ 0. **Omitted redirect args do not deny**; executor may still follow redirects. |
| `network: public_only` | Partial | `_url_host_not_public`: blocks literal private/loopback/link-local/unspecified/multicast/reserved IPs and `localhost`. **No DNS resolution.** Non-literal hostnames always pass this check. |
| Unknown keys | Fail closed | `unenforced limit keys present: …` |

Tests: `tests/test_broker.py` — `test_allow_fetch_exposes_limits_on_decision`, `test_limits_max_bytes_denies_oversized_payload`, `test_limits_redirects_zero_denies_allow_redirects`, `test_limits_network_public_only_denies_private_ip`.

### 4. Tool schemas — `src/containment/tool_schemas.py`

- `web.fetch`: `url` string required; optional `redirects` / `max_redirects` / `allow_redirects` / `max_bytes`; **no `format: uri`**, no scheme enum in schema.
- `http.post`: `url` + body-like fields + `headers`; **no redirect-related properties**; same lack of URI format/scheme.

### 5. Moltbook — `src/containment/moltbook.py` `fetch_posts`

- Builds `url = f"{base_url.rstrip('/')}/posts?{query}"` with default `DEFAULT_API_BASE = "https://www.moltbook.com/api/v1"`.
- GET-only, no auth headers — good for the intended public feed.
- **`base_url` is unconstrained**: any scheme/host (e.g. `http://169.254.169.254`, `file://…`) accepted if the caller passes it.
- Uses `urllib.request.urlopen` by default → **follows HTTP redirects** (`HTTPRedirectHandler`); no custom no-redirect opener.
- `resp.read()` with **no max_bytes** cap.
- Unit tests mock opener; no SSRF / base_url / redirect tests (`tests/test_moltbook.py`).

### 6. Package surface

No `url_guard` / `ssrf` / `validate_url*` module. `__init__.py` does not export URL helpers. Threat model (`docs/THREAT_MODEL.md`) explicitly: does not replace network egress proxies. `AUDIT_HARDEN_PLAN.md` lists “OS sandbox/SSRF full stack” as non-goal — Bar A asks for **helpers**, not a proxy.

---

## Gaps vs Bar A (missing SSRF controls)

| Gap | Severity | Detail |
| --- | --- | --- |
| **No reusable URL allowlist / SSRF helpers** | High (Bar A) | Logic split across `policy._predicate` and `broker._url_host_not_public` / `_limits_violation`. Hosts cannot call one API for scheme + host allowlist + public-IP + redirect-arg checks before mint/execute. |
| **`network: public_only` is literal-IP only** | High | DNS→private IP, `*.nip.io`→RFC1918, cloud metadata via hostname: **not blocked**. Documented in DECISIONS; still a Bar A residual. |
| **Decimal / odd IP forms** | Medium | e.g. `https://2130706433/` → hostname `2130706433`; `_url_host_not_public` returns **False** (not classified as IP). Bypass of `public_only` if that host were also allowlisted (or if host_in were loosened). |
| **Redirects not enforced at fetch time** | High (executor) | Policy `redirects: 0` only inspects args. Default urllib (moltbook) and any executor that ignores `decision.limits` can follow Location to private IPs (classic SSRF). |
| **Userinfo / credential URLs** | Low–Med | `https://user:pass@host/` parses host correctly but credentials are not rejected; risk of logging/leak and confuse-deputy URL shapes. |
| **`http.post` URL gates** | Medium | Shipped policy never allows `http.post` (safe default). Bar A still wants helpers so a future allow rule cannot forget scheme/host/`public_only`/redirects. Schema lacks redirect fields present on `web.fetch`. |
| **Moltbook `base_url` SSRF** | Medium | Injectable/misconfigured `base_url` bypasses all broker/policy URL checks (reader is outside `ToolBroker`). |
| **Response `max_bytes`** | Low–Med | Broker attaches limit; neither moltbook nor a library executor caps body reads. |
| **Schema does not encode https / host** | Low | JSON Schema only `minLength: 1` on `url`; real gates are policy predicates + limits. Fine if helpers are shared; fragile if policy YAML is edited carelessly. |

**Out of scope (explicit non-goals):** full egress proxy, OS sandbox, DNS-rebinding-at-connect as a hard guarantee without optional resolve. Report those as residual risk docs, not blockers.

---

## Surgical helpers proposal (fit the library — no egress proxy)

Add a small pure module, e.g. `src/containment/url_guard.py`, and call it from policy predicates, broker `_limits_violation`, and moltbook. Keep failures as deny reasons; no network I/O in the default path except optional opt-in resolve.

### Proposed API (sketch)

```text
UrlGuardError / reasons: bad_scheme | empty_host | userinfo | host_not_allowlisted
                       | not_public | redirects_exceeded | unenforced_limit

parse_egress_url(url: str, *, allowed_schemes: frozenset[str] = frozenset({"https"}))
  -> ParsedEgressUrl  # scheme, host (lower), port, path; reject userinfo; require host

host_in_allowlist(host: str, allowlist: AbstractSet[str]) -> bool
  # exact match after IDNA/lower normalize; document no wildcard unless explicit

is_blocked_ip_literal(host: str) -> bool
  # ipaddress + localhost aliases + decimal/octal/dotted-quad odd forms
  # + common metadata literals (169.254.169.254, fd00::, etc. via existing flags)

check_public_only(url: str) -> None  # raise/return reason if blocked literal

check_redirect_args(args: Mapping, *, max_redirects: int) -> None
  # move current broker redirects logic here

check_url_for_tool(url, *, schemes, host_allowlist | None, network: "public_only" | None)
  -> None  # compose above for web.fetch / http.post

# Optional (off by default; document residual if unused):
resolve_public_only(host: str) -> None  # DNS then re-check all A/AAAA; still not full rebinding defense
```

### Wire-up (minimal diffs)

1. **`policy.py`**: `args.url.scheme` / `args.url.host_in` call `parse_egress_url` + `host_in_allowlist` (reject userinfo; normalize host).
2. **`broker.py`**: `_url_host_not_public` / redirect branch become thin wrappers around `url_guard` (single source of truth). Keep unknown-limit fail-closed.
3. **`moltbook.fetch_posts`**: before open, `check_url_for_tool(url, schemes={"https"}, host_allowlist={parsed DEFAULT host}, network="public_only")`. Use an opener that **does not follow redirects** (install `HTTPRedirectHandler` that raises, or `urlopen` with a custom opener). Cap `resp.read(max_bytes)` (e.g. 2_000_000).
4. **`tool_schemas.py`**: add optional redirect fields to `http.post` mirroring `web.fetch`; optionally `pattern` for `^https:` (helpers remain authoritative).
5. **Docs**: one short “Host residual SSRF” subsection — no DNS by default; executor must honor `decision.limits["redirects"]`/`max_bytes`; library is not an egress proxy (`THREAT_MODEL` / Bar A docs).
6. **Tests**: table for decimal IP, `[::1]`, userinfo, `http://`, unlisted host, `allow_redirects`, moltbook bad `base_url`, no-redirect opener.

### Example future `http.post` allow rule (YAML only — do not ship until product wants it)

```yaml
- id: approved-http-post
  effect: require_human
  tool: http.post
  when:
    principal.authenticated: true
    args.url.scheme: https
    args.url.host_in: approved_public_hosts
    task.capabilities_contains: http.post
    input.all_integrity: trusted
  limits:
    redirects: 0
    max_bytes: 2000000
    network: public_only
```

Helpers make that rule safe-by-construction; shipped `default_deny.yaml` can stay without an `http.post` allow path.

---

## Ranked harden backlog (slice 3 → ENTERPRISE_HARDEN_PLAN)

1. **P0** — Add `url_guard` helpers; refactor policy + broker to use them; fix decimal-IP / userinfo rejects.
2. **P0** — Moltbook: validate `base_url`/final URL; disable redirects; cap read size.
3. **P1** — Document executor contract: honor `decision.limits` for redirects + response `max_bytes`; add residual-risk note (no DNS / no proxy).
4. **P1** — Align `http.post` schema redirect args with `web.fetch`; keep default policy deny; provide commented/example allow rule using same predicates/limits.
5. **P2** — Optional opt-in `resolve_public_only` for hosts that accept DNS; never claim rebinding immunity without pin-at-connect.

---

## Summary

| Question | Answer |
| --- | --- |
| Are YAML `limits` wired? | Yes (broker H4), with documented partial semantics |
| Scheme + host allowlist for `web.fetch`? | Yes (policy), not factored into helpers |
| Private IP block? | Literal only; hostname→private and decimal forms leak |
| Redirects blocked? | Arg metadata only; fetch path (esp. moltbook urllib) can still follow |
| `http.post` SSRF gating? | Always denied by default policy; no helper for a safe allow rule |
| Bar A helpers present? | **No** → **VERDICT: ISSUES** |
