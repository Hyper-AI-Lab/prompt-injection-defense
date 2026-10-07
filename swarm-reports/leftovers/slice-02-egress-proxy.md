# Slice 02 — SSRF / egress_resolve / pinned connect / HTTP forward proxy

**Repo:** `/workspace/prompt-injection-defense`  
**Slice:** steps 4–6 of `LEFTOVERS_HARDEN_PLAN.md`  
**Date:** 2026-10-07 JST  
**Worker:** local swarm coverage (analysis only; no product code changes)  
**Sources read:** `LEFTOVERS_HARDEN_PLAN.md`, `src/containment/url_guard.py`, `moltbook.py`, `policy.py`, `broker.py`, `tests/test_url_guard.py`, `docs/THREAT_MODEL.md` SSRF residual; industry pattern (resolve-then-pin, proxy-as-chokepoint)

---

## Verdict: **ISSUES**

Plan steps 4–6 correctly target the documented residual. Current tree has **literal-only** `url_guard` and **no** DNS resolve / pin / proxy. Implementation is unblocked, but several concrete gaps and design risks must be sealed in those steps (especially **CGNAT** denial and **CONNECT vs absolute-URI**). Not BLOCKED: stdlib-first design is feasible and maps 1:1 to the law.

---

## Plan alignment (steps 4–6)

| Step | Law requirement | Current state |
|------|-----------------|---------------|
| **4** | `egress_resolve` + pinned connect; deny CIDRs incl. loopback / link-local / IMDS / RFC1918 / ULA / **CGNAT** / IPv4-mapped; tests | **Missing.** Only `url_guard` literal checks. |
| **5** | In-repo Python HTTP forward proxy resolve-pin-forward; CLI `containment-egress-proxy`; hermetic tests | **Missing.** No `egress_proxy` module / entrypoint. |
| **6** | Moltbook / HTTP fetch prefer pinned client or `HTTP(S)_PROXY` under enterprise | **Partial.** Moltbook uses stdlib urllib + hostname allowlist + literal `public_only`; connects via normal DNS (TOCTOU). |

Done-predicate items 5–7 and non-goal “DNS-rebinding immunity without pin/proxy” are consistent with this slice.

---

## Gaps in current `url_guard` (no DNS)

Module self-describes the limit: *“SSRF / egress URL helpers (no DNS; literal checks only).”*

### What it does well
- Scheme allowlist; reject userinfo.
- Literal odd forms: decimal IPv4 (`2130706433`), octal-ish octets, IPv6 loopback, `localhost` / `metadata.google.internal`.
- `is_blocked_ip_literal` uses `ipaddress` flags: private, loopback, link_local, unspecified, multicast, reserved.
- Wired into: policy host predicates (`parse_egress_url` / allowlist), broker `network: public_only` (`check_public_only`), moltbook allowlist + `public_only`.
- Moltbook: no redirects, max body bytes — good complementary controls.

### Critical gaps vs steps 4–6 / threat model

1. **No DNS resolution.** Hostname `evil.example` that resolves to `169.254.169.254` passes `check_public_only` / `check_url_for_tool(..., network="public_only")` because the host string is not an IP literal.
2. **Check-then-reconnect TOCTOU.** Even if a future check called `getaddrinfo` and then handed the **hostname** URL to urllib/httpx, a second resolve at connect time enables DNS rebinding. Need **resolve → validate all answers → connect to pinned IP** (Host / SNI preserved).
3. **Broker `network: public_only` only inspects `arguments["url"]` string literals** (`broker.py` `_limits_violation`). No resolve; no pin; no proxy requirement.
4. **Moltbook** validates allowlisted hostname then `urllib` opens by name — residual rebinding if DNS for that name is attacker-influenced (narrower than open SSRF, still fails enterprise pin requirement).
5. **CGNAT hole (measured).** Python `ipaddress.IPv4Address("100.64.0.1").is_private` is **`False`**. Plan explicitly requires CGNAT deny. Current `is_blocked_ip_literal` therefore **allows** `100.64.0.0/10` literals. Must add an explicit deny table (not rely solely on `is_private`).
6. **No shared deny-CIDR table** as a first-class export for resolve + proxy to share with literal checks (DRY risk if duplicated).
7. **No pinned connect helper**; no `EgressProvider` surface for HostGate (step 2–3 compose; step 4–5 supply).
8. **IPv4-mapped / IPv6 edge cases:** `::ffff:127.0.0.1` / `::ffff:169.254.169.254` are caught when parsed as IPs via `is_loopback` / `is_link_local`, but hostname forms and dual-stack A+AAAA answers need “deny if **any** answer is blocked” semantics at resolve time.

THREAT_MODEL already states this residual; Bar B closes it **in-repo** via resolve-pin + proxy, not by claiming OS replacement.

---

## Minimal production API (stdlib-first)

Keep `url_guard` as the **literal / parse** layer. Add two modules; do not grow `url_guard` into a proxy.

### 1. `containment.egress_resolve` (step 4)

```text
DenyNetworkError(UrlGuardError)   # or sibling; stable .code strings

DENY_NETWORKS: frozenset[ipaddress._BaseNetwork]  # explicit table:
  # loopback, link-local (incl. 169.254.0.0/16 IMDS), RFC1918,
  # ULA fc00::/7, CGNAT 100.64.0.0/10, IPv4-mapped filter,
  # unspecified, multicast, documentation, etc.

def ip_is_denied(ip: IPv4Address | IPv6Address) -> bool
    # literal path: reuse + CGNAT fix; prefer shared helper with url_guard

@dataclass(frozen=True, slots=True)
class ResolvedPin:
    hostname: str          # original (for Host / SNI)
    scheme: str
    port: int
    pinned_ip: str         # chosen public address
    all_ips: tuple[str, ...]
    family: int            # AF_INET / AF_INET6

def resolve_and_pin(
    url: str,
    *,
    allowed_schemes: frozenset[str] = frozenset({"https"}),
    host_allowlist: Set[str] | None = None,
    resolver: Callable[[str, int], list[...]] | None = None,  # inject getaddrinfo
) -> ResolvedPin
    # 1) parse_egress_url / check_url_for_tool (literal + allowlist)
    # 2) if host is IP literal → deny-check → pin that IP
    # 3) else getaddrinfo(host, port); deny if empty OR any IP denied
    # 4) pick first allowed IP (prefer family policy: IPv4-first or dual documented)
    # NEVER return “check passed, connect by name”

def pinned_socket_connect(pin: ResolvedPin, *, timeout: float) -> socket.socket
    # connect((pinned_ip, port)); no second DNS

def pinned_http_url(pin: ResolvedPin) -> str
    # http(s)://<pinned_ip>:<port>/...  for urllib; caller sets Host header

def open_pinned_urllib(request: Request, pin: ResolvedPin, *, timeout: float) -> ...
    # stdlib: custom HTTPHandler or opener that dials pin; set Host; for HTTPS
    # wrap TLS with server_hostname=pin.hostname (SNI + cert verify against hostname)
```

**Injection:** `resolver=` and optional `connector=` keep tests hermetic (no real DNS / IMDS).

**Semantics:** any blocked A/AAAA → hard deny (do not “skip private and use another”).

### 2. Pinned client helper (step 4 + wire in 6)

```text
def pinned_urlopen(url: str, *, timeout: float, max_bytes: int, ...) -> bytes
    # resolve_and_pin → connect pin → optional TLS → read capped; redirects=0 default
```

Moltbook `fetch_posts`: when enterprise / `use_pinned_egress` / env flag: use pinned path (or route via proxy URL). Keep `opener=` DI for tests.

### 3. `containment.egress_proxy` daemon (step 5)

```text
# HTTP forward proxy; resolve-pin-forward; stdlib socketserver / http.server style

@dataclass
class ProxyConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 0          # 0 = ephemeral (tests)
    allowed_schemes: frozenset[str]
    host_allowlist: frozenset[str] | None  # None = any public after pin
    deny_networks: ...            # shared DENY_NETWORKS
    timeout: float
    max_connect_bytes: int        # optional body caps for non-CONNECT
    enable_connect: bool = True   # HTTPS tunneling
    enable_http_forward: bool = True  # absolute-URI GET/POST for http://

class EgressProxyServer:
    def __init__(self, config: ProxyConfig, *, resolver=None): ...
    def serve_forever() / run_in_thread() / socket pair for tests
    @property
    def proxy_url(self) -> str    # http://127.0.0.1:<port>

def main(argv: list[str] | None = None) -> int
    # CLI: containment-egress-proxy --listen 127.0.0.1:8888 [--allow-host ...]
```

**pyproject entrypoint:** `containment-egress-proxy = containment.egress_proxy:main`

**Forward path (resolve-pin-forward):**
1. Parse client request: either `CONNECT host:port` or absolute-form `GET http://host/path`.
2. Build target URL / host:port; scheme allowlist (`https` default for CONNECT; `http` only if explicitly enabled).
3. `resolve_and_pin` (same module as client).
4. Dial **pinned_ip:port** from the proxy process; never dial by name after check.
5. **CONNECT:** on success send `HTTP/1.1 200 Connection Established`, then bidirectional `socket.sendfile` / select loop (blind tunnel — proxy does **not** MITM TLS; SNI is end-to-end client→origin). Pin already enforced on TCP destination.
6. **absolute-URI HTTP:** proxy speaks HTTP to origin on pinned IP with `Host: original`; stream response; no redirect follow (or re-pin each hop if ever enabled — default off).

**EgressProvider (HostGate):** thin Protocol, e.g. `proxy_url: str | None` and/or `pinned_fetch: Callable` so checklist can require proxy URL or in-process pin helper.

---

## Test strategy (hermetic — no real IMDS)

All network assertions via **injected resolver** returning crafted `addrinfo` tuples; optional local TCP servers on `127.0.0.1` for connect/proxy loopbacks. **Never** call real `169.254.169.254`.

### Unit — `egress_resolve`
| Case | Expect |
|------|--------|
| Resolver returns only `169.254.169.254` | deny (`imds` / `denied_cidr`) |
| Returns `10.0.0.1`, `192.168.0.1`, `127.0.0.1`, `::1`, `fc00::1` | deny |
| Returns `100.64.1.1` (CGNAT) | **deny** (regression for current url_guard hole) |
| Returns mix public + private | **deny** (any-blocked) |
| Returns only `93.184.216.34` | pin that IP; hostname preserved |
| Decimal / IPv4-mapped literals | deny without DNS |
| Allowlist miss | deny before or after resolve (order documented) |
| Empty getaddrinfo / gaierror | deny |

### Unit — pinned connect
- Fake connector records connect address == pinned IP (not hostname).
- TLS path unit-test with `ssl.SSLContext` + local cert **or** mock wrap_socket asserting `server_hostname=original_host`.

### Integration — egress_proxy (local loop)
1. Start `EgressProxyServer` on `127.0.0.1:0` with mock resolver.
2. **Deny:** client requests `CONNECT 169.254.169.254:80` or host whose mock DNS → IMDS/private/CGNAT → proxy returns **403/502** with stable reason; no bytes to a real metadata service.
3. **Allow:** mock DNS → `127.0.0.1` **only if** test origin listen is explicitly opted into an **allow_test_networks** flag **or** prefer: mock public IP while origin is a local server reached by **patching connect** to redirect pinned public IP → local test socket (pin table / connect hook). Cleanest hermetic pattern: `connector=` maps pinned IP to local acceptor so deny table still sees “public” pin.
4. **CONNECT tunnel:** local TLS or plain echo server; client uses `urllib`/`http.client` with `ProxyHandler({https: proxy_url})`; assert body round-trip.
5. **absolute-URI:** HTTP origin behind pin; assert `Host` header = original hostname.
6. CLI smoke: `python -m containment.egress_proxy --help` / entrypoint import.

### Wire — moltbook (step 6)
- With pin/proxy flag: mock resolver + local HTTPS origin; ensure fetch still allowlists `www.moltbook.com` host string while dialing pin.
- Without enterprise: existing behavior / tests unchanged.

### Explicit non-tests
- No live AWS/GCP metadata calls.
- No dependency on public internet in `release_gate`.

---

## Risks

### CONNECT vs absolute-URI forward
| Mode | Role | Risk |
|------|------|------|
| **CONNECT** | Required for HTTPS clients (`HTTPS_PROXY`) | Proxy only sees host:port; TLS opaque. **Correct for non-MITM.** Pin applies to TCP peer only — good. Must reject CONNECT to denied IPs/ports (default allow 443; optional 80). |
| **absolute-URI** (`GET http://host/path`) | Classic forward proxy for cleartext HTTP | Easier to inspect; rarely needed if default schemes=`https` only. If enabled, still resolve-pin; strip `Proxy-*` hop-by-hop headers; do not follow redirects by default. |
| **HTTPS absolute-URI / MITM** | Out of scope (plan non-goal: no credential-injection TLS MITM) | Do **not** decrypt TLS. |

**Recommendation:** implement **both** CONNECT (primary) and absolute-URI for `http://` only when `enable_http_forward=True`; default config HTTPS-via-CONNECT. Document that clients must set `HTTPS_PROXY=http://127.0.0.1:<port>` and that **client-side** pin is redundant when trusting this proxy (FastMCP-style trust-proxy), but HostGate should require the proxy **or** in-process pin — not neither.

### Other risks
- **Dual stack:** AAAA → ULA while A → public — deny-any is correct; document.
- **Redirects:** following without re-pin reopens SSRF; default **no redirects** in pin client and proxy HTTP forward.
- **Host header / SNI mismatch:** connecting to IP without `Host`/SNI breaks virtual hosts and cert verify — pinned urllib/TLS must set both to original hostname.
- **Proxy bypass:** process that ignores `HTTP(S)_PROXY` and dials direct defeats chokepoint — HostGate + docs must say “all tool HTTP via pin helper or proxy”; residual if host bypasses (plan non-goal admits this).
- **DNS stub injection in prod:** production uses real `getaddrinfo`; tests inject. Do not leave a “trust hostname” escape hatch in enterprise profile.
- **CGNAT + `is_private`:** failing to fix CGNAT in shared deny table would leave a known hole in both client pin and proxy.
- **Performance:** one `getaddrinfo` + deny walk per request — fine vs LLM latency; proxy adds one hop (localhost) — acceptable.
- **Stdlib proxy quality:** concurrent `ThreadingHTTPServer` is enough for agent sidecar; not a multi-tenant edge proxy. Document single-tenant / localhost listen default (`127.0.0.1` only).

---

## Implementation notes for executors (not plan amendments)

- Share one `DENY_NETWORKS` / `ip_is_denied` between `url_guard.is_blocked_ip_literal` and `egress_resolve` (fix CGNAT in the same change as step 4).
- Prefer stdlib (`socket`, `ssl`, `urllib`, `http.server`) — no httpx/requests required for the daemon; optional later.
- CLI + `build_enterprise_host()` composition land in steps 5/10; this slice only designs the surface.
- Do not clone Hermes iron-proxy (Go) or add TLS MITM — matches plan non-goals.

---

## Summary

**Verdict ISSUES:** steps 4–6 are the right law; current code is literal-only and CGNAT-weak; production API = shared deny table + `resolve_and_pin` + pinned urllib/TLS + localhost HTTP proxy (CONNECT-first) with hermetic resolver injection. No blockers; proceed step 4 → 5 → 6 as written.
