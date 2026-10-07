# Slice A — LEFTOVERS done-predicate matrix (Bar B / 1.3.0)

**Slice:** A (done-predicate map)  
**Tree:** `/workspace/prompt-injection-defense` @ `bf14a69` (containment **1.3.0**; `origin/main` same)  
**Law:** `LEFTOVERS_HARDEN_PLAN.md` done-predicate items 1–12  
**Mode:** analysis only (no product code edits)  
**Verdict:** **PASS**

## Summary

All twelve LEFTOVERS done-predicate items map to **PASS** with file + test evidence on this tree. No concrete functional GAPs evidenced. Naming adaptations (not GAPs): checklist uses `egress_configured: bool` rather than a type named `EgressProvider`; proxy env is `CONTAINMENT_EGRESS_PROXY` (not stdlib `HTTP(S)_PROXY`); audit export ships SHA-256-chained JSONL (`AuditLog`) via `FileAuditShipper` (not a separate HMAC-MAC exporter).

## Matrix (items 1–12)

| # | Predicate (abbrev) | Result | Evidence |
|---|-------------------|--------|----------|
| 1 | Every step VERIFIED in PROGRESS_LOG | **PASS** | `PROGRESS_LOG.md`: Leftovers Bar B steps 2–11 each end `Verdict: VERIFIED`; plan+baseline at 21:56 JST; step 11 post-push VERIFIED (`9e3037f` then log `bf14a69`) |
| 2 | `release_gate.sh` exit 0; no ship-path TODO/NotImplemented/placeholder | **PASS** | Step 11 log: release_gate exit 0 (251 passed, 2 skipped; ASR=0.0000 FPR=0.0278). Live scan: `rg TODO\|FIXME\|NotImplemented` under `src/containment` → empty. `scripts/release_gate.sh` present |
| 3 | HostGate: enterprise / `require_host_gate` refuses mint+privileged execute unless checklist ok (`isolation_declared`, `SecretProvider`, egress, `AuditShipper`) | **PASS** | `src/containment/broker.py` L135–153 (gate before mint); `src/containment/host/checklist.py` (`HostChecklist.ok` / `failures`); `src/containment/enterprise.py` `build_enterprise_host` fail-closed. Tests: `tests/test_broker_host_gate.py` (`test_enterprise_without_checklist_denies`, `test_require_host_gate_incomplete_checklist_denies`, `test_complete_checklist_enterprise_allows`, `test_require_host_gate_false_skips_host_check`); `tests/test_enterprise_compose.py` (`test_rejects_missing_isolation`, `test_rejects_missing_egress`). *Note:* egress surface is `egress_configured: bool` + optional `proxy_url`, not a Protocol class named `EgressProvider` |
| 4 | `SecretProvider` + Env/File; install examples use providers not inline HMAC | **PASS** | `src/containment/host/secrets.py` (`SecretProvider`, `EnvSecretProvider`, `FileSecretProvider`). Tests: `tests/test_host_foundation.py` (`test_env_secret_*`, `test_file_secret_*`). Docs: `docs/AGENT_INSTALL.md`, `README.md`, `docs/HOST_HARDENING.md` use `FileSecretProvider` / `build_enterprise_host`; no `secret=b"..."` inline in those surfaces |
| 5 | Resolve-pin: DNS + deny CIDRs (loopback, IMDS, RFC1918, ULA, CGNAT, IPv4-mapped); pinned connect; metadata/private tests | **PASS** | `src/containment/egress_resolve.py` (`ip_is_denied`, `resolve_and_pin`, `pinned_socket_connect`, `open_pinned_urllib`; `100.64.0.0/10` in deny table). Tests: `tests/test_egress_resolve.py` (`test_deny_table_includes_cgnat`, `test_ip_is_denied_imds_rfc1918_loopback_ula`, `test_ipv4_mapped_cgnat_denied`, `test_resolve_denies_*`, `test_pinned_connect_uses_ip_not_hostname`, …) |
| 6 | In-repo egress proxy daemon; CLI `containment-egress-proxy`; hermetic deny/allow tests | **PASS** | `src/containment/egress_proxy.py` (`EgressProxyServer`, CONNECT + absolute-URI forward, resolve-pin); `pyproject.toml` entrypoint `containment-egress-proxy = containment.egress_proxy:main`. Tests: `tests/test_egress_proxy.py` (`test_connect_denied_imds_via_mock_dns`, `test_connect_denied_cgnat_via_mock_dns`, `test_http_forward_denied_private`, `test_http_forward_allow_mock_public`, `test_connect_allow_then_tunnel_http`, `test_cli_help_exits_zero`, …) |
| 7 | Moltbook / HTTP fetch can use pinned client or proxy→daemon when enterprise | **PASS** | `src/containment/http_egress.py` (`fetch_url` pinned / `proxy_url`); `src/containment/moltbook.py` (`use_pinned_egress`, `proxy_url`, `CONTAINMENT_EGRESS_PINNED`, `CONTAINMENT_EGRESS_PROXY`); enterprise returns `proxy_url` hint (`enterprise.py`). Tests: `tests/test_http_egress.py` (`test_fetch_url_pinned_*`, `test_fetch_url_proxy_path`); `tests/test_moltbook.py` (`test_fetch_posts_use_pinned_egress_local`, `test_fetch_posts_honors_pinned_env`, `test_fetch_posts_honors_proxy_env`, `test_read_posts_passes_pinned_flag`). *Note:* env name is `CONTAINMENT_EGRESS_PROXY`, not stdlib `HTTP(S)_PROXY`; capability is opt-in kwargs/env (“can use”), not auto-forced solely by `enterprise_profile` |
| 8 | `AuditShipper` Protocol + file/HMAC export helper; tests | **PASS** | `src/containment/host/audit_ship.py` (`AuditShipper`, `FileAuditShipper`); chained audit body from `src/containment/audit.py` (SHA-256 `prev_hash`/`event_hash`). Test: `tests/test_host_foundation.py::test_file_audit_shipper_roundtrip`. *Note:* shipper copies JSONL; MAC chain is AuditLog SHA-256, not a separate HMAC-keyed export wrapper |
| 9 | Optional Ed25519 intents + optional Redis consume store; tested or hermetic-skipped | **PASS** | `src/containment/intent.py` (`Ed25519IntentSigner`); `src/containment/capability_store_redis.py` (`RedisConsumeStore`); extras `[crypto]` / `[redis]` in `pyproject.toml`. Tests: `tests/test_intent_ed25519.py` (module `importorskip("cryptography")`; `test_ed25519_*`, `test_broker_ed25519_*`); `tests/test_capability_store_redis.py` (fake client + `test_live_redis_try_consume_unique` skipif/unavailable skip reasons) |
| 10 | Rate/spend gate on broker privileged path | **PASS** | `src/containment/host/rate_limit.py` (`RateLimitGate`, `TokenBucketRateLimit`); `src/containment/broker.py` (`rate_limit` before mint on `PRIVILEGED_SINKS`). Tests: `tests/test_broker_rate_limit.py` (`test_privileged_first_allow_second_deny`, `test_without_rate_limit_unchanged`, `test_non_privileged_not_rate_limited`); foundation `test_token_bucket_*` |
| 11 | `build_enterprise_host()`; `docs/HOST_HARDENING.md`; AGENT_INSTALL / THREAT_MODEL / DECISIONS / README / SKILL updated | **PASS** | `src/containment/enterprise.py`; `docs/HOST_HARDENING.md`; updates present in `docs/AGENT_INSTALL.md`, `docs/THREAT_MODEL.md`, `DECISIONS.md`, `README.md`, `SKILL.md`; exports in `src/containment/__init__.py`. Tests: `tests/test_enterprise_compose.py` (7 tests incl. checklist/gate/rate/proxy) |
| 12 | Latency microbench in PROGRESS_LOG; version **1.3.0** on tree and `origin/main` | **PASS** | `scripts/microbench_host.py`; PROGRESS_LOG step 11 records n=2000 means (resolve_and_pin ~0.016 ms, checklist/rate sub-µs). `__version__` / `pyproject.toml` = **1.3.0**. `origin/main` @ `bf14a69` (release `9e3037f` + log append); live `containment.__version__` == `1.3.0` |

## Concrete GAPs

**None evidenced** (functional). Soft naming notes only — see matrix footnotes for items 3, 7, 8.

## Match vs original leftovers vision

| Vision residual | Plan intent | Tree match |
|-----------------|-------------|------------|
| Host / OS sandbox | Encode declaration + fail-closed; do not ship Kata/gVisor | **Match.** `isolation_declared` required under HostGate / `build_enterprise_host`; residual called out in `docs/HOST_HARDENING.md` + THREAT_MODEL non-goals |
| Egress beyond literal URL guard | Resolve-pin + in-repo Python resolve-pin-forward proxy | **Match.** `egress_resolve` + `egress_proxy` + moltbook/http wire; CGNAT deny closed |
| Secrets (no plaintext HMAC in examples) | `SecretProvider` Env/File | **Match.** Providers + enterprise factory; install docs scrubbed of inline `secret=b"..."` |
| Audit shipping / WORM | `AuditShipper` export; WORM still host | **Match.** `FileAuditShipper` + AuditLog hash chain; docs: export ≠ WORM |
| Rate / spend (LLM10) | Broker privileged hook | **Match.** Optional `RateLimitGate` on privileged sinks |
| Broker bypass by buggy host | Fail-closed when gate on; residual if host skips broker | **Match.** HostGate on `secure_execute` before mint; `CapabilityMinter` alone has no HostGate (documented host residual / laziness) |

## Explicit non-goals still respected

No Kata/gVisor images, no iron-proxy MITM clone, no Claude Code auto-wire, no FedRAMP claims, no “zero residual without proxy/isolation” — consistent with `LEFTOVERS_HARDEN_PLAN.md` non-goals and HOST_HARDENING residual language.

## Slice A conclusion

**PASS.** Bar B 1.3.0 as shipped satisfies LEFTOVERS done-predicate 1–12 with test-backed evidence. Remaining honesty: host must declare isolation, run proxy/pin, and vault secrets; library refuses enterprise execute when checklist incomplete.
