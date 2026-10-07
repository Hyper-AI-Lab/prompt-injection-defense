# Leftovers Harden Plan — Bar B + Egress Proxy (library + host close)

**Date:** 2026-10-07 JST  
**Mode:** poteto-mode / figure-it-out / local swarm  
**Inputs:** K approval (Bar B + in-repo Python egress proxy); THREAT_MODEL residuals §; AGENT_INSTALL §8; research (Hermes iron-proxy pattern, SSRF-beyond-HTTP resolve-pin, NVIDIA agent sandbox guidance)  
**Bar:** B — Host Residual Close + in-repo resolve-pin-forward Python egress proxy  
**Host:** box only for implementation; append-only `PROGRESS_LOG.md`  
**Version:** bump to **1.3.0** at final prove-it only  
**Standing rule:** no Cursor Cloud Agents unless K asks; local executor swarm only

## Done predicate

1. Every step VERIFIED with PROGRESS_LOG evidence (command output / test counts).
2. `scripts/release_gate.sh` exit 0 after all steps; no placeholders / TODOs / NotImplemented in shipped code paths.
3. **HostGate:** under enterprise / `require_host_gate`, broker refuses capability mint and privileged `secure_execute` unless `HostChecklist` passes (`isolation_declared`, `SecretProvider`, `EgressProvider` or proxy URL, `AuditShipper`).
4. **SecretProvider** Protocol with `EnvSecretProvider` + `FileSecretProvider`; install examples use providers, not inline raw HMAC secrets.
5. **Resolve-pin:** `egress_resolve` resolves DNS, checks deny CIDRs (loopback, link-local/IMDS, RFC1918, ULA, CGNAT, IPv4-mapped), returns pinned address; **pinned connect** helper; tests cover metadata/private denies.
6. **In-repo egress proxy daemon:** Python HTTP forward proxy (`containment.egress_proxy`) that resolve-pin-forwards; CLI `containment-egress-proxy`; integration tests (local loop) prove deny of IMDS/private and allow allowlisted public (mocked DNS or controlled hosts).
7. Moltbook / HTTP fetch path can use pinned client or `HTTP(S)_PROXY` pointing at the daemon when enterprise profile is on.
8. **AuditShipper** Protocol + file/HMAC export helper; tests.
9. Optional **Ed25519** intent signer alongside HMAC; optional **Redis** consume store behind `[redis]` extra; both tested or hermetic-skipped with real skip reasons.
10. **Rate/spend gate** hook on broker privileged path (LLM10 residual).
11. `build_enterprise_host()` composition; `docs/HOST_HARDENING.md`; AGENT_INSTALL / THREAT_MODEL / DECISIONS / README / SKILL updated.
12. Latency microbench script recorded in PROGRESS_LOG; version **1.3.0** on tree and `origin/main`.

## Explicit non-goals

- Kata/gVisor/microVM images or Kubernetes operator
- Cloning Hermes iron-proxy (Go) or credential-injection TLS MITM (our proxy is resolve-pin-forward HTTP, not credential vault MITM)
- Auto-wiring Claude Code / ChatGPT / Cursor product
- FedRAMP / SOC2 certification claims
- Claiming zero residual when host runs without the proxy / isolation declaration
- DNS-rebinding immunity without using pinned connect or the proxy (document residual if host bypasses both)

## Execution steps (law)

1. **Baseline** — record gate + pytest + eval metrics; no code changes.
2. **Host foundation** — `containment.host`: `SecretProvider` (Env/File), `HostChecklist`, `AuditShipper` Protocol + `FileAuditShipper`, `RateLimitGate` Protocol + `TokenBucketRateLimit`; unit tests.
3. **Broker HostGate** — `require_host_gate` / enterprise profile wiring; fail-closed mint + privileged execute; tests.
4. **egress_resolve + pin** — module + pinned connect helpers; extend beyond literal `url_guard`; tests (including deny CIDR table).
5. **egress_proxy daemon** — HTTP forward proxy resolve-pin-forward; CLI entrypoint; hermetic tests (deny private/IMDS; allow mock public).
6. **Wire fetch paths** — moltbook / optional http helper prefer pinned client or proxy when enterprise; tests.
7. **Ed25519 intents** — optional signer/verify alongside HMAC; broker accepts either when configured; tests.
8. **Redis consume store** — optional `[redis]` extra + `RedisConsumeStore`; tests skip if redis unavailable.
9. **Rate/spend on broker** — enforce `RateLimitGate` when configured; tests.
10. **Docs + composition** — `build_enterprise_host()`; `docs/HOST_HARDENING.md`; update AGENT_INSTALL/THREAT_MODEL/DECISIONS/README/SKILL/exports.
11. **Final prove-it** — microbench script; version 1.3.0; release_gate; push `origin/main`; hand back metrics.

After each step: verify command, append PROGRESS_LOG, do not start next until VERIFIED.  
Do not add sub-steps or alter this law unless execution would be poor without a documented plan amendment logged in PROGRESS_LOG first.
