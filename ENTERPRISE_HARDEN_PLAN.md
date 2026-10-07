# Enterprise Harden Plan — Bar A (library)

**Date:** 2026-10-07 JST  
**Mode:** poteto-mode / figure-it-out / swarm-fed  
**Inputs:** `swarm-reports/SWARM_AGGREGATE.md` + slices 1–6  
**Bar:** A (signed intents, capability store interface, SSRF/URL helpers, SBOM/CI, OWASP map + red-team, PIGuard-on path, host residual docs)  
**Host:** box only for implementation; append-only `PROGRESS_LOG.md`  
**Version:** bump to **1.2.0** at final prove-it only

## Done predicate

1. Every step VERIFIED with PROGRESS_LOG evidence.
2. `scripts/release_gate.sh` exit 0; GitHub Actions workflow present and locally dry-runnable where feasible.
3. Signed IntentEnvelope (HMAC) verified in broker before mint when enterprise profile / `require_signed_intent`.
4. `CapabilityConsumeStore` Protocol with Memory + SQLite backends; default Memory; tests for cross-instance consume via SQLite.
5. `url_guard` module wired into policy/broker/moltbook; redirects disabled on moltbook opener; tests for metadata IP / userinfo / bad scheme.
6. `.github/workflows/ci.yml` + dependabot; SBOM (CycloneDX) + pip-audit in CI or release_gate optional path; document how to run locally.
7. `docs/OWASP_LLM_TOP10_MAP.md` + ≥10 new attack fixtures from swarm table; corpus tests updated.
8. `CONTAINMENT_STAGE1` / documented PIGuard-on recipe in README + AGENT_INSTALL; host residual checklist in install docs.
9. Placeholder scan clean; no Out-of-Bar-A scope (no FIDES/CaMeL/full egress proxy/Ed25519 required in 1.2 — Ed25519 optional stub only if cheap).

## Explicit non-goals

Full CaMeL/FIDES; Meta PG2 default download; OS sandbox; DNS-rebinding-complete SSRF; Redis as required dep; claiming FedRAMP/SOC2 certification.

## Execution steps (law)

1. **Baseline** — record gate + pytest + eval metrics; no code changes.
2. **Capability consume store** — Protocol + MemoryStore + SqliteStore; wire CapabilityMinter; tests.
3. **Signed intents (HMAC)** — sign/verify IntentEnvelope; bind task_id, principal, scope, issued/expiry, plan_hash; broker `require_signed_intent` / enterprise profile; tests.
4. **url_guard** — module + wire policy/broker; harden public_only; tests.
5. **Moltbook URL harden** — check base_url; no-follow redirects; max read; tests.
6. **OWASP map doc** — `docs/OWASP_LLM_TOP10_MAP.md` from slice-5 mapping.
7. **Red-team fixtures** — add ≥10 attack fixtures (+ combined split if needed); update corpus tests; ≥3 benign counterparts optional if FPR stable.
8. **PIGuard-on + residuals** — env/config `CONTAINMENT_STAGE1`; README/AGENT_INSTALL/SKILL recipes; host residual checklist.
9. **CI supply-chain** — `.github/workflows/ci.yml` (ruff, pytest, release_gate, pip-audit, cyclonedx if installable); `.github/dependabot.yml`; pin action SHAs when practical.
10. **Exports + DECISIONS** — public exports; DECISIONS adopt notes; THREAT_MODEL residual updates for signed intent / SSRF / multi-process.
11. **Final prove-it** — version 1.2.0; release_gate; push `origin/main`; hand back metrics.

After each step: verify command, append PROGRESS_LOG, do not start next until VERIFIED.
