# Swarm aggregate — Bar A enterprise library harden

**Date:** 2026-10-07 JST  
**SHA audited:** `765a618` (`containment==1.1.0`)  
**Shape:** partition N=6 local executors (coverage)  
**Selection:** every slice required

## Result table

| Slice | Topic | Verdict | Report |
| --- | --- | --- | --- |
| 1 | Signed intents | ISSUES | `slice-1-signed-intents.md` |
| 2 | Capability store | ISSUES | `slice-2-capability-store.md` |
| 3 | SSRF / URL | ISSUES | `slice-3-ssrf-url.md` |
| 4 | SBOM / CI | ISSUES | `slice-4-sbom-ci.md` |
| 5 | OWASP / red-team | ISSUES | `slice-5-owasp-redteam.md` |
| 6 | PIGuard / residuals | ISSUES | `slice-6-piguard-residuals.md` |

**Gaps / dropouts:** none.

## Issue one-liners (proven)

1. IntentEnvelope unsigned and unused by broker; principal_authenticated defaults True.
2. Capability consume set is process-local; no pluggable store Protocol.
3. No reusable url_guard; public_only is literal-IP weak; moltbook base_url unconstrained and follows redirects.
4. No `.github/` CI, Dependabot, SBOM, or pip-audit; floating `>=` deps.
5. No in-tree OWASP LLM Top10 map; red-team corpus missing split/suffix/homoglyph/tool-result/HITL-urgency/SSRF/leak/size families.
6. PIGuard-on path exists but no operator recipe / CONTAINMENT_STAGE1; host residuals buried in threat model only.

## Ranked harden backlog → plan

P0 signed intents HMAC + broker verify · P0 capability ConsumeStore Protocol + memory + sqlite · P0 url_guard + moltbook · P0 CI+SBOM+pip-audit · P0 OWASP map + ≥10 fixtures · P0 PIGuard enable docs/env · P1 plan_hash in intent · P1 residual docs in AGENT_INSTALL.
