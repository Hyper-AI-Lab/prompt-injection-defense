# Audit: LEFTOVERS / leftovers vision vs containment 1.3.0

**Date:** 2026-10-07 JST  
**Tree audited:** `bf14a69` then post-fix commits  
**Laws:** `LEFTOVERS_HARDEN_PLAN.md`, `BAR_B_AUDIT_HARDEN_PLAN.md`  
**Swarm:** `swarm-reports/bar-b-audit/`

## Vision match (original leftovers)

| Vision residual | In-package close | Host still owns |
| --- | --- | --- |
| OS/container isolation | `isolation_declared` + HostGate | Real sandbox |
| DNS-aware egress | resolve-pin + egress_proxy | Running proxy / netns |
| Secret vault | SecretProvider Env/File | Real vault / KMS |
| Audit WORM/shipping | AuditShipper + FileAuditShipper | External WORM |
| Rate/spend | TokenBucketRateLimit on broker | Setting limits |
| Broker bypass | HostGate + enterprise compose | Not calling broker |

## Done-predicate 1–12

Slice A: **12/12 PASS** with evidence (see `slice-A-done-predicate.md`). Soft gaps listed as H1/D2/D3 below.

## Integrity findings → disposition

| ID | Finding | Disposition |
| --- | --- | --- |
| H1/D2 | No EgressProvider | **FIXED** step 4 |
| H2 | Secrets/shipper unbound | **FIXED** step 4 (bind + ship hook) |
| H3 | Rate optional on enterprise | **ACCEPT** residual (plan: when configured) |
| E1 | CLI docs mismatch | **FIXED** step 5 |
| E2 | IPv6 CONNECT port | **FIXED** step 5 |
| D1 | Scaffold docstring | **FIXED** step 4/6 |
| D3 | HMAC export helper | **FIXED** step 4 |
| D4 | README tone | **FIXED** step 6 light |
| D5 | release_gate rg | **FIXED** step 7 |

## Architecture judgment

Bar B matches the approved law and the leftovers vision as a **library + host-gate + resolve-pin proxy** system. It does not claim to be an OS sandbox. Soft spots (egress bool theater, unbound secrets, CLI typo, IPv6 CONNECT, release_gate) closed in steps 4–7.
