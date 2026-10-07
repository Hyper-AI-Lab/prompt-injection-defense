# Leftovers swarm aggregate — 2026-10-07 JST

**Base SHA:** `0c17a98` (containment 1.2.0)  
**Shape:** coverage partition N=4 local executors  
**Selection:** all slices required

| Slice | Topic | Verdict |
| --- | --- | --- |
| 01 | HostGate / SecretProvider / AuditShipper | **ISSUES** |
| 02 | egress_resolve / pin / proxy | **ISSUES** |
| 03 | Ed25519 / Redis / rate | **PASS** |
| 04 | Coherence / docs / claims | **PASS** |

## Issue one-liners (evidenced)

1. No `containment.host`; enterprise only forces signed intents; plaintext HMAC in README/AGENT_INSTALL.
2. `url_guard` literal-only; connect re-resolves (rebinding TOCTOU); **CGNAT 100.64/10 not denied** by `is_private`.
3. No egress proxy daemon / pinned client; moltbook dials by hostname.
4. Steps 7–9 fit existing seams (HMAC parallel Ed25519; Protocol store → Redis; rate hook before mint).

## Gaps / dropouts

None. Plan law unchanged; CGNAT already in step-4 deny table (confirm in implementation).

## Proceed

Execute `LEFTOVERS_HARDEN_PLAN.md` steps 2→11. Do not alter law.
