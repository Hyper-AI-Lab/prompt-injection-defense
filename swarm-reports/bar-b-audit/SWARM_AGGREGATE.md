# Bar B audit swarm aggregate — 2026-10-07 JST

**Base:** bf14a69 / containment 1.3.0  
**N=4 local**

| Slice | Verdict |
| --- | --- |
| A done-predicate | PASS (12/12; soft naming notes) |
| B host/broker | ISSUES |
| C egress | ISSUES |
| D docs/claims | ISSUES |

## ISSUES to clear (steps 4–7)

**H1** EgressProvider missing; bool lie path for egress_configured  
**H2** HostGate presence-only for SecretProvider/AuditShipper (no bind / no ship-on-path)  
**H3** enterprise does not require rate_limit (accept as documented residual OR optional checklist field) — **accept residual** per plan “when configured”; document in AUDIT report  
**E1** HOST_HARDENING CLI `--host/--port` vs `--listen`  
**E2** IPv6 CONNECT without port awkward fail-closed  
**D1** HostChecklist scaffold docstring  
**D2** same as H1 naming  
**D3** HMAC export helper gap on FileAuditShipper  
**D4** README soft tone (low)  
**D5** release_gate rg gaps  

## Accept as residual (threat model)

- opener DI bypass (tests)  
- proxy-wins over pin  
- isolation_declared honor system  
- rate_limit optional under enterprise  
