# Swarm frame — enterprise library harden (Bar A)

**Date:** 2026-10-07 JST  
**Repo artifact:** `/workspace/prompt-injection-defense` (`containment==1.1.0`)  
**Remote:** https://github.com/Hyper-AI-Lab/prompt-injection-defense  
**Bar A:** signed intents, multi-process capability store interface, SSRF/URL allowlist helpers, SBOM/CI supply-chain gates, expanded red-team + OWASP LLM Top10 mapping, optional PIGuard-on path, docs for host residual risks.

## Done predicate (swarm)

Return one consolidated report with PASS/ISSUES/BLOCKED per slice, evidence paths, and a ranked harden backlog that feeds `ENTERPRISE_HARDEN_PLAN.md`. No code changes in swarm workers.

## Shape

**Partition** (coverage, not race). N=6 local executors (Task has no `generalPurpose`/`environment:cloud`; box holds the verdant tree). Selection: every slice must report.

## Slices

1. Signed intents / IntentEnvelope  
2. Multi-process capability store interface  
3. SSRF / URL allowlist helpers vs `web.fetch` / `http.post`  
4. SBOM / CI supply-chain gates  
5. Expanded red-team fixtures + OWASP LLM Top 10 mapping  
6. Optional PIGuard-on path + host residual-risk docs  

## Worker report format

File: `swarm-reports/slice-<N>-<slug>.md`  
Verdict line: `VERDICT: PASS|ISSUES|BLOCKED`  
Then evidence, gaps vs Bar A, proposed surgical harden items (no gold-plate).
