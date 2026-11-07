# Benign fixture provenance

- `benign_*` files written for 1.7.x and the 1.8.0 expansion (emails, tickets, docs, code, logs,
  HTML newsletters, multilingual RU/JA/DE/FR/ES/ZH/PT/IT/KO text) are synthetic and written for
  this repository (Apache-2.0). Names, addresses, keys and account numbers are fictitious.
- `benign_stdlib_*.txt` are module or class docstrings copied from the CPython 3.13 standard
  library (Python Software Foundation License 2.0).

## benign_v2_* (added 2026-11-07, 1.9.0)

41 hand-written security-adjacent near-misses: IAM/firewall/policy docs that mention
default-deny, disabling, or allowlists without instructing the agent; phishing-awareness and
password-reset text that quotes attacker phrasing; tool READMEs / MCP docs that describe
logging, mirroring, forwarding, CC without asking the agent to exfiltrate; multi-step
runbooks (setup, backup, release) with no collect-then-transmit; multilingual (RU/JA/DE/FR/ES)
business and security text; a newsletter preheader hidden by CSS. All original prose written
for this repo to stress the 1.9.0 detector without live instructions to an agent.
