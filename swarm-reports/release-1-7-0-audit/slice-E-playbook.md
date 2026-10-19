# Slice E — BOT_PLAYBOOK accuracy vs real CLI/API

**Verdict:** ISSUES (G6 LOW, G4 LOW)

Checked against code: `ingest(...)` → `IngestResult.ok`, `.extract.data`, `.label.integrity == "untrusted"`; `read_posts(sort=, limit=)`; Moltbook schema fields `title/topic/summary`; `build_enterprise_host` kwargs (`secrets_dir`, `egress_configured`, `proxy_url`, `known_tools`); `BrokeredRegistry(host.broker, plan, principal=, task_id=)`; `host.intent_signer.sign(..., plan=)`; `SecurityViolation.decision.rule_id/.reason`; `brokered_tool(registry, tool=)`; default policy 4 rules as tabled; doctor flags/exit codes; reference host output lines match the wheel run verbatim.

- **G6 (LOW)** §3 Ingest precedes §4 "Plan before reading … **before** untrusted content is read", and the intro says "Follow the steps in order". Swap §3/§4 and fix the two step cross-refs.
- **G4 (LOW)** outside the playbook: `intent.py` (2 hints) and `capability_store_redis.py` (1 hint) tell users to `pip install "containment[x] @ git+…git"` (unpinned `main`), unlike doctor/docs which pin `@vX.Y.Z`. Following it swaps the verified release for an unverified `main` build. Pin to `@v{__version__}`.
