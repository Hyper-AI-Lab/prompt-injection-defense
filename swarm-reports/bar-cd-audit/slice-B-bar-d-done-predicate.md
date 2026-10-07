# Slice B — REFERENCE_HOST done-predicate matrix (Bar D / 1.5.0)

**Slice:** B (Bar D done-predicate map)  
**Tree:** `/workspace/prompt-injection-defense` @ `933ead21a5e1ce449b4a40c35de2d740cefe955c` (short `933ead2`; containment **1.5.0**; `origin/main` same)  
**Law:** `REFERENCE_HOST_PLAN.md` done-predicate items 1–5 + Explicit non-goals; clarifications/residuals from `PROGRESS_LOG.md` Bar D sections  
**Mode:** analysis only (no product code edits)  
**Verdict:** **PASS**

## Summary

All five REFERENCE_HOST done-predicate items map to **PASS** with file + test + CLI evidence on this tree. Architecture vision (`build_enterprise_host` + signed intents + `BrokeredRegistry` + ingest; hermetic attack deny / benign allow / `require_human`→approve; live Moltbook opt-in fail-closed) matches the shipped package. Accepted residuals from PROGRESS_LOG (`isolation_declared` honor-system; live Moltbook optional) are documented and do **not** violate done-predicate or non-goals. No concrete functional GAPs evidenced.

## Matrix (items 1–5)

| # | Predicate (abbrev) | Result | Evidence |
|---|-------------------|--------|----------|
| 1 | Every step VERIFIED with PROGRESS_LOG evidence | **PASS** | `PROGRESS_LOG.md` Bar D: Plan+Baseline VERIFIED (23:07 JST); Step 2 Fixtures+core VERIFIED; Step 3 Scenarios VERIFIED; Step 4 CLI VERIFIED; Step 5 Tests VERIFIED; Step 6 Docs+exports VERIFIED; Step 7 Final prove-it VERIFIED; Step 7 post-push VERIFIED (`fc3c77d` then tip `933ead2`). Each section ends `Verdict: VERIFIED`. |
| 2 | Package `containment.reference_host` + CLI `containment-reference-host`: offline-by-default scenarios (attack deny, benign allow, require_human approval); uses `build_enterprise_host` + secrets under tmp + `BrokeredRegistry` + `ingest`; Moltbook live only behind `CONTAINMENT_LIVE_MOLTBOOK` | **PASS** | Package: `src/containment/reference_host/{__init__,host,scenarios,cli}.py` + `fixtures/`. `host.build_reference_host` → `build_enterprise_host(...)` with `secrets_dir` under `work_dir/secrets/`, `BrokeredRegistry(enterprise.broker, plan, ...)`, hermetic stubs; `sign_intent` / `call` bind `IntentSigner` + `SignedIntent`. Scenarios use `ingest` (`scenarios.py`). CLI: `pyproject.toml` `[project.scripts] containment-reference-host = containment.reference_host.cli:main`. Live: `cli._run_live_moltbook` refuses unless `LIVE_ENV` (`CONTAINMENT_LIVE_MOLTBOOK`) `== "1"` → exit 2. Live CLI evidence (no env): refuse message. Hermetic CLI: `--scenario all` → 3 PASS, exit 0 (this slice). Tests: `test_live_moltbook_refused_without_env` (rc==2); `test_no_live_network_in_default_suite`. |
| 3 | Hermetic tests cover all three paths; no placeholders; audit events asserted | **PASS** | `tests/test_reference_host.py` (10 tests): `test_attack_denies_tainted_email`, `test_benign_allows_web_fetch`, `test_human_requires_approval_then_allows`, `test_run_all_three_pass`, CLI + live refuse + direct host + offline guard. This slice: `pytest tests/test_reference_host.py -q` → 10 passed. Audit asserts inside scenarios before `ok=True`: attack `no-tainted-egress` deny; benign `read-public-web` allow; human `approved-email` `require_human` (`scenarios.py` L121–126, L175–179, L258–263). Placeholder scan on `src/containment/reference_host/` + test file: no TODO/FIXME/NotImplemented/placeholder (only typing `tuple[...,]` ellipsis). Fixtures present (pkg + `tests/fixtures/reference_host/`). |
| 4 | `docs/REFERENCE_HOST.md` + README / AGENT_INSTALL / DECISIONS / SKILL / exports updated | **PASS** | `docs/REFERENCE_HOST.md` (quick run, three paths, API, residuals). `README.md` Bar D blurb + CLI. `docs/AGENT_INSTALL.md` §10. `DECISIONS.md` 2026-10-07 ADOPT + non-goals. `SKILL.md` wiring recipe + doc link. Exports: `containment.reference_host.__all__`; top-level `containment.__init__` imports/exports `build_reference_host` (and related). Hatch force-include: `src/containment/reference_host/fixtures`. Workflow SKILL also references CLI (PROGRESS_LOG Step 6). |
| 5 | `release_gate.sh` exit 0; version **1.5.0** on `origin/main` | **PASS** | Version: `pyproject.toml` + `containment.__version__` == **1.5.0**. `origin/main` @ `933ead2` (same as HEAD). PROGRESS_LOG Step 7 post-push: release_gate OK, 287 passed, ASR 0.0000. Bar C+D Audit Step 1 baseline (same tip): release_gate exit 0; 287 passed, 2 skipped; ASR **0.0000**. |

## Architecture vision match

| Vision element | Tree match |
|----------------|------------|
| `build_enterprise_host` | **Match.** `host.build_reference_host` calls it with policy, audit paths, secrets_dir, `isolation_declared`/`egress_configured`, `known_tools`. Live probe: `checklist.ok()` True; `PinnedEgressProvider` + `FileSecretProvider` + `FileAuditShipper` bound. |
| Signed intents | **Match.** `ReferenceHost.sign_intent` / `call` require `IntentSigner` → `SignedIntent` (`mac`, `plan_hash`, …). Enterprise gate path. |
| `BrokeredRegistry` | **Match.** Constructed on `enterprise.broker` + demo `Plan`; tools `web.fetch` / `email.send` registered; `registry.call` is the invoke path. |
| `ingest` | **Match.** Attack/benign scenarios call `containment.ingest.ingest`; default integrity `untrusted` (attack). |
| Hermetic attack deny (`no-tainted-egress`) | **Match.** CLI + tests: effect=deny, rule_id=`no-tainted-egress`; stub never runs (`send_log` unchanged). |
| Hermetic benign allow (`read-public-web`) | **Match.** CLI + tests: effect=allow, rule_id=`read-public-web`; hermetic fetch body. |
| `require_human` → approve | **Match.** CLI + tests: phase1 fail-closed without hook; `approve_all` → send; audit `require_human`/`approved-email`. |
| Live Moltbook opt-in fail-closed (`CONTAINMENT_LIVE_MOLTBOOK`) | **Match.** CLI + `test_live_moltbook_refused_without_env`; `moltbook.LIVE_ENV` constant. Default suite monkeypatches urllib and asserts no network. |

## Explicit non-goals still respected

| Non-goal | Status |
|----------|--------|
| Eval card / release ritual / bot playbook | Not shipped in reference_host; deferred per plan |
| Auto-wire Claude.app | Documented residual in `docs/REFERENCE_HOST.md` + DECISIONS; points to RUNTIME_ADAPTER |
| OS sandbox / FedRAMP claims | Not claimed; `isolation_declared` honor-system called out |
| LLM round-trips in CI | Hermetic stubs only; no model calls |
| Live network required for prove-it | Offline default; live behind env flag |

## PROGRESS_LOG clarifications / residuals

| Residual (from Bar D log) | Disposition vs done-predicate |
|---------------------------|-------------------------------|
| `isolation_declared` honor-system in demo | **Accepted residual** — documented in REFERENCE_HOST.md + DECISIONS non-goals; matches plan honesty, not a GAP |
| Live Moltbook optional / off by default | **Accepted residual** — required by predicate item 2 (behind env); tests enforce refuse |
| Claude.app hooks not auto-wired | **Accepted residual** — Bar D non-goal; RUNTIME_ADAPTER owns that surface |

## Soft notes (not functional GAPs)

| ID | Note |
|----|------|
| D-B-S1 | `docs/REFERENCE_HOST.md` attack narrative writes `ingest(..., integrity="untrusted")`; code uses ingest default (`integrity="untrusted"`). Behavior matches; wording is slightly more explicit than the call site. |
| D-B-S2 | `run_human` phase1 defensively accepts `deny` + `"human approval"` in exception text if effect ≠ `require_human`. Live CLI/tests currently observe `require_human`. Soft looseness only; audit still requires `require_human`/`approved-email` for PASS. |

## Concrete GAPs

**None evidenced** (functional). Soft notes D-B-S1/S2 only.

## CLI evidence (this slice, hermetic)

```text
containment-reference-host --scenario all
# [PASS] attack: effect=deny rule_id=no-tainted-egress — ...
# [PASS] benign: effect=allow rule_id=read-public-web — ...
# [PASS] human: effect=require_human rule_id=approved-email — ...
# OK — 3 scenario(s) passed  (exit 0)

# without CONTAINMENT_LIVE_MOLTBOOK:
# refusing --live-moltbook without CONTAINMENT_LIVE_MOLTBOOK=1 (fail closed)
# (test asserts exit 2)
```

## Package scan checklist

| Surface | Present |
|---------|---------|
| `host.py` | Yes — config, builder, stubs, sign/call/audit helpers |
| `scenarios.py` | Yes — attack / benign / human / run_all |
| `cli.py` | Yes — scenarios + live fail-closed |
| `fixtures/` | `attack_inject.txt`, `benign_note.txt` (+ test mirror) |
| `tests/test_reference_host.py` | 10 hermetic tests |
| `docs/REFERENCE_HOST.md` | Yes |
| CLI entry `containment-reference-host` | Yes (`pyproject.toml`) |

## Slice B conclusion

**PASS.** Bar D 1.5.0 as shipped at `933ead2` / `origin/main` satisfies REFERENCE_HOST done-predicate 1–5 with test- and CLI-backed evidence. Vision and PROGRESS_LOG residuals align; no ISSUES IDs (D-B1, …) raised for functional gaps.
