# Audit: RUNTIME_ADAPTER + REFERENCE_HOST plans vs code (Bar C+D / 1.5.0)

**Date:** 2026-10-08 JST  
**Tree:** `933ead2` → harden toward **1.5.1** if behavior fixes land  
**Inputs:** `RUNTIME_ADAPTER_PLAN.md`, `REFERENCE_HOST_PLAN.md`, `BAR_CD_AUDIT_HARDEN_PLAN.md`, `swarm-reports/bar-cd-audit/SWARM_AGGREGATE.md`, PROGRESS_LOG Bar C/D

## Done predicate matrices

### Bar C — RUNTIME_ADAPTER (items 1–6)

| # | Result | Evidence / gap |
|---|--------|----------------|
| 1 | **PASS** | PROGRESS_LOG Bar C steps VERIFIED through `dafa58b` |
| 2 | **PASS*** | BrokeredRegistry + tests; *integrity bug C2 concurrent executor (fix) |
| 3 | **PASS** | `brokered_tool` allow/deny tested |
| 4 | **PASS*** | Claude hook + CLI; *C3 dry_run / ask-after-execute footgun (fix) |
| 5 | **PASS*** | Docs/exports present; *X1–X3 claim/layout drift (fix) |
| 6 | **PASS** | 1.4.0 shipped; tree now 1.5.0 |

### Bar D — REFERENCE_HOST (items 1–5)

| # | Result | Evidence / gap |
|---|--------|----------------|
| 1 | **PASS** | PROGRESS_LOG Bar D steps VERIFIED |
| 2 | **PASS** | `containment.reference_host` + CLI; hermetic scenarios; live fail-closed |
| 3 | **PASS** | `tests/test_reference_host.py` green; CLI `--scenario all` PASS |
| 4 | **PASS*** | Docs present; *ARCHITECTURE/README omit modules (X1/X2) |
| 5 | **PASS** | 1.5.0 on `origin/main` @ `fc3c77d`/`933ead2` |

## Architecture / vision match

| Vision | Match | Notes |
|--------|-------|-------|
| Consequence containment at tool boundary (C) | **Match** with HIGH gaps | Public API sealed; C1 privilege id drift; C2 race; C3 PreToolUse side effects |
| Reference host = wiring recipe (D) | **Match** | enterprise + signed intents + BrokeredRegistry + ingest; three hermetic paths |
| install≠wired / isolation honor / live Moltbook opt-in | **Match** | accepted residuals |

## GAP list (law steps 4–7 must clear)

| ID | Sev | Cluster | Action |
|----|-----|---------|--------|
| C1 | HIGH | C | Add `fs.write`/`fs.read` to `PRIVILEGED_SINKS`; schemas; docs align |
| C2 | HIGH | C | Per-call `executor=` on `secure_execute`; registry stops mutating shared field |
| C3 | HIGH | C | `dry_run` on `secure_execute`; Claude hook always dry_run |
| C4 | MED | C | Schemas for shell.exec / file.write / fs.write / fs.read |
| C5 | LOW | C | Registry uses broker label-required set |
| X1 | docs | X | ARCHITECTURE.md modules |
| X2 | docs | X | README package layout |
| X3 | docs | X | Reference-host policy packaging note |

**Accept residuals:** C-C6 private `_entries`, C-C7 unmapped deny, isolation_declared honor, Claude install≠wired, live Moltbook opt-in.

## Verdict after Step 3

Plan match is **strong** for Bar D and **strong-with-integrity-GAPs** for Bar C. Production-complete claim blocked until C1–C3 fixed and gate green.


## Post-fix status (Steps 4–7) — 2026-10-08 JST

Behavior fixes landed → version target **1.5.1** at Step 8.

| ID | Status | Notes |
|----|--------|-------|
| C1 | **CLEARED** | `fs.write`/`fs.read` in `PRIVILEGED_SINKS`; schemas; docs |
| C2 | **CLEARED** | Per-call `executor=` on `secure_execute`; concurrent cross-wire test |
| C3 | **CLEARED** | `dry_run` on broker; Claude PreToolUse always `dry_run=True` |
| C4 | **CLEARED** | Schemas for `shell.exec` / `file.write` / `fs.write` / `fs.read` |
| C5 | **CLEARED** | Public `LABEL_REQUIRED_SINKS`; registry early gate; exported from `containment` |
| X1 | **CLEARED** | `docs/ARCHITECTURE.md` modules: adapters + reference_host |
| X2 | **CLEARED** | `README.md` package layout |
| X3 | **CLEARED** | `docs/REFERENCE_HOST.md` policy packaging residual |

**Integrity (Step 7):** placeholder/TODO scan clean on adapters/reference_host/broker; Edit/Read map assertions added; pytest **293 passed**, 2 skipped; ruff clean on changed surfaces.

**Accepted residuals (unchanged):** C-C6 private `_entries`; C-C7 unmapped Claude tools deny; `isolation_declared` honor-system; Claude install≠wired; live Moltbook opt-in; reference-host no `--policy` (documented).
