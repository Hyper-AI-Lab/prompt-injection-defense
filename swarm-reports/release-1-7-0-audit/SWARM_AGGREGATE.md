# Release 1.7.0 audit aggregate — 2026-10-19 JST

**Base:** `v1.7.0` / `8d18e31` (HEAD `6155a1f`)  
**Slices:** 7, local (box only; no Cloud Agents)

| Slice | Verdict |
| --- | --- |
| A cut_release.sh | PASS |
| B publish.yml security | PASS |
| C doctor | ISSUES (G1 MED, G2 MED, G3 LOW) |
| D packaging | ISSUES (G5 LOW) |
| E playbook vs API | ISSUES (G6 LOW, G4 LOW) |
| F docs consistency | PASS |
| G release assets + attestations | PASS |

## Fresh baseline

`release_gate.sh` exit 0: ruff clean, **337 passed, 2 skipped** (live Redis, live Moltbook opt-in), policy-ON ASR **0.0000**, FPR 0.0278, utility 0.9722, blocked 53/53, scan clean. Clean build reproduces the release assets byte for byte. Wheel venv: doctor install-only 2/2, full host 8/8, eval card gate=PASS (ON 0.0000 / OFF 1.0000), reference host 3/3.

## ISSUES to clear

- **G1 MED** doctor crashes on unreadable secret file.
- **G2 MED** doctor prints proxy URL credentials.
- **G3 LOW** doctor crashes on malformed proxy URL; bad port passes.
- **G4 LOW** unpinned `[crypto]`/`[redis]` runtime install hints.
- **G5 LOW** sdist lacks `scripts/` → shipped tests error.
- **G6 LOW** playbook plan/ingest order.

## Accept as residual

- Card not in `release_gate`; actions pinned by major tag; host owns isolation / egress enforcement / WORM / secret rotation; PyPI not published until G0; earlier Bar C–E residuals (private `_entries`, unmapped Claude tools deny, `isolation_declared` honor-system, Claude install ≠ wired, live Moltbook opt-in, reference host no `--policy`, `card_from_dict` trusts flags, `--suite` label only).
- A-L1: cut_release does not enforce empty `[Unreleased]` / compare link (runbook-owned).
- G-N1: reproducible builds mean main-ref attestations also match release digests; tag-bound verify still holds.
- B-N1: open green Dependabot PRs for ci.yml actions — K's merge decision.

## Post-harden (step 4)

- **G1 CLEARED** — `host.secrets` catches `OSError`; test `test_unreadable_secret_fails_with_report`.
- **G2 CLEARED** — `_redact_url` in egress details; test `test_proxy_credentials_never_appear_in_output`.
- **G3 CLEARED** — `_proxy_url_ok` (scheme, host, port) before provider build; 5-case parametrized test.
- **G4 CLEARED** — `intent.py` ×2 + `capability_store_redis.py` use `extra_install_hint`; test `test_runtime_extra_hints_pin_this_version`.
- **G5 CLEARED** — sdist include `/scripts`; test + unpacked 1.7.1 sdist pytest **347 passed, 2 skipped**.
- **G6 CLEARED** — playbook §3 Plan / §4 Ingest; test `test_playbook_declares_plan_before_ingest`.
- New tests fail on the 1.7.0 code (6 doctor cases + hint test) and pass after.
- `release_gate.sh` exit 0: **347 passed, 2 skipped**, ASR 0.0000; wheel venv: doctor 8/8, malformed/credential proxy cases fail or redact with valid JSON, eval card PASS, reference host 3/3.
- Version **1.7.1** (behaviour change in doctor + error hints).

### Verdict: VERIFIED
