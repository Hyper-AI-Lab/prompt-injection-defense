# Slice D — placeholders / exports / docs / claim drift (Bar C+D)

**SHA:** `933ead21a5e1ce449b4a40c35de2d740cefe955c` (`933ead2`)  
**Version:** 1.5.0  
**Scope:** read-only audit of `src/containment/adapters`, `src/containment/reference_host`, related product docs, exports, scripts, PROGRESS_LOG / DECISIONS residuals  
**When:** 2026-10-08 00:22 JST  
**Verdict:** **ISSUES**

---

## Summary

No TODO/FIXME/NotImplemented/placeholder/TBD scaffolds in Bar C/D source. Public exports and both CLI entrypoints resolve to real callables and match what RUNTIME_ADAPTER / REFERENCE_HOST / AGENT_INSTALL / SKILL / DECISIONS claim. Overclaims (FedRAMP, OS sandbox, auto-wire Claude, live Moltbook required, universal safety) are explicitly negated and aligned with accepted residuals.

Gaps are **documentation coherence / residual completeness**, not missing code scaffolds:

| ID | Severity | One-liner |
| --- | --- | --- |
| **X-D1** | med | `docs/ARCHITECTURE.md` modules table omits Bar C `adapters` and Bar D `reference_host` (README still points readers there). |
| **X-D2** | low | README “Where things live” one-liner lists `src/containment/` contents without `adapters` / `reference_host`. |
| **X-D3** | med | Claude maps Write/Edit → `fs.write`, but `PRIVILEGED_SINKS` has `file.write` not `fs.write`; RUNTIME_ADAPTER residual understates this accepted PROGRESS_LOG residual. |
| **X-D4** | low–med | `containment-reference-host` has no `--policy` / `CONTAINMENT_POLICY`; default policy is repo-checkout heuristic. Docs Quick run uses `pip install -e` (honest) but CLI help/env table omit the packaging residual that non-editable wheels ship fixtures only (no `policies/`). |

---

## 1. Placeholder scan

**Targets:** `src/containment/adapters/**`, `src/containment/reference_host/**`, plus related docs (`RUNTIME_ADAPTER`, `REFERENCE_HOST`, `AGENT_INSTALL`, `HOST_HARDENING`, `THREAT_MODEL`, README, SKILL).

**Pattern:** `TODO|FIXME|NotImplemented|NotImplementedError|TBD|scaffold|placeholder` (and `pass  #` / bare `raise NotImplementedError`).

**Result:** **clean** for product meaning of placeholders.

False positives only:

- Type / Callable ellipsis: `tuple[SecurityLabel, ...]`, `Callable[..., Any]` in adapters/registry and host signatures.
- Docstring Example body `...` in `openai_tools.py` (ellipsis placeholder in prose example, not unfinished code).

Hermetic **demo stubs** (`[hermetic-fetch]`, `[hermetic-send]`) in `reference_host/host.py` are intentional Bar D fixtures, documented as stubs in REFERENCE_HOST.md Residuals — **not** unfinished scaffolds.

`scripts/release_gate.sh` placeholder scan (same family of patterns on `src`/`tests`/`docs`/README/SKILL) was clean at Step 1 baseline for this SHA.

---

## 2. Exports vs docs claims

### `containment.adapters`

`__all__`: `BrokeredRegistry`, `brokered_tool`, `default_claude_plan`, `handle_pretool_use`, `map_claude_tool`.

Re-exported from top-level `containment` (imports + `__all__`). Matches RUNTIME_ADAPTER.md / AGENT_INSTALL §9 / SKILL / PROGRESS_LOG Bar C Step 5.

### `containment.reference_host`

`__all__` includes host constants (`APPROVED_HOST`, `STEP_FETCH`, …), `ReferenceHost`, `ReferenceHostConfig`, `build_reference_host`, fixture helpers, and scenario runners (`run_all` / `run_attack` / `run_benign` / `run_human`, `ScenarioResult`).

Top-level `containment` re-exports the public subset claimed by docs (`ReferenceHost*`, `build_reference_host`, `run_*`, `ScenarioResult`). REFERENCE_HOST.md correctly imports `STEP_FETCH` from `containment.reference_host` (not top-level) — consistent.

### API smoke (editable tree)

- `ReferenceHost.sign_intent` / `call` / `trusted_label` / `enterprise` / `registry` / `intent_signer` exist; `call()` auto-signs when `intent` omitted — matches REFERENCE_HOST Library API example.
- `default_claude_plan()` returns plan with capabilities `shell.exec` / `fs.write` / `fs.read`.

**Export claim drift:** none found.

---

## 3. `pyproject.toml` scripts

| Script | Target | Callable? |
| --- | --- | --- |
| `containment-claude-hook` | `containment.adapters.claude_hook:main` | yes (`def main(...) -> int`) |
| `containment-reference-host` | `containment.reference_host.cli:main` | yes (`def main(...) -> int`) |

CLI `--help` surfaces documented flags:

- Claude: `--policy`, `--audit`, `--principal` (+ env `CONTAINMENT_*` per RUNTIME_ADAPTER).
- Reference host: `--work-dir`, `--scenario {all,attack,benign,human}`, `--live-moltbook` (requires `CONTAINMENT_LIVE_MOLTBOOK=1`).

Companion policy `policies/claude_code_hooks.yaml` present (default deny for mapped tools).

---

## 4. Claim drift (overclaims vs residuals)

Checked README / SKILL / RUNTIME_ADAPTER / REFERENCE_HOST / AGENT_INSTALL / HOST_HARDENING / THREAT_MODEL / DECISIONS against PROGRESS_LOG Bar C+D accepted residuals.

| Claim class | Status |
| --- | --- |
| Auto-wire / auto-enable Claude hooks | **Negated** (README, RUNTIME_ADAPTER, SKILL, AGENT_INSTALL, DECISIONS non-goals, REFERENCE_HOST residuals) |
| OS sandbox / FedRAMP / SOC2 | **Negated** (README Bar B, HOST_HARDENING, DECISIONS) |
| Live Moltbook required | **Negated** — optional, env-gated, CI offline (REFERENCE_HOST, AGENT_INSTALL §10, DECISIONS Bar D) |
| Universal / immunity guarantees | README puts “Adaptive attack immunity guarantees” in **out-of-scope** column — not an overclaim |
| `isolation_declared` honor-system | Stated consistently (REFERENCE_HOST, AGENT_INSTALL, THREAT_MODEL, DECISIONS, PROGRESS_LOG) |

**No overclaim ISSUES** of the FedRAMP / auto-wire / live-required class.

---

## 5. Coherence: DECISIONS / THREAT_MODEL / HOST_HARDENING vs shipped C+D

- **DECISIONS** Bar C ADOPT (BrokeredRegistry, brokered_tool, containment-claude-hook; non-goals: LangGraph-only, full MCP product, auto-install, undeclareable hooks) matches shipped code + docs.
- **DECISIONS** Bar D ADOPT (reference_host package, three scenarios, CLI, optional live Moltbook; non-goals: eval card / release ritual / auto-wire Claude.app / OS isolation from flag) matches shipped code + docs.
- **THREAT_MODEL** / **HOST_HARDENING** residuals (isolation honor-system, egress proxy, no FedRAMP) remain consistent with Bar D demo declaring `isolation_declared=True` without proving OS isolation.

**Gap:** **ARCHITECTURE.md** (see X-D1) did not grow with Bar C/D modules; pipeline diagram still ends at bare `ToolBroker.secure_execute` with no adapter / reference-host wiring layer.

---

## 6. Reference host CLI / env docs integrity

- Flags in REFERENCE_HOST.md Options table match `cli.py` argparse and `--help`.
- `--live-moltbook` fail-closed without `CONTAINMENT_LIVE_MOLTBOOK=1` matches code + docs.
- Offline default + hermetic stubs documented honestly.
- **X-D4:** Unlike `containment-claude-hook`, reference-host CLI does **not** accept `--policy` / `CONTAINMENT_POLICY`. Policy path is `default_policy_path()` → repo-root `policies/default_deny.yaml` via `Path(__file__).parents[2]`. Wheel metadata includes `containment/reference_host/fixtures/*` only (force-include); **`policies/` is sdist/repo, not wheel package data**. Editable Quick run is correct; non-editable install residual is under-documented in CLI help and REFERENCE_HOST Options/env.

---

## 7. Issues (detail)

### X-D1 — ARCHITECTURE.md stale for Bar C+D

- **Evidence:** `docs/ARCHITECTURE.md` Modules table ends at `cli` / `eval_runner` / `moltbook`. No rows for `adapters` (BrokeredRegistry, Claude hook) or `reference_host`. README links ARCHITECTURE as a primary doc.
- **Why it matters:** Readers following architecture after 1.5.0 miss the shipped authority path (runtime → registry/hook → broker) and the reference wiring recipe.
- **Fix direction (for later harden steps):** Add module rows + a short “runtime adapter / reference host” branch on the pipeline diagram; do not invent new behavior.

### X-D2 — README layout one-liner incomplete

- **Evidence:** README ~L163: ``src/containment/ — labels, policy, broker, ingest, detectors, quarantine, moltbook, CLI`` — omits `adapters`, `reference_host` (and other post-1.0 modules, but slice focus is C+D).
- **Fix direction:** Extend the one-liner (or point solely at ARCHITECTURE once X-D1 is fixed).

### X-D3 — `fs.write` vs `file.write` / PRIVILEGED_SINKS residual under-documented

- **Evidence:**
  - Claude map: Write/Edit → `fs.write`, Read → `fs.read`, Bash → `shell.exec` (`claude_hook.py`).
  - `PRIVILEGED_SINKS` = `email.send`, `file.write`, `http.post`, `shell.exec`, `wallet.transfer` — **no** `fs.write` / `fs.read`.
  - Registry empty-label fail-closed only when `entry.tool in PRIVILEGED_SINKS`.
  - PROGRESS_LOG Bar C residuals (accepted): “`fs.write`/`fs.read` not in `PRIVILEGED_SINKS` (only `file.write`); default-deny still denies.”
  - RUNTIME_ADAPTER Residuals mention PRIVILEGED_SINKS empty-label fail-closed for hook labels but **do not** state the name mismatch; a reader can over-infer Write/Edit get privileged empty-label treatment.
- **Why it matters:** Claim/residual honesty gap; default-deny still protects, but privileged H1 path does not apply to `fs.write`.
- **Fix direction:** One residual bullet in RUNTIME_ADAPTER (+ optional AGENT_INSTALL §9): mapped `fs.write`/`fs.read` ≠ `file.write`; privileged empty-label applies to `shell.exec` among the mapped set; hosts allowing fs tools must add explicit rules **and** consider aligning names or extending sinks.

### X-D4 — Reference-host policy packaging / CLI env residual

- **Evidence:** `cli.py` has no policy flag; `host.default_policy_path()` requires checkout layout; wheel file list shows fixtures only under `containment/reference_host/`. Claude hook documents missing-policy fail-closed + `CONTAINMENT_POLICY`; reference host docs Options table does not.
- **Fix direction:** Document residual (“needs repo `policies/` or pass `policy_path=` to `build_reference_host`”); and/or add `--policy` / env for CLI parity with Claude hook (code change — outside this read-only slice).

---

## 8. Explicit non-issues (checked)

- Placeholder / TODO / NotImplemented in adapters + reference_host source: none.
- Scripts pointing at missing symbols: none.
- Docs claiming FedRAMP, OS sandbox, auto-wired Claude, or mandatory live Moltbook: none (negations present).
- Export surface vs RUNTIME_ADAPTER / REFERENCE_HOST named APIs: match.
- Hermetic stubs: intentional demo tools, documented.
- DECISIONS Bar C/D ADOPT notes vs shipped behavior: match.
- Vision residuals in PROGRESS_LOG (`isolation_declared` honor-system; live Moltbook opt-in; install ≠ wired): still accurately reflected in product residuals (except X-D3 under-documentation of the fs/file write naming residual).

---

## Verdict

**ISSUES** — four doc/coherence items (X-D1…X-D4). No code placeholders or broken export/script claims found in Bar C+D surfaces.

**Report path:** `/workspace/prompt-injection-defense/swarm-reports/bar-cd-audit/slice-D-docs-claims.md`
