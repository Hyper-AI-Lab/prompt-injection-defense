# Slice A — Bar C done-predicate matrix (RUNTIME_ADAPTER / 1.4.0 → tree 1.5.0)

**Slice:** A (Bar C done-predicate map)  
**Tree:** `/workspace/prompt-injection-defense` @ `933ead2` (containment **1.5.0**; Bar C closed at **1.4.0** / `dafa58b`, ancestor of HEAD)  
**Law:** `RUNTIME_ADAPTER_PLAN.md` done-predicate items 1–6 + Explicit non-goals + PROGRESS_LOG Bar C sections  
**Mode:** analysis only (no product code edits)  
**Adapter tests this slice:** `pytest tests/test_adapters_{registry,openai,claude_hook}.py` → **18 passed**  
**Verdict:** **ISSUES**

## Summary

Done-predicate items **1–6 all map to PASS** with file + test evidence. Architecture vision (BrokeredRegistry → ProposedAction → `ToolBroker.secure_execute` only; privileged sinks need labels; Claude PreToolUse thin adapter; install≠wired residual documented) matches the plan and PROGRESS_LOG clarifications.

One **concrete integrity bug** evidenced under concurrent use of a shared registry/broker (**C-A1**). Remaining notes are accepted residuals or soft coverage — not done-predicate fails.

## Matrix (items 1–6)

| # | Predicate (abbrev) | Result | Evidence |
|---|-------------------|--------|----------|
| 1 | Every step VERIFIED in PROGRESS_LOG | **PASS** | `PROGRESS_LOG.md`: Bar C Plan+Baseline 22:53 JST; Steps 2–5 each `Verdict: VERIFIED`; Step 6 prove-it + post-push `Verdict: VERIFIED (Bar C complete)` @ `dafa58b` / 1.4.0 |
| 2 | `BrokeredRegistry`: register→callable; invoke only via `secure_execute`; unknown deny; privileged sinks need labels; bypass impossible through registry API | **PASS** | `src/containment/adapters/registry.py` (`register`, `call` → `ProposedAction` + temp executor + `secure_execute`; unknown → `unknown_registry_tool`; `PRIVILEGED_SINKS` + empty labels → `empty_input_labels`; public API `register`/`call`/`names` only). Tests: `tests/test_adapters_registry.py` — `test_allow_path_returns_callable_result`, `test_deny_path_raises_security_violation`, `test_unknown_name_denied_never_calls`, `test_privileged_without_labels_denied`, `test_only_call_executes_no_public_raw_invoke`, `test_sync_known_tools_on_register`, `test_plan_factory` |
| 3 | `brokered_tool` / OpenAI-style wrapper; args → ProposedAction; allow + SecurityViolation | **PASS** | `src/containment/adapters/openai_tools.py` (`brokered_tool` → `registry.register` + wrapper → `registry.call` only; strips `_input_labels`/`_plan_*`). Tests: `tests/test_adapters_openai.py` — `test_brokered_tool_allow`, `test_brokered_tool_deny_raises`, `test_brokered_tool_rejects_positional` |
| 4 | CLI `containment-claude-hook`: PreToolUse stdin→decision JSON; Bash\|Write\|Edit\|Read map; default-deny; hermetic fixtures; settings snippet in docs | **PASS** | `src/containment/adapters/claude_hook.py` (`map_claude_tool`, `handle_pretool_use`, `main`); `pyproject.toml` script `containment-claude-hook = containment.adapters.claude_hook:main`; `policies/claude_code_hooks.yaml`; fixtures `tests/fixtures/claude_hook/{bash_rm,unknown_tool}.json`. Tests: `tests/test_adapters_claude_hook.py` — `test_map_bash_and_write`, `test_bash_rm_denied_default_policy`, `test_unknown_tool_denied`, `test_allow_with_inline_policy`, `test_require_human_maps_to_ask`, `test_malformed_event_denied`, `test_cli_stdin_bash_deny`, `test_cli_malformed_json_still_exit_0`. Docs sample `.claude/settings.json`: `docs/RUNTIME_ADAPTER.md` |
| 5 | `docs/RUNTIME_ADAPTER.md` + AGENT_INSTALL / README / SKILL / DECISIONS / exports; no plaintext secrets; no placeholders | **PASS** | `docs/RUNTIME_ADAPTER.md` present; README Bar C blurb + link; `docs/AGENT_INSTALL.md` §9; `DECISIONS.md` 2026-10-07 ADOPT; repo + workflow `SKILL.md` runtime-adapters paragraph; exports in `src/containment/__init__.py` + `adapters/__init__.py` (`BrokeredRegistry`, `brokered_tool`, `handle_pretool_use`, `map_claude_tool`, `default_claude_plan`). Docs use `secret_bytes` / SecretProvider language — no `secret=b"..."` inline. `rg TODO\|FIXME\|NotImplemented` under `src/containment/adapters/` → empty (ellipsis only in type hints / docstring examples) |
| 6 | `release_gate.sh` exit 0; version **1.4.0** on `origin/main` | **PASS** | PROGRESS_LOG Step 6 post-push: gate OK, 277 passed, ASR=0.0000 @ `dafa58b` / **1.4.0**. Tree advanced by Bar D to **1.5.0** @ `933ead2` (1.4.0 commit is ancestor). Live `__version__` == `1.5.0` — supersession, not Bar C incompleteness |

## Architecture vision match

| Vision | Plan intent | Tree match |
|--------|-------------|------------|
| BrokeredRegistry → ProposedAction → `ToolBroker.secure_execute` only | No public raw invoke | **Match.** `call()` builds action; swaps executor; only `secure_execute` runs fn. Tests assert no `invoke_raw` / `get_fn` / `__getitem__` |
| Privileged sinks need labels | H1 spirit / `PRIVILEGED_SINKS` | **Match.** Registry pre-check + broker `_LABEL_REQUIRED_SINKS`. *Residual:* mapped Claude ids `fs.write`/`fs.read` are **not** in `PRIVILEGED_SINKS` (only `file.write`) — accepted in PROGRESS_LOG Step 5/6; default-deny still denies |
| Claude PreToolUse thin adapter | stdin JSON → `permissionDecision` allow\|deny\|ask | **Match.** `handle_pretool_use` / CLI; `require_human` → `ask` via `default_approval_hook` → `SecurityViolation` catch (mint count 0 on ask); allow uses `secure_execute` with `executor=None` (no tool side effect; does mint unused capability — soft residual) |
| install≠wired residual | Non-goal: auto-install / cannot-skip-hooks claim | **Match.** Documented in `docs/RUNTIME_ADAPTER.md` Residuals, README, SKILL, PROGRESS_LOG |

## Explicit non-goals still respected

No LangGraph-only plugin, no full MCP server product, no auto-install into Claude without user settings, no claim that Claude Code cannot disable hooks — consistent with plan non-goals and RUNTIME_ADAPTER residual language.

## Concrete GAPs / issues

### C-A1 — Concurrent `BrokeredRegistry.call` cross-wires shared `broker.executor` (integrity bug)

**Evidence:** `src/containment/adapters/registry.py` L148–157 assigns `self._broker.executor = _executor` then restores `prev` with no lock. Hermetic repro on this tree (two threads, `web.fetch` + `http.post`, barrier before `secure_execute`): both calls returned `'POST'` and `seen == [('post', …/p), ('post', …/f)]` — fetch arguments executed by the post callable.

**Impact:** Multi-threaded hosts sharing one `ToolBroker` / `BrokeredRegistry` can run the wrong registered function after an allow decision. Single-threaded reference host / CLI paths unaffected. No current test covers concurrency.

**Suggested fix direction (for parent harden steps, not this slice):** pass executor as `secure_execute` argument / contextvar, or per-call broker clone — avoid mutating shared `broker.executor`.

### Soft / accepted (not done-predicate fails)

| ID | Note |
|----|------|
| C-A2 | `fs.write`/`fs.read` ∉ `PRIVILEGED_SINKS` — **accepted residual** (PROGRESS_LOG Bar C Steps 5–6); Claude hook always supplies labels; default-deny still denies |
| C-A3 | Edit/Read: map implemented (`_CLAUDE_TOOL_MAP`); dedicated `handle_pretool_use` fixtures only cover Bash + unknown — coverage soft, map unit test covers Bash/Write only |
| C-A4 | Claude **allow** path mints one unused capability (`executor is None` skips execute) — decide-via-`secure_execute` side effect; deny/ask do not mint |
| C-A5 | Python `_entries` private access can call `fn` without broker — **outside** “registry API”; public surface sealed; language residual, same class as any Python encapsulation |

## Package / scripts scan

| Surface | Status |
|---------|--------|
| `adapters/registry.py` | Present; BrokeredRegistry |
| `adapters/openai_tools.py` | Present; `brokered_tool` |
| `adapters/claude_hook.py` | Present; map + handle + CLI |
| `adapters/__init__.py` | Re-exports all five public symbols |
| `tests/test_adapters_*.py` | 3 modules, 18 tests green |
| `docs/RUNTIME_ADAPTER.md` | Present + residuals |
| `pyproject` script | `containment-claude-hook` wired |
| `policies/claude_code_hooks.yaml` | Present; force-include `/policies` in wheel |

## Slice A conclusion

**ISSUES** — done-predicate 1–6 **PASS** and Bar C vision matches plan/logs, but **C-A1** is a real concurrent executor cross-wire bug that production-grade hardening should fix before treating adapters as complete under shared-broker multi-thread use. Accept C-A2 as documented residual; C-A3–C-A5 optional follow-ups.
