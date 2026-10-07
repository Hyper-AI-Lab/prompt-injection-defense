# Slice C — adapters / registry / hooks / broker integrity

**SHA:** `933ead21a5e1ce449b4a40c35de2d740cefe955c` (`933ead2`)  
**Version:** 1.5.0  
**When:** 2026-10-08 00:23 JST  
**Scope:** `src/containment/adapters/{registry,openai_tools,claude_hook}.py` + interaction with `ToolBroker` / `PRIVILEGED_SINKS` / HostGate-adjacent broker paths  
**Mode:** read-only analysis; tests run for evidence; **no** `src/` or `tests/` edits  

## Verdict

**ISSUES**

Core Bar C claim holds for the *happy* single-threaded path: unknown registry names deny; public registry API has no raw invoke; `brokered_tool` only calls `registry.call`; Claude CLI fail-closes on bad JSON / unmapped tools; adapter unit tests green (18 passed). Production integrity gaps remain: Claude Write tool-id drift vs `PRIVILEGED_SINKS`, shared-broker executor mutation race, and PreToolUse calling `secure_execute` (mint/execute) instead of evaluate-only.

## What was proved (bypass matrix)

| Claim | Result | Evidence |
| --- | --- | --- |
| BrokeredRegistry cannot invoke without `ToolBroker.secure_execute` via public API | **Hold** | `call()` always assigns executor then `secure_execute` (`registry.py:145-158`); no `invoke_raw` / `get_fn` / `__getitem__` (`test_only_call_executes_no_public_raw_invoke`) |
| Unknown registry names deny | **Hold** | `unknown_registry_tool` (`registry.py:106-113`; `test_unknown_name_denied_never_calls`) |
| Privileged sinks require non-empty `input_labels` | **Partial** | Hold for `PRIVILEGED_SINKS` / `_LABEL_REQUIRED_SINKS`. **Fail** for Claude-mapped `fs.write` (not in set). See C-C1 |
| Claude unmapped / malformed → deny | **Hold** | `map_claude_tool` None → deny; CLI bad JSON → deny exit 0 (`test_unknown_tool_denied`, `test_cli_malformed_json_still_exit_0`) |
| `allow` / `deny` / `require_human`→`ask` mapping | **Hold** for decision JSON | Tests `test_allow_with_inline_policy`, `test_require_human_maps_to_ask`. **Undermined** when broker has executor: side effects may run before `ask`/`allow` returned. See C-C3 |
| Docs RUNTIME_ADAPTER vs code | **Drift** | Docs/threat model say `file.write` privileged; Claude map uses `fs.write`. See C-C1 / C-C8 |

## Test evidence

```text
.venv/bin/pytest tests/test_adapters_registry.py \
  tests/test_adapters_openai.py \
  tests/test_adapters_claude_hook.py -q
# 18 passed
```

Probe scripts (venv) additionally demonstrated C-C1 / C-C2 / C-C3 (not covered by current tests).

## Issues

### C-C1 — HIGH — Claude `fs.write` escapes privileged-sink protections

**Symptom.** Write/Edit map to containment tool id `fs.write` (`claude_hook.py:53-54`). `PRIVILEGED_SINKS` lists `file.write`, not `fs.write` (`detectors/cascade.py:34-41`). Broker `_LABEL_REQUIRED_SINKS` likewise omits `fs.write` (`broker.py:25`).

**Proof.** With an allow-rule for `fs.write` and empty `input_labels`, `BrokeredRegistry.call` **allowed and executed** the callable (`fired=1`). Same setup for `file.write` denied with `empty_input_labels`. `fail_closed_privileged=True` **allowed** `fs.write` and denied `file.write` with `detector_fail_closed`.

**Impact.** Empty-label fail-closed, detector fail-closed selection, and privileged rate-limit charging do not apply to Claude Write/Edit once a host adds an allow rule. Docs claim privileged sinks need labels (`RUNTIME_ADAPTER.md:50`, `:128-130`); THREAT_MODEL lists `file.write` (`docs/THREAT_MODEL.md:11`). PROGRESS_LOG already noted the naming residual (ship-time honesty), but behavior is still wrong for production allow policies.

**Fix direction (for parent fix cluster).** Align ids: map Write/Edit → `file.write`, or add `fs.write` to `PRIVILEGED_SINKS` / `_LABEL_REQUIRED_SINKS` (+ schemas/rate-limit), and update policies/docs/tests.

### C-C2 — HIGH — `BrokeredRegistry.call` mutates shared `broker.executor` (cross-wire race)

**Symptom.** `call()` does `prev = self._broker.executor; self._broker.executor = _executor; … finally: restore` (`registry.py:148-157`). Two concurrent `call`s on one broker/registry can install each other's executor.

**Proof.** Concurrent `reg.call("a", …)` and `reg.call("b", …)` with distinct fns tagged A/B observed `outs={'b': 'A:https://example.com/b', 'a': 'A:…'}` → **`executor_cross_wire_observed True`**.

**Impact.** Wrong callable may run under a capability minted for the other call. Production multi-threaded hosts sharing one `ToolBroker` are unsafe.

**Fix direction.** Pass executor per `secure_execute` invocation (API change), or use a lock + deep isolation; do not swap a shared mutable `executor` field.

### C-C3 — HIGH — `handle_pretool_use` uses `secure_execute` (mint / optional execute), not evaluate-only

**Symptom.** PreToolUse should gate Claude's tool run. Implementation calls `broker.secure_execute` (`claude_hook.py:171-172`), which mints a one-use capability and runs `broker.executor` when set (`broker.py:388-401`).

**Proof.**

1. Broker with allow policy + `executor=…` → decision `allow`, **`executor_fired 1`**.
2. Broker with `require_human` + approval hook returning `ApprovalOutcome()` + executor → hook returns **`ask`** but **`fired 1`** (tool already ran; Claude still told to ask).

CLI `_build_broker` does not set an executor (safe for the stock entrypoint). Library / enterprise compose reuse is the footgun.

**Impact.** Side effects and capability minting during a permission hook; `ask` can lie after execution.

**Fix direction.** Add evaluate-only broker path (policy+gates, no mint/execute), or force `executor=None` and skip mint inside the hook; never share an executing broker with PreToolUse.

### C-C4 — MEDIUM — No JSON schemas for Claude-mapped / shell / file tools

**Symptom.** `TOOL_ARG_SCHEMAS` only covers `web.fetch`, `email.send`, `http.post`, `wallet.transfer` (`tool_schemas.py:11-78`). `shell.exec`, `fs.write`, `fs.read`, `file.write` hit the “unknown → structural pass” branch (`tool_schemas.py:96-98`).

**Proof.** `registry_schema_validator("shell.exec", {"command":"x","extra_evil":True})` and same for `fs.write` raise nothing.

**Impact.** Extra/malformed args not fail-closed at schema; TypeError may surface from `entry.fn(**args)` as a raw exception rather than `SecurityViolation` if a host registers callables with strict signatures.

**Fix direction.** Add schemas for `shell.exec` / `file.write` (and alias `fs.*` if kept) with `additionalProperties: false`.

### C-C5 — LOW — Registry early label gate narrower than broker

**Symptom.** Registry pre-check uses `PRIVILEGED_SINKS` only (`registry.py:123`). Broker uses `_LABEL_REQUIRED_SINKS = PRIVILEGED_SINKS | {"social.publish"}` (`broker.py:25,262`).

**Proof.** `social.publish` + empty labels still denied by broker (`empty_input_labels`) after passing registry early check. Not a bypass.

**Impact.** Inconsistent early-deny surface; docs only mention `PRIVILEGED_SINKS`.

**Fix direction.** Registry should use the same set as broker (export `_LABEL_REQUIRED_SINKS` or share a public constant).

### C-C6 — LOW — Private `_entries[name].fn` still callable without broker

**Symptom.** Python private attribute access runs the registered callable directly.

**Proof.** `reg._entries["my_shell"].fn(command="whoami")` returned without broker; public API still clean (`test_only_call_executes_no_public_raw_invoke`).

**Impact.** Matches “no *public* path” claim; not a library bypass vs a determined host. Residual / honor-system for callers who keep the original fn (always true for `@brokered_tool` decoratee before wrap).

### C-C7 — RESIDUAL (accepted) — Claude tool map intentionally incomplete

Bash|Write|Edit|Read only (`claude_hook.py:51-56`). Unmapped (Glob, Grep, WebFetch, NotebookEdit, …) deny. Documented (`RUNTIME_ADAPTER.md:81`, matcher note `:119-120`). Plan done-predicate listed those four. Not a bug if hosts use `"*"` matcher and accept deny, or extend the map.

### C-C8 — MEDIUM — Doc / threat-model / code tool-id drift

| Surface | Tool id for writes |
| --- | --- |
| `PRIVILEGED_SINKS` / THREAT_MODEL | `file.write` |
| Claude map / default_claude_plan / claude_code_hooks.yaml / RUNTIME_ADAPTER table | `fs.write` |
| `TOOL_ARG_SCHEMAS` | neither |

RUNTIME_ADAPTER residual text claims empty-label fail-closed “still applies … for PRIVILEGED_SINKS” during hooks (`:128-130`) while always injecting labels — true for `shell.exec`, **not** for Write→`fs.write` under allow policies (C-C1).

## Docs cross-check (`docs/RUNTIME_ADAPTER.md`)

| Doc claim | Code |
| --- | --- |
| Only `call()` → `secure_execute` | True for public API |
| Unknown names → `unknown_registry_tool` | True |
| Privileged sinks need labels | True for `PRIVILEGED_SINKS`; false for `fs.write` |
| `brokered_tool` reserved kwargs | Matches `openai_tools.py:47-57` |
| Claude map Bash/Write/Edit/Read; else deny | Matches |
| allow / deny / ask mapping | Decision JSON matches; execute side effects undocumented (C-C3) |
| Env flags + fail-closed missing policy | Matches `main()` |
| Install ≠ wired; user can disable hooks | Honest residual |

## Broker / HostGate interaction (adapters)

Adapters do not special-case HostGate. If the shared broker is enterprise (`require_host_gate` / signed intent), Claude hook and registry inherit fail-closed gates via `secure_execute`. That is correct composition, but amplifies C-C3 (hook should not mint/execute under those paths either).

## Bypass attempts summary

| Attempt | Outcome |
| --- | --- |
| Unknown registry name | Deny `unknown_registry_tool` |
| Privileged `shell.exec` empty labels | Deny `empty_input_labels` (registry + broker) |
| `social.publish` empty labels | Deny at broker `empty_input_labels` (C-C5) |
| `fs.write` empty labels + allow policy | **ALLOW + execute (C-C1)** |
| Public raw invoke | None (tests) |
| Private `_entries[].fn` | Callable (C-C6 residual) |
| Concurrent registry calls | **Cross-wired executor (C-C2)** |
| Claude unmapped / bad JSON | Deny |
| Claude allow/ask with executor on broker | **Side effect runs (C-C3)** |

## Suggested fix priority (parent Step 4 cluster C)

1. C-C1 tool-id / PRIVILEGED_SINKS alignment  
2. C-C3 PreToolUse evaluate-only (no mint/execute)  
3. C-C2 per-call executor isolation  
4. C-C4 schemas for shell/file tools  
5. C-C5/C-C8 shared label-required constant + doc sync  

Do not treat C-C6/C-C7 as blockers if docs stay honest.

## Principles applied

- **Prove it works** — runtime probes, not test-green alone  
- **Attack the premise** — “privileged Write is covered because shell is” failed under `fs.write` naming  
- **Test behavior, not implementation** — cross-wire and empty-label allow are behavioral failures current tests miss  
