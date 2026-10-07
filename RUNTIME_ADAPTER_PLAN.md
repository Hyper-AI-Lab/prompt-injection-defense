# Runtime Adapter Plan — Bar C (→ 1.4.0)

**Date:** 2026-10-07 JST  
**Mode:** poteto-mode / figure-it-out / local executors  
**Inputs:** K approval (Bar C as framed); Claude Code hooks reference (PreToolUse stdin JSON → `hookSpecificOutput.permissionDecision` allow|deny|ask|defer); containment 1.3.1  
**Bar:** C — Runtime adapter: BrokeredRegistry + OpenAI-style wrapper + Claude Code PreToolUse CLI  
**Host:** box only; append-only `PROGRESS_LOG.md`  
**Version:** bump to **1.4.0** at final prove-it only

## Done predicate

1. Every step VERIFIED with PROGRESS_LOG evidence.
2. `containment.adapters` ships `BrokeredRegistry`: register name→callable; invoke only via `ToolBroker.secure_execute`; unknown tools denied; privileged sinks require labels; tests prove bypass impossible through registry API.
3. `brokered_tool` / OpenAI-style wrapper: decorate callables; arguments become ProposedAction; tests cover allow + SecurityViolation.
4. CLI `containment-claude-hook`: reads PreToolUse JSON stdin; maps Bash|Write|Edit|Read|… to ProposedAction + default-deny policy path; writes PreToolUse decision JSON (`permissionDecision` deny|allow + reason); hermetic fixture tests; sample `.claude/settings` snippet in docs.
5. `docs/RUNTIME_ADAPTER.md` + AGENT_INSTALL / README / SKILL / DECISIONS / exports updated; no plaintext secrets; no placeholders.
6. `release_gate.sh` exit 0; version **1.4.0** on `origin/main`.

## Explicit non-goals

- LangGraph-only plugin, full MCP server product, auto-install into Claude without user settings
- Bars for demo / eval card / release ritual / bot playbook (later)
- Claiming Claude Code cannot be configured to skip hooks (host config residual)

## Execution steps (law)

1. **Baseline** — gate + pytest + eval; no code.
2. **BrokeredRegistry** — `src/containment/adapters/registry.py` (+ package); tests.
3. **OpenAI-style wrapper** — `brokered_tool` decorator/helper; tests.
4. **Claude Code PreToolUse hook** — `containment.claude_hook` + CLI entrypoint; tool name→action map; fixtures; tests.
5. **Docs + exports** — RUNTIME_ADAPTER.md; wire pyproject scripts; README/AGENT_INSTALL/SKILL/DECISIONS/__init__.
6. **Final prove-it** — version 1.4.0; release_gate; push origin/main; hand back.

After each step: verify, append PROGRESS_LOG, do not start next until VERIFIED.
