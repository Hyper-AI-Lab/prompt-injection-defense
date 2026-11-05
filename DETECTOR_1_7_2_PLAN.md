# Plan: containment 1.7.2 — detector coverage for the 2026-11 threat check

Law for this patch. Approved by K on 2026-11-05 (JST). Source of truth:
`THREATCHECK_2026-11.md` (scratch) and its 11 attack fixtures. GitHub-only release; no PyPI.

## Problem
v1.7.1 blocked all 11 new attack techniques only through policy (untrusted taint /
default deny). The detector cascade flagged 0/11, so a host with a looser policy has no
second layer.

## Steps (each has a check)
1. Baseline at `21da2ef`: eval ON (53 attacks / 36 benign, ASR 0.0000, FPR 1/36),
   pytest 347 passed / 2 skipped. Check: numbers recorded in PROGRESS_LOG.md.
2. Add the 11 fixtures to `fixtures/attacks/` and a regression test that requires
   `detector_blocked` (not policy) for each. Check: test fails on 1.7.1 code.
3. Stage-0 rules (`detectors/rules.py`), each a structured `Finding` with weight ≥ 0.4:
   - `tool_call_directive`: text telling the agent to call a tool and pass conversation
     content (Log-To-Leak).
   - `secret_exfil_directive`: secret/credential files or keys + send/upload verb + URL or
     email destination.
   - `url_data_exfil_code`: code that appends serialized data (`to_json`, `os.environ`, …)
     to a URL query.
   - `package_swap_directive`: `use X instead of Y` / `import X as Y` where X is a
     look-alike of Y (edit distance ≤ 2, not an affix variant like `ujson`/`json`).
   - `forged_role_tag`: `<think>`, `<reasoning>`, ChatML/Llama/system role tags.
   - `approval_claim`: spoofed compaction/session summaries claiming prior approval or
     telling the agent not to ask again.
   - `error_fallback_steering`: error/403/FAILED text followed by a "fallback/fix
     procedure" that uploads/posts/sends.
   - `agent_addressed_directive`: text addressed to "AI assistant:" / "assistants must
     first" (banners, hidden email notes).
   - `refusal_suppression`: bans on refusal words, disclaimers or warnings.
   - `css_hidden_text`: HTML text hidden by `display:none`, `visibility:hidden`,
     zero font, zero opacity, white-on-unset background, off-screen positioning.
   - `morse_run`: Morse-code runs decoded to ≥ 2 words (encoding discovery).
   Directive rules run on NFKC text with invisible characters removed.
   Check: unit test per rule (hit + benign near-miss).
4. Benign near-miss fixtures, one per new rule, in `fixtures/benign/`.
   Check: eval FPR ≤ 1/36 (≤ 0.0278), report exact count.
5. Trust propagation: `labels.derive_label(...)` (lowest integrity, highest
   confidentiality, merged transformations) and `ingest(..., derived_from=...)`.
   Check: tests that a summary of any untrusted input stays untrusted.
6. Version 1.7.2 (pyproject, `__version__`, CHANGELOG, doc pins), DECISIONS entry.
   Check: `scripts/release_gate.sh` exit 0; eval card gate=PASS; `containment doctor
   --install-only` OK.
7. Commit, push `main`, CI green; `scripts/cut_release.sh 1.7.2` dry run, then
   `--execute` (tag + attested GitHub Release). Check: release URL, attestations verified.
8. Append evidence to PROGRESS_LOG.md; push.

## Out of scope
PyPI publishing (G0); policy changes; ML Stage-1 changes.
