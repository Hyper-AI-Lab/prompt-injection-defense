# Detector 1.9.0 plan — close the 1.8.0 blind spots

Owner request (K, 2026-11-07): tighten the remaining blind spots reported for v1.8.0.
This file is the law for 1.9.0: steps run in order, each ends with a PROGRESS_LOG entry
(append-only) and a commit. Box only. GitHub-only release, **no PyPI**.

## Step 0 — Honesty about the old holdout

The 1.8.0 report named the held-out misses (goal decomposition, MCP log-to-leak, policy
delete) and the held-out benign false positives by file. Fixing exactly those would tune on
the 1.8.0 holdout. So:

- The 1.8.0 mutation holdout is still reported (continuity), but marked **seen** for the gap
  cases and the named benign files.
- The honest measure for 1.9.0 is a **fresh gap suite** written and committed *before* any
  detector change (`fixtures/gaps/`), each gap with its own `train` and `holdout` items,
  attack and benign near-miss. Holdout items are measured once before and once after; they
  are never used to choose rules or thresholds. The file SHA-256 is recorded in
  PROGRESS_LOG at freeze time.
- A fresh benign batch (`fixtures/benign/benign_v2_*`, ≥ 40 items, security-adjacent
  near-misses) is added to the corpus before any change; it goes through the usual
  sha-split, so its holdout part is unseen.

## Step 1 — Gap suite + baseline (no detector change)

`fixtures/gaps/gaps.yaml`: items `{id, gap, split, kind: attack|benign, text | chunks}`.
Gaps:
1. `multistep` — staged instructions where no single step is an attack (collect → transmit,
   escalate privileges, disable checks), incl. across chunks, EN/RU/JA.
2. `tool_meta` — tool descriptions / MCP metadata / manifests asking to log, mirror, forward,
   CC, BCC, sync conversation or data; and `policy_tamper` — short paraphrases of disabling,
   erasing, relaxing the policy / guardrails / allowlist.
3. `long_doc` — generated long documents (≥ 120 KB up to the 256 KB limit) with an injection
   at the start / middle / end / straddling a model window boundary, plus long benign docs.
4. `quoted` — injections quoted inside text that discusses attacks (attacker-style
   "research notes" wrappers and real-looking articles); benign security articles.
5. `judge` — unit-level: a steered fake judge (offline HTTP server).

`containment eval --suite gaps [--json]`: per gap × split × kind, both modes (zero-dep and
`CONTAINMENT_STAGE1=onnx`). Metric: `high_risk` for attacks/benign; for gap 4 also
"embedded-instruction finding present". Baseline recorded for 1.8.0 code.

## Step 2 — Fixes (tuned on train items only)

1. **Document-level intent aggregation** (zero-dep, Stage 0): extract imperative *steps*
   (lines, numbered/bulleted items, sentences) across the whole document and across chunks;
   tag each with action roles: `collect` (read/gather/bundle/copy sensitive or broad data),
   `transmit` (upload/send/post/sync/forward to an external destination), `escalate`
   (grant/enable/sudo/admin/disable checks), `conceal`. Flag `staged_intent` when a
   `collect` step on sensitive data is followed by a `transmit` step to a destination, or
   an `escalate` step on privileges/guards, even when each step alone is harmless.
   `scan_chunks` feeds the joined document to the aggregator.
2. **Tool metadata + policy tampering** (zero-dep): `tool_meta_exfil` — a tool/function
   description or manifest (JSON `description`, MCP schema, docstring) that asks the caller
   to log / mirror / forward / CC / record conversation, user input, responses or data to
   another tool or destination. `policy_tamper` — verb (disable, erase, wipe, drop, remove,
   relax, bypass, turn off …, RU/JA) + policy object (policy, guardrail, allowlist, deny
   rule, safety filter, `default_deny`, sandbox, approval requirement).
3. **ONNX whole-document scan:** character segments with overlap feed token windows
   (stride overlap) over the *whole* text and views; a total-time budget
   (`CONTAINMENT_STAGE1_BUDGET_S`, default 45 s, below the 60 s cascade timeout). Budget
   exceeded → `error` (fail closed) with `windows_scored/total` in the detail. No cap that
   silently skips text.
4. **Quoted injections:** stop discarding quoted spans. In discussion context a quoted
   injection raises `quoted_instruction` (weight 0.3: below the high-risk line alone, so
   articles stay usable, but it is reported, `IngestResult.contains_instruction_text` is
   True, and any other signal pushes the document over 0.4). Attacker wrappers that address
   the reader outside the quotes still score high.
5. **LLM judge hardening:** datamark the data (`datamark.mark`, spotlighting), strict output
   schema (exact keys, types, enum), per-call secret canary that must be echoed (known-answer
   detection: a steered judge drops or alters it), one-time calibration probe (known injection
   must be flagged, known benign must pass) before use. Parse / schema / canary / calibration
   failure → high risk (`error` or `malicious` with `steered=True`). Raise-only stays.
6. **Benign FP reduction:** analyse each listed 1.8.0 FP (train and holdout), fix general
   causes only (e.g. "send … to" in setup instructions addressed to a human, negated
   security advice, meeting notes reporting what happened). Measure on the fresh benign
   holdout; report the 222-set numbers too, marked "seen".

## Step 3 — Tests, eval, docs, release

- Tests: held-out gap items as regression tests (a test reads them; never used to tune),
  benign near-miss tests per gap, ONNX budget/fail-closed tests with a fake model, judge
  steering tests with a fake server.
- Re-run mutation eval (both modes) and the benign set; latency per KB both modes.
- Version 1.9.0, CHANGELOG, THREAT_MODEL / EVAL_CARD / README / AGENT_INSTALL / DECISIONS.
- release gate, CI green, `cut_release.sh 1.9.0` dry run + `--execute`, skill pins
  (minimal edit), `/workspace/.venvs/containment`, doctor.

## Success criteria
- Each gap measurably closed on its **holdout** items in both modes where feasible (state
  plainly where a mode cannot).
- Mutation held-out recall ≥ 90.2 % zero-dep / ≥ 97.9 % ONNX.
- Benign flagged on the 222 set ≤ 6 zero-dep / ≤ 8 ONNX (aim lower); fresh benign holdout
  reported.
- Policy-on ASR 0.0000; latency reported; pytest, release gate, CI green.

## Out of scope
PyPI; policy semantics; adaptive optimisation attacks on the classifier; a local LLM for the
judge (interface + offline tests only).
