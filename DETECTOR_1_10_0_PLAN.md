# DETECTOR 1.10.0 PLAN — honest fresh holdout, zero-dep learned scorer, ONNX FP fusion

Authorizing request (K, 2026-11-15, pt87u): "Could you, please, work on fixing those remaining
limits that you've mentioned?" — the v1.9.0 residuals: (a) no-model mode misses injections
planted in neutral-sounding prose in long documents; (b) ONNX false positives on
security-adjacent documents. Plus: the 1.9.0 holdout was small and built knowing its gaps,
so measure honestly on a fresh, independent, frozen set first.

This file is law. PROGRESS_LOG.md is append-only. Box only. GitHub-only release, NO PyPI.

## Step 0 — fresh independent holdout (frozen BEFORE any detector change)

0.1 Sources (licenses checked 2026-11-15, recorded in fixtures/fresh/SOURCES.md):
  Attacks — holdout-only sources (never used for training or tuning):
  - microsoft/BIPIA `benchmark/text_attack_test.json`, `code_attack_test.json` (MIT; attack
    strings only — BIPIA contexts come from third-party datasets and are NOT used).
  - uiuc-kang-lab/InjecAgent attacker instructions (MIT).
  - ethz-spylab/agentdojo injection-task goals rendered with its published attack templates (MIT).
  - deepset/prompt-injections **test** split, label=1 (Apache-2.0).
  Attacks — training pool only (for the learned scorer; never in the fresh holdout):
  - deepset/prompt-injections train split, Lakera/gandalf_ignore_instructions train (MIT),
    BIPIA *train* attack files, repo train fixtures (mutation/gap train split).
  Benign (security-adjacent heavy, multilingual), document-disjoint train/holdout by
  sha256(doc_id) % 3 == 0 → holdout:
  - Wikipedia security articles EN/RU/JA/DE/FR/ES (CC BY-SA 4.0; attribution in SOURCES.md),
  - NVD CVE descriptions (public domain, US Gov), OWASP Cheat Sheet Series + OWASP Top 10 for
    LLM (CC BY-SA 4.0), MITRE ATT&CK technique descriptions (MITRE terms, attribution),
  - deepset test split label=0 (holdout) / train split label=0 (train pool).
0.2 Different generation process: attacks are planted into carrier documents by a NEW script
  (`scripts/build_fresh_holdout.py`, its own templates and seed) — email, HTML page with real
  markup, README/markdown, JSON tool output, chat log, and long neutral-prose documents
  (benign holdout prose, payload at a random offset). Plus each attack bare.
0.3 Freeze: fixtures/fresh/{holdout,train_pool}.jsonl + MANIFEST.sha256 committed before any
  detector change. Report 1.9.0 on the fresh holdout in both modes, per source.
  The fresh holdout is never inspected item-by-item for tuning; only aggregate numbers.
  Error analysis for tuning uses the train pool only.

## Step 1 — zero-dependency learned scorer + structural shift signals (residual a)

1.1 Hashed char-n-gram (3–5) + word (1–2) linear model, trained offline (scratch venv with
  numpy/sklearn, NOT a runtime dependency) on train-pool windows; weights quantized (int8,
  2^16 buckets) and shipped as package data (`containment/_data/ngram_scorer.bin`, small).
  Runtime is pure Python (stdlib zlib.crc32 hashing); whole document scanned with sliding
  windows using prefix sums (O(n) per document). Feature transform identical at train/infer.
1.2 Structural signals: addressee/register shift (window agent-addressed / 2nd-person imperative
  while the document baseline is not), imperative-density spike vs document median.
1.3 Fusion in Stage 0: high learned score → finding; mid score → needs corroboration
  (shift/spike/structural cue). Thresholds tuned on train pool only.
1.4 Latency budget: keep zero-dep under ~2x 1.9.0 per KB; report.

## Step 2 — ONNX FP reduction via fusion/calibration (residual b)

2.1 Mid-confidence model hits (t_hi ≤ p < very-high) require corroboration (structural cue,
  learned scorer, shift signal) unless the window is agent-addressed.
2.2 Discourse features: "about attacks" (discussion markers, quoting, third person, headings,
  CVE/advisory framing) vs "addressed to the agent"; applied only to mid-confidence hits.
2.3 Per-window calibration: use the probability of the window that triggered, with its context.
2.4 Never trade recall: any change that lowers train-pool or old-suite recall is reverted.
  Quoted-attack content still raises at least a low-severity finding (1.9.0 behaviour).

## Step 3 — verify, document, release
- Fresh holdout both modes (1.9.0 vs 1.10.0, per source), old suites (fixtures, mutations,
  gaps) — recall not lower; FPs lower (esp. ONNX on security docs); ASR policy-on 0.
- Tests (scorer determinism, weights integrity sha256, sliding window coverage, fusion,
  shift signals, ONNX corroboration), release_gate, CI green, version 1.10.0, CHANGELOG/docs
  keeping "no detector catches every injection", skill pin minimal edit, release venv, doctor.

## Out of scope
PyPI; adaptive/white-box attacks; retraining the ONNX model; policy semantics changes.
