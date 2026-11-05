# Plan: containment 1.8.0 — wording-independent detector

Law for this release. Approved by K on 2026-11-05 (JST): "It should strive to protect against
any possible prompt-injection. That was the plan from the start, but if it wasn't properly
implemented, we should fix it." Box only (no Cloud Agents). GitHub-only release; **no PyPI**.
Execute steps in order; after each step run its check and append evidence to
`PROGRESS_LOG.md` (append-only). One point, one solution.

## Step 1 — Audit: detector as built vs the original plan (2026-10-06/07)

Sources: `KIRILL_RESEARCH.md` §"Detector cascade" (lines ~308–318), `DEVELOPMENT_PLAN.md`
(2026-10-07) steps 7–8 and 17, `DECISIONS.md` (Stage-1 entries), code at `fb88cc6`.

What the plan said:
- Stage 0 deterministic parser (normalize, hidden chars, markup stripping, encoded-content
  discovery, schemas).
- **Stage 1 local fast classifier** ("Prompt Guard 2 22M/86M, StackOne Defender, PIGuard, or
  an independently benchmarked local classifier") run on **all untrusted fields**.
  DEVELOPMENT_PLAN: "Detector default: rules + PIGuard when weights available".
- Stage 2 contextual detector (AlignmentCheck / sequence rules) for ambiguous/sensitive flows.
- "Build local attack/benign datasets and calibrate detector thresholds per workflow and
  language"; "AdaptiveAttackAgent … mandatory before claiming a detector … is robust".

What shipped (verified in code, 1.0.0 → 1.7.2):
1. **The only detector that ever runs is Stage-0 regex/heuristics** (`detectors/rules.py`):
   invisible/control chars, NFKC change, base64/hex/percent/rot13/Morse *presence*, a size
   limit, and the eleven 1.7.2 phrase/proximity rules. `RulesOnlyDetector` and
   `PassthroughStage1` (the default Stage 1 everywhere: `ingest`, `eval`, reference host)
   just re-run Stage 0 — Stage 1 is a mirror, not a second detector.
2. **The ML screener was planned, adapted, never shipped as a working default and never
   measured.** `PIGuardDetector` / `PromptGuard2Detector` / `StackOneDetector` adapters exist
   and are unit-tested only with fakes. `select_stage1(prefer="piguard")` silently returns
   rules-only unless `allow_download=True`; the `[ml]` extra (torch + transformers) was never
   installed on the box; PROGRESS_LOG has no run with real weights and no recall/FPR number
   for any model. PIGuard loading also needs `trust_remote_code=True` (runs repo Python).
   Prompt Guard 2 is gated (`gated: manual`) and cannot be fetched without K's HF account.
3. **Stage 2 is `NoOpContextualDetector`** (always `inconclusive`, excluded from aggregation).
4. **No calibration and no paraphrase/adaptive evaluation** was ever run, contrary to the
   research plan. The suite has 64 attacks written alongside the rules that catch them.
5. **The reported detector number is inflated by an eval-only regex.** `eval_runner.
   _INSTRUCTION_HINT_RE` ("ignore previous instructions", "system prompt", "you are now", …)
   counts toward `detector_block_rate` but is **not** in the production cascade, so
   `ingest()` never flags plain "Ignore previous instructions".
6. Encoding findings fire on presence, not content: a 40-char git SHA (`hex_run`, weight 0.4)
   alone makes text `high_risk` — a false-positive source on real code/logs.
7. CSS hiding is inline-`style` only (stated in 1.7.2 residuals); `<style>` classes, the
   `hidden` attribute and ancestor inheritance are not handled.

Why it is wording-bound: every Stage-0 directive rule is a lexicon/regex over English
surface forms (e.g. `must … call <dotted.tool>` + `user_query`, `context compacted` +
`approved`). A paraphrase, another language, an indirect third-person phrasing, or a split
across chunks removes the literal cue, and nothing semantic sits behind it.

**Verdict: not implemented per plan.** The plan's core detector layer (an independently
benchmarked local classifier on all untrusted text, calibrated per language) exists only as
optional, unmeasured adapters; production runs regex only. Policy containment (taint +
default deny) was implemented and is why ASR stayed 0.

## Step 2 — Measure the gap first (no detector change in this step)

- `fixtures/mutations/paraphrases.yaml`: hand-written meaning-preserving variants for **every**
  attack fixture: `reword` (English rewording), `indirect` (third-person / embedded-in-document
  phrasing), `ru` (Russian), `ja` (Japanese).
- `src/containment/mutation_eval.py`: programmatic families derived per case: `synonym`
  (synonym-table substitution of the original), `split` (reword split into two chunks scanned
  separately), `b64` / `hex` / `url_escape` / `rot13` (reword encoded behind a neutral cue),
  `md_wrapper` (code block / blockquote), `html_comment`, `css_class` (`<style>` class with
  `display:none` etc., text in a classed element).
- Held-out split by **case group**: a case is held out iff `int(sha256(case_id), 16) % 3 == 0`;
  all variants of a held-out case are test-only.
  The split is printed by the eval and frozen in `fixtures/mutations/SPLIT.md`.
- Expanded benign corpus (≥ 200 total): realistic emails, tickets, docs, READMEs, code, CI
  logs, HTML newsletters with real `<style>` classes, hashes/JWTs/base64 images, agent rule
  files with legitimate conventions, multilingual (RU/JA/DE/FR/ES/ZH) business text, and
  benign text that talks about prompt injection. Same case-group split for benign
  (train = tuning only).
- Metric = **detector-only** (policy off): `cascade.high_risk` from the production `ingest`
  cascade (no eval-only regex). Report per category, train vs held-out, originals vs variants.
- Check: `containment eval --suite mutations` prints the table; numbers for `fb88cc6` recorded
  in PROGRESS_LOG before any detector change.

## Step 3 — Layered, wording-independent detector

1. **Honest eval:** move `_INSTRUCTION_HINT_RE` into Stage 0 as `override_phrase`; eval
   measures exactly the production cascade.
2. **Decode-then-rescan:** base64/hex/percent/rot13/Morse payloads are decoded (bounded size,
   depth ≤ 2) and the decoded text is rescanned by the full stack; encoded *instructions* are
   flagged (`encoded_instruction`). Bare non-text blobs (hashes, binary base64) keep their
   finding but stop forcing `high_risk` alone. Existing finding kinds stay.
3. **Computed CSS hiding:** stdlib `html.parser` walk with `<style>` rules (class, id, tag,
   tag.class, selector lists), inline style, `hidden` attribute, ancestor inheritance;
   hidden text ≥ 4 words → `css_hidden_text` (replaces the inline-only regex as the source).
4. **Structural intent signals (zero-dependency):** per text window, categories rather than
   phrases — addressing the AI/agent/reader in 2nd person, imperative/obligation, override of
   prior instructions/rules/policy, concealment from the user, authority/approval spoofing,
   and action targets (tools, secrets, outbound destinations, money, privileged ops). Lexicons
   cover EN/RU/JA/DE/FR/ES/ZH/PT/IT. A finding needs a co-occurrence of ≥ 2 categories in one
   window, never a single word. Runs in the default (no-deps) cascade.
5. **ML Stage 1 (optional extra `[ml]` = onnxruntime + tokenizers + numpy, no torch):**
   generic `OnnxClassifierDetector` with a pinned model registry (repo, revision SHA, file
   SHA-256), `containment models fetch` (download + verify), windowed scoring (max over
   windows) and a load-time self-test. Model chosen by measurement (Step 3 research):
   candidates Horizon-Labs prompt-injection-guard small/base (Apache-2.0, multilingual,
   indirect-trained, ONNX), ProtectAI deberta-v3-base v2 (Apache-2.0, English, archived);
   Prompt Guard 2 is gated → adapter kept, not default.
6. **Fail closed:** if `CONTAINMENT_STAGE1=onnx[:name]` (or code asks for it) and the model,
   deps or hashes are missing/invalid, every scan returns `label="error"` → `high_risk` and
   privileged sinks fail closed. No silent fallback for an explicitly configured model.
7. **Optional LLM-judge screener** (`LLMJudgeDetector`, Stage 2): OpenAI-compatible endpoint,
   datamarked input, strict JSON verdict, timeout/parse error → `error`. Interface + offline
   tests with a local fake server; not part of measured numbers (no local LLM on the box).
8. **Chunk scanning:** `DetectorCascade.scan_chunks(chunks)` scans each chunk and each
   adjacent pair joined; aggregate = worst.
9. **Fusion:** Stage-1 `LayeredDetector` = rules + structural + ML; flag if
   `ml ≥ t_hi` or `structural ≥ s_hi` or (`ml ≥ t_lo` and `structural ≥ s_lo`).
   Thresholds tuned on the **train** split only (attack variants + benign train), recorded in
   DECISIONS with the sweep; held-out never used for tuning.

## Success criteria (falsifiable)
- Detector-only recall on held-out paraphrases substantially above the Step-2 baseline;
  exact before/after per category, both for the zero-dep default and with ML.
- Policy-on ASR stays 0.0000 on fixtures; eval card gate PASS.
- FP on the expanded benign set (≥ 200) reported before/after, train and held-out.
- Latency per KB reported (zero-dep and ML) on the box CPU.
- `scripts/release_gate.sh` exit 0; CI green; ruff clean; full pytest green.
- Version 1.8.0: pyproject, `__version__`, CHANGELOG, docs; THREAT_MODEL states plainly that
  no detector catches all injections and that policy/capability containment is the guarantee.

## Step 4 — Release
Version bump, DECISIONS entry (model choice + URLs + dates), docs, commit, push `main`, CI
green, `scripts/cut_release.sh 1.8.0` dry run then `--execute` (tag + attested GitHub
Release). Then update `/workspace/.venvs/containment` and the shared skill pins
(`/home/box/agent-data/workflows/containment-untrusted-content/SKILL.md`, minimal version
edits only) and run `containment doctor`.

## Out of scope
PyPI; policy changes; shipping model weights in the wheel; adaptive (optimization-based)
attacks against the classifier (documented as a remaining blind spot).
