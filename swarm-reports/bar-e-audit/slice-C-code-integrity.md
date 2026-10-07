# Slice C — eval_card + tests + CLI + packaging integrity

**Base:** `d025cf2` / **1.6.0**  
**Verdict:** ISSUES (1 MED)

## Surfaces scanned

- `src/containment/eval_card.py`
- `tests/test_eval_card.py` (11 tests green)
- `pyproject.toml` console script
- `scripts/release_gate.sh` (card intentionally absent)

## Placeholder / stub scan

No TODO / FIXME / NotImplemented / placeholder / empty `pass` ship stubs in Bar E surfaces.

## Metric reuse

`_slice_from_metrics` copies fields from `EvalMetrics`; `generate_card` does not recompute ASR/FPR/utility. PASS.

## Corpus mismatch

`build_card` raises `ValueError` when ON/OFF `n_attack`/`n_benign` differ — tested. PASS.

## JSON ↔ dict roundtrip

`write_json` → `card_from_dict` preserves fields. `card_from_dict` **trusts** `on_asr_ok`/`control_ok` from JSON (does not recompute). Docstring: roundtrip helper for tests. CLI path always uses `build_card`/`generate_card`. **Accept residual** (C-R1): not on ship CLI path.

## Packaging

- Entry point `containment-eval-card = containment.eval_card:main` — PASS
- `python -m containment.eval_card` works — PASS (`test_console_script_entrypoint`)
- No nested empty `evals/` package — PASS (laziness)

## ISSUE E1 (MED) — control_ok vs displayed ASR

**File:** `src/containment/eval_card.py` `control_is_ok` (~L108–110)

`on_asr_is_ok` rounds with `round_asr` (4 decimals). `control_is_ok` compares **raw** floats (`off_asr > on_asr`). Writers round ASR in Markdown and JSON.

**Repro:**

```python
# on=0.0, off=0.00004 → control_ok True, but both display as 0.0000
```

Measured on box: `build_card` → gate PASS while Markdown shows `| ASR | 0.0000 | 0.0000 |`.

**Why it matters:** Citeable card can claim control_ok while printed rates look equal. Docs/DECISIONS say OFF must be strictly greater; `on_asr_ok` already documents 4-decimal rounding. Coherence requires the same rounding for the control inequality.

**Fix direction:** `return round_asr(off_asr) > round_asr(on_asr)`; lock with a hermetic test; scrub docs/gate comment to say “after 4-decimal rounding”.

## Soft / residual

- **C-R1** — `card_from_dict` trusts flags (test helper).
- **C-R2** — Package root does not re-export `on_asr_is_ok` / `control_is_ok` (docs import from `containment.eval_card`). Fine.
- Threshold edge `on_asr_is_ok(0.00004)` True — intentional per docs.

## Edge cases checked

- CLI fail-closed monkeypatch — PASS
- Naive `generated_at` → treated as UTC — PASS
- `resolve_git_sha` failure → `unknown` — PASS (best-effort)
