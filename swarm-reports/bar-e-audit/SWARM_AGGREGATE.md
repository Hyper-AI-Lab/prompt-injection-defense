# Bar E audit swarm aggregate — 2026-10-08 JST

**Base:** `d025cf2` / containment **1.6.0**  
**N=4 local** (box executors; no Cloud Agents)

| Slice | Verdict |
| --- | --- |
| A EVAL_CARD_PLAN done-predicate | ISSUES (→ E1) |
| B vision / PROGRESS_LOG architecture | PASS (soft B-S1) |
| C code integrity | ISSUES (E1 MED) |
| D docs / claims | ISSUES (X1, X2 LOW) |

## ISSUES to clear (steps 4–6)

**E1 (MED)** = A→E1 / C-E1 — `control_is_ok` compares raw floats while Markdown/JSON round ASR to 4 decimals. Gate can PASS with displayed ON=OFF=`0.0000` (e.g. on=0.0, off=0.00004). Fix: compare `round_asr(off) > round_asr(on)`; hermetic test; docs + `release_gate` comment + DECISIONS wording align (“after 4-decimal rounding”).

**X1 (LOW)** = D-X1 — `docs/ARCHITECTURE.md` Modules table omits `eval_card`.

**X2 (LOW)** = D-X2 — README package layout bullet omits `eval_card` module name.

## Accept as residual (threat model / plan)

- **Card not inside release_gate** — intentional; documented in gate comments + EVAL_CARD.md + DECISIONS (plan predicate 5 optional-or-document).
- **Generated artifacts gitignored** — generate on demand.
- **C-R1** — `card_from_dict` trusts JSON flags (test roundtrip helper; CLI uses `build_card`).
- **C-R2** — `on_asr_is_ok` / `control_is_ok` imported from `containment.eval_card`, not package root.
- **B-S1** — `--suite` is a label only (fixtures corpus until more suites; out of audit non-goals to expand).
- Prior Bar C+D residuals unchanged.

## Bar E plan-match summary

Done-predicate 1–5 **PASS** pending E1 coherence harden. Vision match **PASS**. Functional GAP count for steps 4–5: **E1** (code) + **X1/X2** (docs).

## Post-harden (steps 4–6)

- **E1 CLEARED** — `control_is_ok` uses `round_asr`; tests lock display coherence.
- **X1 CLEARED** — ARCHITECTURE Modules includes `eval_card`.
- **X2 CLEARED** — README layout names `eval_card (Bar E)`.
- Residuals unchanged (card out of gate, gitignored artifacts, C-R1/C-R2, B-S1, prior C+D).
