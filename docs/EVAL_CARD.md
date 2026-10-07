# Eval card

Citable offline scorecard for `containment`: Markdown + JSON produced from the
fixture corpus with policy **ON** and policy **OFF** (control).

## What it is

- Reproducible package metrics from `containment.eval_runner.run_eval`
- Records package version, git SHA, corpus counts, ASR / FPR / utility,
  `detector_block_rate`, `policy_block_rate`, UTC + JST timestamps
- Fail-closed CLI: exit non-zero unless `on_asr_ok` and `control_ok`

## What it is not

- Not AgentDojo, not hosted shields, not a public leaderboard
- Not a SOTA or certification claim
- Not part of `scripts/release_gate.sh` (gate keeps a single policy-ON eval so
  CI stays fast). Use the card CLI as the prove-it / citation smoke.

## Thresholds

| Flag | Rule |
| --- | --- |
| `on_asr_ok` | ON ASR equals **0.0000** after 4-decimal rounding (`ON_ASR_REQUIRED`) |
| `control_ok` | OFF ASR is **strictly greater** than ON ASR |

Constants live in `containment.eval_card` (`ON_ASR_REQUIRED`, `ASR_ROUND_DIGITS`).

## Generate

```bash
containment-eval-card --suite fixtures --out-dir artifacts/eval-card
# or:
python -m containment.eval_card --suite fixtures --out-dir artifacts/eval-card
```

Writes:

- `artifacts/eval-card/eval-card.json`
- `artifacts/eval-card/eval-card.md`

`artifacts/` is gitignored; generate on demand for reviews or releases.

## Library API

```python
from containment.eval_card import generate_card, write_card_artifacts

card = generate_card(suite="fixtures")
assert card.on_asr_ok and card.control_ok
write_card_artifacts(card, "artifacts/eval-card")
```

Metrics are never recomputed in the card module — ON/OFF slices come from
`EvalMetrics` produced by `run_eval`.

## Relationship to `containment eval`

| Command | Role |
| --- | --- |
| `containment eval` | Single-mode metrics (ON or `--no-policy`); used by release_gate |
| `containment-eval-card` | ON + OFF card artifact; prove-it / citation; fail-closed gates |
