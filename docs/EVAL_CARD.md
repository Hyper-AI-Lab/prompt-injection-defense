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
| `control_ok` | OFF ASR is **strictly greater** than ON ASR after 4-decimal rounding |

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

## Detector-only paraphrase / mutation eval (1.8.0)

`containment eval --suite mutations [--json]` measures the **detector alone** (policy not
used) on 64 attacks × 14 families: the original, hand-written `reword`, `indirect`, `ru`,
`ja` paraphrases (`fixtures/mutations/paraphrases.yaml`), and generated `synonym`, `split`
(multi-chunk), `b64`, `hex`, `url_escape`, `rot13`, `md_wrapper`, `html_comment`,
`css_class` (hidden via a `<style>` class). Benign: 222 files in `fixtures/benign/`.

Cases are split by `sha256(case_id) % 3 == 0` → holdout (18 cases, listed in
`fixtures/mutations/SPLIT.md`); the same rule splits benign files. All rule and threshold
tuning used the **train** split only; holdout numbers are the honest estimate.

Recall, train / holdout (variants of the same attack case are never split):

| family | 1.7.2 | 1.8.0 zero-dep | 1.8.0 + ONNX hl-small |
| --- | --- | --- | --- |
| original | 43.5 % / 38.9 % | 100 % / 100 % | 100 % / 100 % |
| reword | 26.1 / 22.2 | 100 / 88.9 | 100 / 94.4 |
| indirect | 30.4 / 27.8 | 100 / 94.4 | 100 / 100 |
| ru | 28.3 / 22.2 | 100 / 88.9 | 100 / 94.4 |
| ja | 23.9 / 16.7 | 100 / 83.3 | 100 / 94.4 |
| synonym | 43.5 / 38.9 | 100 / 94.4 | 100 / 100 |
| split | 21.7 / 22.2 | 100 / 88.9 | 100 / 100 |
| b64 / hex | 100 / 100 ¹ | 100 / 88.9 | 100 / 100 |
| url_escape | 8.7 / 5.6 | 100 / 94.4 | 100 / 100 |
| rot13 | 21.7 / 22.2 | 100 / 88.9 | 100 / 100 |
| md_wrapper | 26.1 / 22.2 | 100 / 88.9 | 100 / 94.4 |
| html_comment | 26.1 / 22.2 | 100 / 88.9 | 100 / 94.4 |
| css_class | 26.1 / 22.2 | 100 / 94.4 | 100 / 100 |
| **all variants** | **37.1 / 34.2** | **100 / 90.2** | **100 / 97.9** |
| benign flagged (of 161 / 61) | 5 / 3 | 2 / 4 | 3 / 5 |

¹ 1.7.2 flagged any base64/hex presence (also hashes, JWTs, images); 1.8.0 flags decoded
instructions and caps presence-only findings below the threshold.

Train recall of 100 % reflects tuning on train; read the holdout column. Latency (8 vCPU,
loaded box): zero-dep 11–23 ms/KB; ONNX hl-small ≈ 90 ms for 1 KB, ≈ 145–155 ms/KB above.
No detector catches every injection — see `docs/THREAT_MODEL.md`.
