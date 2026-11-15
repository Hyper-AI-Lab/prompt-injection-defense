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

### 1.9.0 — blind-spot tightening (held-out)

1.9.0 closes the six reported 1.8.0 gaps with structural rules (no retraining) and whole-
document ONNX scanning. A frozen held-out **gap suite** (`containment eval --suite gaps`,
`fixtures/gaps/gaps.yaml`) and a fresh benign batch were committed **before** any change.

| metric | 1.8.0 holdout | 1.9.0 holdout |
| --- | --- | --- |
| mutation recall, zero-dep | 90.2 % | **100 %** |
| mutation recall, ONNX hl-small | 97.9 % | **100 %** |
| benign flagged, zero-dep | 4 / 61 | **1 / 72** |
| benign flagged, ONNX | 5 / 61 | **3 / 72** |

Benign corpus grew to **263 files** (191 train / 72 holdout) with 41 security-adjacent near-
misses (IAM/firewall/policy docs, phishing-training, tool READMEs that log/mirror/forward/CC,
multi-step runbooks, multilingual). Gap suite: multistep, tool_meta, policy_tamper and quoted
are closed on holdout in both modes; long-document planted payloads are caught in ONNX mode
only (zero-dep Stage 0 does not classify neutral-looking prose). ASR policy-on: 0. Remaining
ONNX benign FPs are the classifier's own calls on hard near-misses.

Train recall of 100 % reflects tuning on train; read the holdout column. Latency (8 vCPU,
loaded box): zero-dep 11–23 ms/KB; ONNX hl-small ≈ 90 ms for 1 KB, ≈ 145–155 ms/KB above.
No detector catches every injection — see `docs/THREAT_MODEL.md`.

### 1.10.0 — fresh independent holdout

A new held-out set (`containment eval --suite fresh`, `evalsets/fresh/`, provenance and
licences in `SOURCES.md`) was built by a different generator from public benchmarks and
security prose, and frozen (`MANIFEST.sha256`) **before** any 1.10.0 detector change. All
tuning used the train pool, mostly out of fold. The ONNX model's training data doesn't include
any holdout attack source.

| attacks by source (recall) | zero-dep 1.9.0 | zero-dep 1.10.0 | ONNX 1.9.0 | ONNX 1.10.0 |
| --- | --- | --- | --- | --- |
| agentdojo | 137/455 | **295/455** | 406/455 | **422/455** |
| bipia | 45/415 | **262/415** | 217/415 | **302/415** |
| deepset | 18/193 | **114/193** | 102/193 | **147/193** |
| injecagent | 237/416 | **248/416** | 270/416 | **279/416** |
| **all attacks** | 437/1479 | **919/1479** | 995/1479 | **1150/1479** |

| benign by source (flagged) | zero-dep 1.9.0 | zero-dep 1.10.0 | ONNX 1.9.0 | ONNX 1.10.0 |
| --- | --- | --- | --- | --- |
| wikipedia | 47/207 | 10/207 | 47/207 | 10/207 |
| mitre_attack | 33/163 | 13/163 | 33/163 | 13/163 |
| nvd_cve | 22/139 | 8/139 | 25/139 | 11/139 |
| arxiv_abstract | 20/150 | 4/150 | 20/150 | 4/150 |
| owasp_cheatsheet | 17/70 | 14/70 | 17/70 | 14/70 |
| owasp_llm_top10 | 7/12 | 3/12 | 7/12 | 3/12 |
| gov_guidance | 0/4 | 1/4 | 0/4 | 1/4 |
| deepset | 0/56 | 0/56 | 0/56 | 0/56 |
| long_benign | 34/40 | 29/40 | 35/40 | 30/40 |
| carrier_benign | 0/160 | 8/160 | 5/160 | 13/160 |
| **all benign** | 180/1001 | **90/1001** | 189/1001 | **99/1001** |

| attacks by carrier | zero-dep 1.9.0 | zero-dep 1.10.0 | ONNX 1.9.0 | ONNX 1.10.0 |
| --- | --- | --- | --- | --- |
| bare | 99/444 | 227/444 | 234/444 | 286/444 |
| email | 49/227 | 166/227 | 162/227 | 197/227 |
| html | 41/210 | 116/210 | 155/210 | 175/210 |
| json_tool | 59/229 | 130/229 | 175/229 | 184/229 |
| chat | 54/222 | 151/222 | 127/222 | 169/222 |
| long | 135/147 | 129/147 | 142/147 | 139/147 |

**Long documents, honestly:** each long doc concatenates 8 security-prose chunks around a
planted payload. The raw `long` row mostly measures filler false positives. With the payload
removed, the filler alone is flagged in 134/147 docs (1.9.0) and 120/147 (1.10.0), zero-dep. So
zero-dep detections attributable to the payload went from **1** to **9** of 147. Among docs
with clean filler, 9/27 payloads are caught (1.9.0: 1/13). The gap suite's two long-doc
payloads are still missed in zero-dep mode and caught by ONNX.

Old suites: mutation recall is 100 % / 100 % (train/holdout) in both modes, as in 1.9.0.
Mutation-benign flags: zero-dep 3/263 (1.9.0: 2), ONNX 8/263 (1.9.0: 8). Fixture suite: ASR 0
with policy on, benign flagged 3/263 in both modes (1.9.0: 2 in both). The newly flagged item
everywhere is an IT password-reset email the learned scorer rates 0.87.

Latency (8 vCPU, loaded box): zero-dep 22 ms/KB on the fresh holdout (1.9.0: 21). The
learned scorer plus discourse adds ~1.25 ms/KB, 0.3 s for a 200 KB document. ONNX ≈ 111 ms/KB.

Regressions we accept: benign *carriers* (emails/chats with ordinary human-addressed
requests) went from 0 to 8/160 flagged zero-dep and from 5 to 13/160 with ONNX. The learned
scorer cannot always tell a human-addressed request from an agent-addressed one.
BIPIA-text and InjecAgent-base attacks look like ordinary requests that are injections only
because of where they sit, which caps recall on those sources.
No detector catches every injection — see `docs/THREAT_MODEL.md`.
