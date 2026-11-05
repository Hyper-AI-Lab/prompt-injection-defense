# Architecture

## Pipeline overview

```
untrusted bytes
    │
    ▼
 ingest (label + normalize + cascade + quarantine extract)
    │
    ├── SecurityLabel (usually integrity=untrusted)
    ├── CascadeResult (risk signals only)
    └── ExtractResult | extract_error (closed JSON Schema)
    │
    ▼
 model may propose ProposedAction
    │
    ▼
 ToolBroker.secure_execute
    ├── known tool?
    ├── schema validate
    ├── PolicyEngine.evaluate (default deny)
    ├── require_human → approval hook
    ├── CapabilityMinter (one-use)
    └── AuditLog append
```

## Modules

| Module | Role |
| --- | --- |
| `labels` | `SecurityLabel` integrity/confidentiality/provenance |
| `plan` / `actions` | `IntentEnvelope`, `Plan`, `ProposedAction`, `PolicyDecision` |
| `policy` | YAML load; allow / deny / require_human; taint predicates |
| `capability` | one-use HMAC capability tokens |
| `audit` | append-only JSONL |
| `broker` | reference monitor `secure_execute` |
| `detectors.rules` | Stage0 Unicode / invisible / encodings / Morse / size; steering directives (tool-call, secret exfil, package swap, role tags, approval claims, error fallbacks, refusal bans, override phrases); structural intent; rescans decoded / de-obfuscated / CSS-hidden *views* (`encoded_instruction`, `obfuscated_instruction`, `hidden_instruction`) |
| `detectors.structural` | multilingual (EN/RU/JA + common EU) intent categories and combinations, negation- and discussion-aware |
| `detectors.decode` | discovery-only decoding (base64, hex, percent, ROT13, Morse, nested) + confusable folding |
| `detectors.html_hidden` | computed CSS hiding: `<style>` rules (tag/.class/#id), inline style, `hidden`, inheritance |
| `detectors.onnx_classifier` | optional pinned + SHA-256-verified ONNX classifier (`[ml]`), windowed; `UnavailableStage1` fails closed |
| `detectors.layered` | Stage-1 fusion of classifier probability with structural cues (thresholds tuned on train split) |
| `detectors.llm_judge` | optional Stage-2 OpenAI-compatible judge; raises risk only; fails closed |
| `detectors.cascade` | Stage0→1→2 aggregation, `scan_chunks` (chunks + adjacent joins); never authorizes |
| `detectors.piguard` | Stage-1 selection (`rules_only`, `onnx[:model]`, legacy PIGuard, fake for CI) |
| `mutation_eval` | detector-only paraphrase/mutation eval with a frozen train/holdout split |
| `quarantine` | tool-less typed extract; closed schema |
| `datamark` | random marker wrap/unwrap |
| `ingest` | wires label → cascade → quarantine |
| `moltbook` | public posts client → ingest → `{title,topic,summary}` |
| `cli` / `eval_runner` | `containment eval` (offline ASR/FPR/utility) and `containment doctor` |
| `doctor` | Bar G: offline install + host wiring report from `HostChecklist` + `build_enterprise_host`; JSON/human; exit 0/1/2 |
| `resources` | locate shipped `policies/` + `fixtures/` (wheel `containment/_data/` or checkout) |
| `eval_card` | Bar E: citable ON+OFF Markdown/JSON scorecard; fail-closed CLI; reuses `run_eval` |
| `adapters` | Bar C: `BrokeredRegistry`, `brokered_tool`, Claude PreToolUse hook CLI |
| `reference_host` | Bar D: enterprise compose demo; hermetic attack/benign/human scenarios |
| `enterprise` / `host` | HostGate checklist, SecretProvider, AuditShipper, rate limit, egress hints |

## Authorization rule

**Detectors advise. Policy decides. Broker enforces.**

`DetectorCascade` must not import or call `PolicyEngine` / `ToolBroker`.

## Moltbook path

`fetch_posts` (stdlib urllib, no auth) → per-post `ingest` with
`MOLTBOOK_SUMMARY_SCHEMA` → only `title`, `topic`, `summary` may survive.
All posts labeled untrusted. No tools are exposed inside the reader.

## Release path

`scripts/cut_release.sh` (fail-closed preflight + tag) → `.github/workflows/publish.yml`
(build once, `actions/attest` provenance; PyPI job opt-in) → GitHub Release with CHANGELOG
notes, attested wheel + sdist and the eval card. Runbook: [RELEASE.md](RELEASE.md).
