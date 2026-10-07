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
| `detectors.rules` | Stage0 Unicode / invisible / base64 / size |
| `detectors.cascade` | Stage0→1→2 aggregation; never authorizes |
| `detectors.piguard` | optional HF PIGuard; Fake/RulesOnly for CI |
| `quarantine` | tool-less typed extract; closed schema |
| `datamark` | random marker wrap/unwrap |
| `ingest` | wires label → cascade → quarantine |
| `moltbook` | public posts client → ingest → `{title,topic,summary}` |
| `cli` / `eval_runner` | offline ASR/FPR/utility |
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
