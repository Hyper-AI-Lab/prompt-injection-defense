# Slice 6 — Optional PIGuard-on path + host residual-risk docs

**SHA:** `765a618ef258130d9523a50fc39e151bc74009e7`  
**Bar A item:** optional PIGuard-on path, docs for host residual risks  
**Scope:** Read-only audit of `select_stage1` / `piguard.py`, ingest defaults, README / `THREAT_MODEL` / `AGENT_INSTALL` (plus ARCHITECTURE / SKILL for enable + host obligations).  
**Date:** 2026-10-07 JST

---

## VERDICT: ISSUES

Code supports an optional PIGuard Stage-1 path (`select_stage1` + `[ml]` + `PIGuardDetector.try_load`), and `THREAT_MODEL.md` states high-level residual risks (sandbox / egress / vaults). **Bar A is not met as an operator story:** there is no documented enable recipe that wires PIGuard into `ingest` + broker fail-closed, no env/config API (`CONTAINMENT_STAGE1` absent), and host residual obligations are not a checklist in `AGENT_INSTALL` / README / SKILL. Not BLOCKED: adapter + selection + broker hooks exist; gaps are doc + thin config surface.

---

## Evidence (what exists today)

### 1. `select_stage1` / `PIGuardDetector` — `src/containment/detectors/piguard.py`

| Piece | Behavior |
| --- | --- |
| Model | `PIGUARD_MODEL_ID = "leolee99/PIGuard"` |
| `PIGuardDetector.try_load` | Import `transformers` → `AutoTokenizer` / `AutoModelForSequenceClassification` with **`trust_remote_code=True`** → text-classification pipeline; returns `None` on ImportError or any load failure (no raise). |
| `select_stage1(prefer="piguard", allow_download=False)` | **Does not call `try_load`.** Immediate RulesOnly + `fail_closed_privileged=True` (reason cites `allow_download=False`). |
| `select_stage1(prefer="piguard", allow_download=True)` | `try_load()`; on success backend=`piguard`, `fail_closed_privileged=False`; on failure RulesOnly + fail-closed. |
| `prefer="rules_only"` | Explicit RulesOnly + fail-closed. |
| `prefer="fake"` | CI double; `fail_closed_privileged=False`. |
| Default kwargs | `prefer="piguard"`, `allow_download=False` → **effective default is RulesOnly fail-closed** when callers omit args. |

**Docstring vs code:** docstring says prefer piguard “attempts load only when `allow_download` is True **or the model is already cached**.” Implementation never probes cache when `allow_download=False`; local HF cache alone cannot enable PIGuard.

Scan failure path: classifier exception → `RiskSignal(label="error", score=1.0)` (feeds cascade fail-closed helper when wired).

Exports: `select_stage1` (and detectors package) re-exported from `containment` / `containment.detectors` (`__init__.py`).

Tests: `tests/test_piguard.py` — rules_only / fake / no-download fallback / try_load offline / cascade+fake / no NotImplemented stubs. **No live `allow_download=True` load test** (by design for offline CI).

### 2. Ingest defaults — `src/containment/ingest.py`

```python
def default_ingest_cascade() -> DetectorCascade:
    selection = select_stage1(prefer="rules_only")
    return DetectorCascade(stage1=selection.detector)
```

- Production default = **RulesOnly**, not Fake (H3 fixed; asserted by `test_default_ingest_cascade_is_rules_only_not_fake`).
- Docstring points hosts at `select_stage1(prefer="piguard", allow_download=...)` for real ML — **no helper** builds that cascade; callers must construct `DetectorCascade(stage1=selection.detector)` and pass `cascade=` into `ingest`.
- `IngestResult` returns `cascade: CascadeResult` but **does not surface** `Stage1Selection.fail_closed_privileged` / backend name for broker handoff.
- Moltbook (`moltbook.ingest_post`) uses `cascade or default_ingest_cascade()` → same RulesOnly default.

### 3. Broker integration (related, not enable docs)

`ToolBroker.secure_execute(..., cascade=None, fail_closed_privileged=False)` (H2 wired):

- Denies privileged sinks when `privileged_sink_fail_closed(tool, cascade)` **or** `fail_closed_privileged and tool in PRIVILEGED_SINKS`.
- Hosts must **explicitly** pass `cascade=result.cascade` and/or `fail_closed_privileged=selection.fail_closed_privileged`. Defaults leave the gate off.
- Tests: `tests/test_broker.py` (`test_fail_closed_privileged_flag_blocks_email`, cascade deny path).

When PIGuard loads successfully, `fail_closed_privileged=False` — fail-closed then depends on **cascade risk/error signals**, not the selection flag.

### 4. Packaging — `pyproject.toml`

```toml
[project.optional-dependencies]
ml = ["transformers>=4.40", "torch>=2.0"]
```

README install mentions `pip install -e ".[dev,ml]"` under “Optional ML Stage-1 weights” — install only, no wiring snippet.

### 5. Docs — enable path & host residuals

| Doc | PIGuard enable? | Host residual (sandbox / egress / secrets)? |
| --- | --- | --- |
| `README.md` | `[ml]` pip one-liner; threat table says library does **not** replace OS sandbox / egress; “missing weights failing closed” | Brief out-of-scope table only |
| `docs/THREAT_MODEL.md` | Notes optional HF weights may be unavailable; offline = rules + fail-closed | **Best residual section:** “Does not replace OS process isolation, network egress proxies, or secret vaults”; audit JSONL not WORM; detectors can FN/FP |
| `docs/AGENT_INSTALL.md` | **No PIGuard / `select_stage1` / `[ml]` section** | Placeholder `CapabilityMinter(secret=...)`; no sandbox/egress/vault checklist; `CONTAINMENT_LIVE_MOLTBOOK` only |
| `docs/ARCHITECTURE.md` | Module row: “optional HF PIGuard; Fake/RulesOnly for CI” | No host obligations section |
| `SKILL.md` | Install `.[dev]` only (no `[ml]`) | “do not claim … zero residual risk”; no host controls list |
| `DECISIONS.md` | Full adopt rationale + `[ml]` + `allow_download=True` | Developer-facing; not agent install |

**Env / config API:** only `CONTAINMENT_LIVE_MOLTBOOK` exists under `src/containment`. **No `CONTAINMENT_STAGE1`**, no YAML/config object for Stage-1 backend. `prompt_guard2.py` docstring mentions “select_stage1 / config” but no config module exists for Stage-1.

---

## Gaps vs Bar A

| Gap | Severity | Detail |
| --- | --- | --- |
| **No operator enable recipe** | High (Bar A docs) | README/`AGENT_INSTALL`/SKILL never show: install `[ml]` → `select_stage1(prefer="piguard", allow_download=True)` → `DetectorCascade` → `ingest(..., cascade=...)` → `secure_execute(..., cascade=..., fail_closed_privileged=...)`. DECISIONS + ingest docstring are insufficient for Bar A “docs”. |
| **No Stage-1 config / env API** | Medium | No `CONTAINMENT_STAGE1=piguard\|rules_only\|fake`, no `CONTAINMENT_PIGUARD_ALLOW_DOWNLOAD`, no shared config dataclass. Only kwargs. Agents cannot flip Stage-1 without code edits. |
| **Docstring lies about HF cache** | Low–Med | Claims load when “already cached”; code requires `allow_download=True` even for cached weights. |
| **Host residual checklist missing from install path** | High (Bar A docs) | THREAT_MODEL has bullets; `AGENT_INSTALL` does not tell hosts they **must still** provide: OS/process sandbox, network egress allowlist/proxy, secret vault (not plaintext minter secret in source), WORM/signed audit shipping, independently of PIGuard-on. |
| **Selection metadata not returned from ingest** | Medium | Enabling PIGuard without threading `fail_closed_privileged` / cascade into broker leaves H2 off by default — easy misconfig; undocumented. |
| **`trust_remote_code=True`** | Low (residual) | Host supply-chain residual when turning PIGuard on; not called out in install docs. |
| **No offline “cached weights, no download” knob** | Low | Cannot set `allow_download=False` but still load from local cache (docstring implies this). |

What already satisfies parts of Bar A:

- Optional adapter + fail-closed RulesOnly fallback.
- Default ingest is production RulesOnly (not Fake).
- Broker can enforce detector fail-closed when host passes args.
- THREAT_MODEL residual paragraph covers sandbox / egress / vaults at a high level.

---

## Surgical harden proposals (doc + thin config; no gold-plate)

1. **`docs/AGENT_INSTALL.md` § “Optional PIGuard Stage-1”** — copy-paste recipe:
   - `pip install 'containment[ml]'` (or `.[dev,ml]`).
   - Prefetch/cache note: first enable needs network **or** pre-seeded HF cache; set `allow_download=True` only when intentional.
   - Snippet: `sel = select_stage1(prefer="piguard", allow_download=True)` → `casc = DetectorCascade(stage1=sel.detector)` → `ingest(..., cascade=casc)` → `broker.secure_execute(..., cascade=result.cascade, fail_closed_privileged=sel.fail_closed_privileged)`.
   - Explicit: PIGuard-on does **not** replace policy/broker; detectors advise only.

2. **`docs/AGENT_INSTALL.md` § “Host must still provide”** (mirror THREAT_MODEL, actionable):
   - OS / container process isolation (this package is not a sandbox).
   - Network egress proxy / DNS-aware SSRF controls beyond library helpers.
   - Secret vault for `CapabilityMinter` HMAC secret (rotate; never commit).
   - External WORM / signed log shipping for audit JSONL.
   - Supply-chain: review HF `trust_remote_code` before PIGuard-on.

3. **README** — short “Enable PIGuard” subsection linking AGENT_INSTALL; keep `[ml]` line; one sentence that default `ingest()` stays RulesOnly fail-closed metadata until host wires PIGuard + broker args.

4. **Config API (minimal)** — prefer one of:
   - **(A)** Env: `CONTAINMENT_STAGE1=rules_only|piguard|fake` + `CONTAINMENT_PIGUARD_ALLOW_DOWNLOAD=0|1` read inside a tiny `stage1_from_env()` used by `default_ingest_cascade` **only if** env set (else keep today’s rules_only). Document in AGENT_INSTALL next to `CONTAINMENT_LIVE_MOLTBOOK`.
   - **(B)** No env: add `make_stage1_cascade(prefer=..., allow_download=...) -> tuple[DetectorCascade, Stage1Selection]` helper so hosts get both detector and fail-closed flag without inventing glue. Still document in AGENT_INSTALL.

   Avoid a full YAML config system for 1.x.

5. **Fix `select_stage1` docstring** — remove “or already cached”; state clearly that `allow_download=True` is required to call `try_load` (HF may then use cache without re-download). Optional follow-up: `allow_download=False` + `local_files_only=True` try_load path if product wants cache-without-network.

6. **SKILL.md** — one bullet: default RulesOnly; optional PIGuard via AGENT_INSTALL; host sandbox/egress/secrets still required.

Out of scope for this slice’s surgical bar: ONNX/Rust PIGuard backends, auto-download in default CI, shipping weights in the package, replacing OS egress.

---

## Ranked backlog (feeds ENTERPRISE_HARDEN_PLAN)

1. AGENT_INSTALL PIGuard enable recipe + host residual checklist (doc-only).
2. README + SKILL cross-links / one-liners.
3. `make_stage1_cascade` helper **or** `CONTAINMENT_STAGE1` + allow-download env (pick one; prefer helper if env sprawl is unwanted).
4. Align `select_stage1` docstring with `allow_download` gate; optional `local_files_only` later.
5. Note `trust_remote_code=True` under host supply-chain residual.

---

## Summary

| Bar A claim | Status at `765a618` |
| --- | --- |
| Optional PIGuard-on **code** path | **Present** (`piguard.py`, `[ml]`, exports, tests offline) |
| Default safe offline path | **Present** (RulesOnly ingest default) |
| Operator enable + broker wiring **docs** | **Missing / incomplete** |
| Host residual-risk **docs** (sandbox, egress, secrets) | **Partial** (THREAT_MODEL only; not install checklist) |
| Config / env for Stage-1 | **Absent** (`CONTAINMENT_STAGE1` does not exist) |

**VERDICT: ISSUES**
