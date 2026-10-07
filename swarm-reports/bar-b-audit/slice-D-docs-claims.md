# Slice D — Docs / claims / exports / placeholders (analysis only)

**Tree:** `/workspace/prompt-injection-defense` @ containment **1.3.0**  
**Scope:** placeholders, claim drift, `__init__` exports, README/AGENT_INSTALL secrets, FedRAMP/zero-residual claims, `release_gate` rg coverage  
**Method:** `rg` on `src` `tests` `docs` `README.md` `SKILL.md`; AST compare of `containment/__init__.py` imports vs `__all__`; dry-run of `scripts/release_gate.sh` placeholder pattern  
**Date:** 2026-10-07 JST

## Verdict

**ISSUES**

Ship surfaces are largely honest (FedRAMP/zero-residual negated; plaintext HMAC examples scrubbed from README/AGENT_INSTALL). Several coherence gaps remain: one stale “later steps” docstring (scaffold residue), plan wording that names a non-existent `EgressProvider` type, plan “file/HMAC export helper” vs file-only `FileAuditShipper`, soft “production” marketing on README L3, and measurable `release_gate` placeholder-scan coverage holes.

---

## PASS (evidence)

### Placeholders / unfinished markers (ship surfaces)

Dry-run of release_gate pattern on ship paths:

```text
rg -n 'TODO|FIXME|NotImplemented|pass  #|placeholder|TBD' src tests docs README.md SKILL.md
→ exit 1 (no matches)
```

- No `TODO` / `FIXME` / `placeholder` / `TBD` / `pass  #` in `src` `tests` `docs` `README.md` `SKILL.md`.
- Protocol bodies use `...` (typing ellipsis) only — correct; not unfinished stubs.
- Case-insensitive hit only: `tests/test_piguard.py:75` `test_no_notimplemented_in_adapters` (test name; case-sensitive gate does not trip).

### Plaintext secrets in README / AGENT_INSTALL

- `rg 'secret\s*=\s*b["\x27]'` on `README.md` `docs/AGENT_INSTALL.md` `SKILL.md` → **clean**.
- README quickstart uses `FileSecretProvider` + `secrets.get_bytes("capability")` (L90–97).
- AGENT_INSTALL prefers `build_enterprise_host` / `FileSecretProvider`; documents file/env material, “Never commit HMAC/Ed25519 material.”
- `docs/HOST_HARDENING.md:42` contains the string `secret=b"..."` only as an explicit **negation** (“never inline …”). Acceptable instructional anti-pattern.
- Test fixtures use `secret=b"..."` under `tests/` — expected hermetic keys; not a docs claim issue.

### FedRAMP / zero-residual claims

Affirmative certification / zero-residual claims **absent**. Negations present:

| Surface | Evidence |
| --- | --- |
| README L29 | “This is not a FedRAMP claim and not an OS sandbox.” |
| HOST_HARDENING L18, L123 | not FedRAMP/SOC2; explicit residuals |
| SKILL L35, L78 | “Do not claim zero residual risk” / no certification |
| THREAT_MODEL / DECISIONS | residuals + Bar B non-goals list FedRAMP/zero-residual |

README threat table correctly lists “Adaptive attack immunity guarantees” as **out of scope**.

### `__init__` export internal consistency

- `__version__ = "1.3.0"` matches `pyproject.toml`.
- AST: `__all__` ↔ imported names — **no drift** (69 public names; empty symmetric difference).
- Bar B surface exported at top level: `build_enterprise_host`, `EnterpriseHost`, host types, egress resolve/proxy, Ed25519, Redis store, rate gate, `fetch_url`, etc.
- CLI entrypoints in `pyproject.toml`: `containment`, `containment-egress-proxy`.

### Detector / advanced API layering (accepted)

Many public symbols live under `containment.detectors` / submodule imports (`RiskSignal`, `RulesDetector`, `scan_stage0`, `ip_is_denied`, `pinned_socket_connect`, eval helpers, etc.) and are **not** re-exported from top-level `__init__`. Docs that need them either use `containment.detectors` or the symbols that *are* top-level (`make_stage1_cascade`, `resolve_and_pin`, `open_pinned_urllib`). **Not a bug** if treated as intentional layering — see INFO below.

---

## ISSUES

### D1 — Stale scaffold docstring on `HostChecklist` (HIGH for coherence)

**File:** `src/containment/host/checklist.py` L15–16

```text
``egress_configured`` is a bool in this step; later steps set it when an
egress provider or proxy URL is present.
```

Bar B steps that wire egress/`proxy_url`/`build_enterprise_host` already landed. This is leftover step-2 language (“this step / later steps”), not caught by `TODO|FIXME|placeholder`. Misleading for integrators reading the class docstring.

**Fix direction (for plan step 6):** rewrite to current semantics — bool flag set by host / `build_enterprise_host` when `egress_configured=True` and/or `proxy_url` is set; no future-step promise.

### D2 — Plan claim drift: `EgressProvider` type never shipped (MEDIUM)

**Plan:** `LEFTOVERS_HARDEN_PLAN.md` done-predicate §3 names `EgressProvider` or proxy URL.  
**Code/docs:** no `EgressProvider` type anywhere in `src`/`docs`/`README`/`SKILL`. Reality is `HostChecklist.egress_configured: bool` + optional `proxy_url` on enterprise/moltbook/fetch.

Functionally the gate exists; the **named type in the law** does not. Docs (HOST_HARDENING) already describe the bool. Audit matrix should mark plan item as **PASS-with-wording-GAP** (bool + proxy_url ≡ intent) or introduce a thin Protocol if the law is read literally.

### D3 — Plan claim drift: “file/HMAC export helper” vs file-only shipper (MEDIUM)

**Plan:** done-predicate §8 — “AuditShipper Protocol + file/HMAC export helper”.  
**Shipped:** `AuditShipper` + `FileAuditShipper` (append JSONL only). No HMAC-signing / chained re-hash on ship. Hash-chain tamper-evidence remains on `AuditLog` itself; HOST_HARDENING honestly says export is not WORM.

Either:
- accept as intentional (file ship + existing AuditLog HMAC/hash chain), and scrub plan/PROGRESS language; or
- treat as residual GAP if “HMAC export helper” meant a signed shipper backend.

Current docs do **not** overclaim HMAC-on-ship.

### D4 — Soft overclaim: README “production prompt-injection defense” (LOW)

**File:** `README.md` L3 — packages the kit as “production **prompt-injection defense**” before the honest-claim block (L6–9) and Bar B residual blurb (L22–29).

Not a FedRAMP/zero-residual lie, but tone drifts toward “finished product” vs SKILL/HOST_HARDENING residual discipline. Prefer “production-*oriented*” / “defense kit” aligned with L6–9.

### D5 — `release_gate` placeholder `rg` coverage gaps (MEDIUM)

**File:** `scripts/release_gate.sh` L24

```bash
rg -n 'TODO|FIXME|NotImplemented|pass  #|placeholder|TBD' src tests docs README.md SKILL.md
```

| Gap | Risk |
| --- | --- |
| Case-sensitive only | lowercase `todo:` / `fixme` slip |
| `pass  #` requires **two** spaces | `pass #` / bare `pass` stubs not flagged (many bare `pass` in `egress_proxy.py` are intentional `except:` cleanup — noisy if naïvely added) |
| No scan for scaffold phrases | D1 (“later steps”) would still green |
| No `secret\s*=\s*b["']` on README/docs/SKILL | Bar B done-predicate §4 regression not gated (currently clean by luck/review) |
| No FedRAMP *affirmative* claim scan | Relies on human review; negations exist today |
| `scripts/` excluded | Fine (gate self-mentions “placeholder”); also means script TODOs never fail the gate |
| Plans / PROGRESS / DECISIONS excluded | Intentional for ship surfaces |

**Current dry-run:** ship-surface pattern is **clean**. Gaps are **coverage**, not present failures.

### D6 — HOST_HARDENING instructional `secret=b"..."` (LOW / accept)

L42 anti-example can confuse automated “no plaintext secret” greps that include all of `docs/`. PROGRESS_LOG correctly scoped scrub to README/AGENT_INSTALL. Optional: rephrase to “never pass raw `bytes` literals into `CapabilityMinter`” without the exact `secret=b"` token if gate grows a secret scan.

---

## INFO (not ISSUES unless product wants flatter API)

1. **Top-level vs submodule:** `ToolSchemaError`, `registry_schema_validator`, `ip_is_denied`, `pinned_socket_connect`, `pinned_http_url`, detector Stage-0/1 types, eval_runner types — public but submodule-only. README still imports several symbols from submodules even when re-exported (`ToolBroker`, `PolicyEngine`) — style inconsistency, not breakage.
2. **SKILL.md L44** uses `...` in a comment block for error handling — prose ellipsis, fine; not a code placeholder.
3. **Rate/spend:** broker + `TokenBucketRateLimit` present; HOST_HARDENING correctly leaves model/API quotas as host residual (LLM10). No claim drift.
4. **Non-goals honored in docs:** no Kata/gVisor ship claim; proxy described as resolve-pin-forward not iron-proxy MITM; no Claude Code auto-wire claim.

---

## rg summary (commands run)

```bash
rg -n -i 'TODO|FIXME|NotImplemented|placeholder|...' src tests docs README.md SKILL.md
rg -n 'secret\s*=\s*b["\x27]' README.md docs SKILL.md
rg -n -i 'fedramp|zero.?residual|...' docs README.md SKILL.md src
rg -n 'EgressProvider' src docs README.md SKILL.md   # → none
rg -n -i 'later step|scaffold|...' src tests docs README.md SKILL.md
# AST __all__ ↔ imports → empty diff
```

---

## Recommended handoff to audit law

For `BAR_B_AUDIT_HARDEN_PLAN.md` step 6 (cluster D), clear at least:

1. **D1** — rewrite `HostChecklist` docstring (code/docs coherence).
2. **D2/D3** — record in `AUDIT_PLAN_VS_BAR_B.md` as wording PASS/GAP; no new type required unless aggregate demands literal `EgressProvider`.
3. **D5** — optionally tighten `release_gate` (case-insensitive markers; `secret=b"` ban on README/AGENT_INSTALL/SKILL; optional `later steps` / `NotImplementedError` already covered via substring).
4. **D4** — one-line README tone scrub if touching docs anyway.

No functional Bar B capability absence found in this slice beyond plan-wording vs bool/`FileAuditShipper` semantics above.
