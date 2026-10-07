# Bar C+D audit swarm aggregate — 2026-10-08 JST

**Base:** `933ead2` / containment **1.5.0**  
**N=4 local** (box executors; no Cloud Agents)

| Slice | Verdict |
| --- | --- |
| A Bar C done-predicate | ISSUES (predicate 1–6 PASS; C-A1 race) |
| B Bar D done-predicate | PASS (soft D-B-S1/S2 only) |
| C adapters integrity | ISSUES (3 HIGH) |
| D docs/claims | ISSUES (docs/packaging) |

## ISSUES to clear (steps 4–7)

**C1 (HIGH)** = C-C1 / C-A2 / X-D3 / C-C8 — Claude `fs.write`/`fs.read` not in `PRIVILEGED_SINKS` (`file.write` only). Empty labels + allow policy execute; `fail_closed_privileged` skips. Align by adding `fs.write`/`fs.read` to `PRIVILEGED_SINKS` (+ schemas) and scrub docs drift.

**C2 (HIGH)** = C-C2 / C-A1 — `BrokeredRegistry.call` swaps shared `broker.executor`; concurrent calls cross-wire. Fix: per-call `executor=` on `secure_execute` (no shared mutable swap).

**C3 (HIGH)** = C-C3 / C-A4 — `handle_pretool_use` uses full `secure_execute` (mint/execute). With approving hook + executor, tool can run then hook returns `ask`. Fix: `dry_run=True` evaluate path (policy+gates, no approval/mint/execute); hook always dry-run.

**C4 (MED)** = C-C4 — Add JSON schemas for `shell.exec` / `file.write` / `fs.write` / `fs.read` (`additionalProperties: false`).

**C5 (LOW)** = C-C5 — Registry early label gate should use same set as broker `_LABEL_REQUIRED_SINKS`.

**X1** = X-D1 — `ARCHITECTURE.md` modules omit `adapters` + `reference_host`.

**X2** = X-D2 — README package layout omits same.

**X3** = X-D4 — Document reference-host policy packaging / no `--policy` vs Claude hook (residual or small CLI note).

## Accept as residual (threat model)

- **C-C6 / C-A5** — private `_entries[].fn` / Python encapsulation (public API sealed)
- **C-C7** — unmapped Claude tools deny by design
- **C-A3** — Edit/Read map covered; optional extra fixtures (coverage soft; add if cheap in step 7)
- **isolation_declared** honor-system; live Moltbook opt-in; Claude install≠wired (prior Bars)
- Bar D soft D-B-S1/S2 (doc ingest wording; human deny alternate) — fold into X cluster if wording fix is trivial

## Bar D

Done-predicate 1–5 **PASS**. No functional D-cluster GAPs evidenced. Step 5 may be VERIFIED with no code if only soft notes remain after X fixes.
