# Threat model

## Goal

Reduce the chance that **untrusted content** causes an agent to perform
**privileged actions** the user did not authorize — even when a language model
is influenced by injected instructions.

## Assets

- Privileged tools: `email.send`, `http.post`, `wallet.transfer`, `shell.exec`, `file.write`, and any tool registered with the broker
- Secrets and private data labeled `confidentiality=private|identity`
- Audit trail integrity (append-only JSONL)
- One-use capability tokens

## Adversaries

1. **Direct prompt injection** — user- or attacker-controlled chat text.
2. **Indirect injection** — malicious content in fetched pages, email, tickets, Moltbook posts, CSV/JSON fields, HTML comments.
3. **Obfuscation** — invisible Unicode, bidi overrides, base64/hex/URL encoding, multilingual wrappers.
4. **Confused deputy** — model proposes a tool call that launders untrusted bytes into a privileged sink.

## Trust boundaries

| Zone | Integrity default | Notes |
| --- | --- | --- |
| Operator / signed task intent | trusted | Established before reading untrusted content |
| Model proposals | untrusted until policy allows | Never self-authorizing |
| External feeds (web, Moltbook, email bodies) | untrusted | Always run through ingest |
| Quarantined typed extract | untrusted data, schema-limited shape | No tools inside quarantine |

## Controls (mapped)

1. **Labels** — every value carries integrity/confidentiality/provenance.
2. **Ingest pipeline** — label → normalize → detector cascade → quarantine typed extract.
3. **Detector cascade** — Stage0 rules → Stage1 adapter → optional Stage2; **never authorizes**.
4. **Policy engine** — YAML default-deny; taint predicates block untrusted → privileged egress.
5. **Tool broker** — unknown tools denied; schema check; capability mint one-use; audit append.
6. **Fail closed** — detector error / missing Stage-1 weights advise deny for privileged sinks.
7. **Datamarking** — optional spotlighting helpers for trusted instructions vs untrusted data.
8. **Signed intents (HMAC)** — optional/enterprise: verify `IntentEnvelope` MAC + expiry + `plan_hash` before capability mint (`require_signed_intent` / `enterprise_profile`).
9. **Capability consume store** — pluggable one-use consume (`MemoryConsumeStore` default; `SqliteConsumeStore` for multi-process).
10. **url_guard** — shared egress URL parsing: scheme allowlist, userinfo reject, literal metadata/private IP deny; wired into policy/broker/moltbook.

## Non-goals / residual risk

- No claim of immunity to adaptive or novel attacks.
- Detectors can miss (false negatives) or over-flag (false positives); policy is the authority boundary.
- Does not replace OS process isolation, network egress proxies, or secret vaults.
- Optional HF weights (PIGuard / Prompt Guard 2) may be unavailable; offline mode uses rules + fail-closed privileged path.
- Live third-party APIs (Moltbook) remain untrusted even when “verified” by the host site.
- **Audit trail integrity residual (L3):** `AuditLog` is an append-only JSONL file with a
  best-effort per-event hash chain (`prev_hash` / `event_hash`). Anyone with filesystem
  write access can truncate, rewrite, or replace the file; truncation/rewrite is not
  cryptographically prevented. This is **not** WORM storage. Treat the chain as tamper-
  *evidence* against casual edits, not as integrity against a privileged filesystem adversary.
  External WORM / signed log shipping remains out of scope for this package.
- **Signed intent residual:** HMAC binding authenticates envelopes only when the host
  configures `require_signed_intent` / enterprise profile and protects the signer secret.
  Unsigned paths remain available for non-enterprise deployments; Ed25519 is not required
  in 1.2. Compromised signer secrets forge intents — keep secrets in a vault.
- **SSRF / URL residual:** `url_guard` blocks literal metadata/private IPs, userinfo, and
  bad schemes; it does **not** perform DNS resolution or defeat DNS rebinding. Hosts must
  still run an egress proxy / allowlist beyond these helpers. Moltbook disables redirects
  and caps read size, but third-party sites remain untrusted content sources.
- **Multi-process capability store residual:** `MemoryConsumeStore` does not synchronize
  across processes (double-consume possible under multi-worker hosts). Use
  `SqliteConsumeStore` (or a future external store) when multiple broker processes share
  mint/verify. SQLite file permissions and locking are host responsibilities; Redis is
  not a required dependency.
- **LLM08 / LLM09 / multimodal:** no in-package vector store (LLM08 N/A); misinformation
  (LLM09) out of authority-path scope; image-embedded injection out of the text fixture
  corpus — see `docs/OWASP_LLM_TOP10_MAP.md`.

## Evaluation

Offline fixture eval prints ASR / FPR / utility. A control run with policy disabled
must show **higher ASR** (worse security) than policy enabled. Measured numbers are
empirical on the committed corpus, not a certification.
