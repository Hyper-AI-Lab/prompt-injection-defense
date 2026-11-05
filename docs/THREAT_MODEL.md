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
3. **Obfuscation** — invisible Unicode, bidi overrides, base64/hex/URL/Morse encoding, CSS-hidden HTML text, multilingual wrappers.
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
3. **Detector cascade** — Stage0 rules (zero-dependency: rules, multilingual structural
   intent, decode-and-rescan, computed CSS hiding, de-obfuscation views) → Stage1 (rules
   mirror, or the optional local ONNX classifier fused with structural cues) → optional
   Stage2 LLM judge; **never authorizes**.
4. **Policy engine** — YAML default-deny; taint predicates block untrusted → privileged egress.
5. **Tool broker** — unknown tools denied; schema check; capability mint one-use; audit append.
6. **Fail closed** — detector error, a configured-but-unusable model (`CONTAINMENT_STAGE1=onnx`)
   or an unreachable judge (`CONTAINMENT_STAGE2=llm`) yields `error` → high risk; privileged
   sinks deny.
7. **Datamarking** — optional spotlighting helpers for trusted instructions vs untrusted data.
8. **Signed intents (HMAC / optional Ed25519)** — enterprise: verify `IntentEnvelope`
   authenticity + expiry + `plan_hash` before capability mint
   (`require_signed_intent` / `enterprise_profile`).
9. **Capability consume store** — pluggable one-use consume (`MemoryConsumeStore`
   default; `SqliteConsumeStore`; optional `RedisConsumeStore` behind `[redis]`).
10. **url_guard + resolve-pin + egress proxy** — literal SSRF helpers; DNS
    resolve-pin helpers; in-repo `containment-egress-proxy` (resolve-pin-forward,
    not TLS MITM).
11. **HostGate** — `HostChecklist` (isolation declaration, `SecretProvider`,
    `EgressProvider`, `AuditShipper`); capability secret bind to minter;
    optional audit ship on each decision (fail-closed under HostGate). See
    `docs/HOST_HARDENING.md`.
12. **RateLimitGate** — optional token-bucket on privileged broker mint (LLM10).

## Detection is best effort; containment is the guarantee

**No detector catches every prompt injection, and this one does not either.** Natural
language has unbounded ways to phrase an instruction; attackers can adapt to any fixed
detector (rules, classifier or LLM judge). The detector cascade is built to be
wording-independent and to catch as much as it can — on the held-out paraphrase eval it
flags 90.2 % of variants with no dependencies and 97.9 % with the ONNX layer (see
`docs/EVAL_CARD.md`) — but the remaining misses are real, and so are false positives.

The guarantee comes from **policy and capability containment**: untrusted content is
labeled untrusted, the model only *proposes* actions, and the broker denies privileged
tools (email, HTTP, wallet, shell, ...) for tainted plans unless policy and, where required,
a human allow them. A missed injection can still influence text the model writes; it cannot
by itself authorize a privileged action.

## Non-goals / residual risk

- No claim of immunity to adaptive or novel attacks.
- Detectors can miss (false negatives) or over-flag (false positives); policy is the authority boundary.
- Known detector blind spots (1.8.0 held-out eval): multi-step "diagnostic" instructions where
  each step looks harmless (goal decomposition); MCP tool descriptions asking to log/forward
  data (zero-dep mode); terse policy-tampering paraphrases ("erase the default_deny policy")
  in zero-dep mode; injections quoted inside text that also discusses attacks (the quote
  dampener treats them as mentions); text beyond ~100 KB is scored by Stage 0 only (the ONNX
  layer reads the first 64 token windows); the LLM judge itself reads untrusted text and can
  be steered (it can only raise risk).
- Does not replace OS process isolation. In-package interfaces cover vault-shaped
  secrets (`SecretProvider`), audit export (`AuditShipper`), rate gates, and an
  optional resolve-pin forward proxy; residual remains if the host skips
  checklist / proxy / real isolation (see `docs/HOST_HARDENING.md`).
- Optional model weights (ONNX hl-small/hl-base; legacy PIGuard / Prompt Guard 2) may be
  unavailable; zero-dependency mode uses Stage 0 + fail-closed privileged path, and a model
  that was configured but cannot load fails closed.
- Live third-party APIs (Moltbook) remain untrusted even when “verified” by the host site.
- **Audit trail integrity residual (L3):** `AuditLog` is an append-only JSONL file with a
  best-effort per-event hash chain (`prev_hash` / `event_hash`). Anyone with filesystem
  write access can truncate, rewrite, or replace the file; truncation/rewrite is not
  cryptographically prevented. This is **not** WORM storage. Treat the chain as tamper-
  *evidence* against casual edits, not as integrity against a privileged filesystem adversary.
  `AuditShipper` exports JSONL for host SIEM/WORM; the package still does not
  provide WORM storage itself.
- **Signed intent residual:** binding authenticates envelopes only when the host
  configures `require_signed_intent` / enterprise profile and protects signer
  material via `SecretProvider` (HMAC) or Ed25519 keys (`containment[crypto]`).
  Unsigned paths remain for non-enterprise deployments. Compromised signer
  secrets forge intents; keep material in a vault, not source.
- **SSRF / URL residual:** `url_guard` blocks literal metadata/private IPs, userinfo,
  and bad schemes. Resolve-pin helpers and `containment-egress-proxy` close DNS
  check-then-connect gaps when used. Residual remains if the host bypasses both
  and reconnects after a separate check. Moltbook disables redirects and caps
  read size; third-party sites remain untrusted content sources.

- **Accepted HostGate residuals (Bar B audit):** `RateLimitGate` remains optional
  under `build_enterprise_host` (configure when spend caps are required).
  `isolation_declared` is an honor-system declaration. Opener DI and proxy-wins-
  over-pin stay intentional bypasses for hermetic tests / trusted host proxies.
- **Multi-process capability store residual:** `MemoryConsumeStore` does not synchronize
  across processes (double-consume possible under multi-worker hosts). Use
  `SqliteConsumeStore` or optional `RedisConsumeStore` (`containment[redis]`) when
  multiple broker processes share mint/verify. Store permissions and locking are
  host responsibilities; Redis is not a required dependency.
- **LLM08 / LLM09 / multimodal:** no in-package vector store (LLM08 N/A); misinformation
  (LLM09) out of authority-path scope; image-embedded injection out of the text fixture
  corpus — see `docs/OWASP_LLM_TOP10_MAP.md`.

## Evaluation

Offline fixture eval prints ASR / FPR / utility. A control run with policy disabled
must show **higher ASR** (worse security) than policy enabled. Measured numbers are
empirical on the committed corpus, not a certification.
