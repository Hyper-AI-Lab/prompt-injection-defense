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

## Non-goals / residual risk

- No claim of immunity to adaptive or novel attacks.
- Detectors can miss (false negatives) or over-flag (false positives); policy is the authority boundary.
- Does not replace OS process isolation, network egress proxies, or secret vaults.
- Optional HF weights (PIGuard / Prompt Guard 2) may be unavailable; offline mode uses rules + fail-closed privileged path.
- Live third-party APIs (Moltbook) remain untrusted even when “verified” by the host site.

## Evaluation

Offline fixture eval prints ASR / FPR / utility. A control run with policy disabled
must show **higher ASR** (worse security) than policy enabled. Measured numbers are
empirical on the committed corpus, not a certification.
