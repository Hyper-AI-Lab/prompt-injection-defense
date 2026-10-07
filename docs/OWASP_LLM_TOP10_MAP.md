# OWASP LLM Top 10 (2025) ↔ containment controls

**Date:** 2026-10-07 JST  
**Sources:** [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/), [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/risk/llm01-prompt-injection/)  
**Corpus / gap analysis:** `swarm-reports/slice-5-owasp-redteam.md`

This map links package controls to OWASP LLM01–LLM10. Detectors are **advisory**;
policy + broker remain the authority boundary. Measured offline ASR/FPR is empirical
on the committed fixture corpus, not a certification.

## Controls summary ↔ LLM Top 10

| OWASP 2025 | Risk (one-line) | Repo controls | Fixture coverage | Gap / residual |
| --- | --- | --- | --- | --- |
| **LLM01** Prompt Injection | Direct/indirect instruction overwrite | Labels + ingest; Stage0/1 cascade; quarantine instruction reject; datamark; offline eval | Classic direct/indirect/encoded/invisible + expanded split/suffix/nested/homoglyph/tool-result/RAG/delimiter/composition | Multimodal image-embedded instructions out of text corpus scope |
| **LLM02** Sensitive Information Disclosure | Leak secrets / PII via model or tools | `confidentiality` on `SecurityLabel`; `no-tainted-egress` + `input.max_confidentiality_lte` in default-deny policy; exfil-oriented fixtures | Partial (tool-exfil, disregard) | Host must not echo `identity` labels into logs/prompts |
| **LLM03** Supply Chain | Compromised models/deps/plugins | Optional Stage-1 extras (`[ml]`, `[stackone]`); CI/`pip-audit`/Dependabot/SBOM (Bar A); DECISIONS adopt-skip notes | N/A for prompt fixtures | Host reviews HF `trust_remote_code` before PIGuard-on |
| **LLM04** Data and Model Poisoning | Poison train/RAG/embed corpora | Threat model + RAG/retrieved-chunk fixtures; quarantine typed extract | Partial (summary poison, RAG chunk) | No in-package vector store; host owns corpus hygiene |
| **LLM05** Improper Output Handling | Unsafe use of model output (XSS, cmd, SQL, SSRF) | Quarantine closed schema; broker JSON Schema args; `url_guard` + policy host allowlist / public_only | Partial (SSRF URL attempt, HTML/script emit) | Host must not execute model output as code/HTML without sanitization |
| **LLM06** Excessive Agency | Too many tools / autonomous high-risk acts | Default-deny; one-use capabilities; HITL / MFA gates; unknown-tool deny; privileged fail-closed | Good (shell/wallet/capability + HITL urgency) | Host still supplies OS sandbox and egress proxy |
| **LLM07** System Prompt Leakage | Extract hidden system/developer prompts | Overlaps direct override detectors; dedicated leak/roleplay fixtures | Thin→improved (roleplay leak fixture) | System prompt content is host-controlled; package cannot hide what the host puts in context |
| **LLM08** Vector / Embedding Weaknesses | Embedding inversion, poison retrieval | Not in package threat surface (no vector store) | None (acceptable) | Documented N/A |
| **LLM09** Misinformation | Hallucinated / attacker-steered false content | Out of authority-path scope; utility metric only | None (acceptable for Bar A) | Optional later |
| **LLM10** Unbounded Consumption | DoS / cost bombs via huge or recursive prompts | Stage0 size limit; policy `max_bytes` on `web.fetch`; size-bomb fixture | Dedicated size-bomb + Stage0 max bytes | Host must rate-limit model/API spend |

## LLM01 mitigations ↔ controls

| OWASP LLM01:2025 mitigation | Present? | Where |
| --- | --- | --- |
| Constrain model behavior | Host responsibility (partial) | Threat model / agent install; not enforced in-package |
| Validate expected output formats | Yes | `quarantine.closed_object_schema`, `tool_schemas` |
| Input/output filtering | Yes (advisory) | Stage0/1 cascade — **never authorizes** |
| Least privilege | Yes | Default-deny YAML; capability mint; `known_tools` |
| HITL for high-risk | Yes | `require_human` / `require_human_and_mfa` |
| Segregate untrusted content | Yes | Integrity labels; datamark; ingest feeds always untrusted |
| Adversarial testing | Yes (offline) | `fixtures/`, `eval_runner`, release gate eval |

## Expanded red-team fixtures (Bar A)

See `swarm-reports/slice-5-owasp-redteam.md` surgical table. Filenames under `fixtures/attacks/`:

| Fixture | Primary OWASP tags |
| --- | --- |
| `indirect_payload_split_combined.txt` (+ part_a / part_b) | LLM01#6 |
| `direct_adversarial_suffix.txt` | LLM01#8 |
| `encoded_nested_b64_hex.txt` | LLM01#9 |
| `invisible_homoglyph_ignore.txt` | LLM01 |
| `indirect_tool_result_poison.json` | LLM01 + LLM06 |
| `indirect_rag_chunk_poison.txt` | LLM01 / LLM04-adjacent |
| `direct_chatml_delimiter.txt` | LLM01 |
| `direct_hitl_urgency_approve.txt` | LLM06 |
| `direct_ssrf_web_fetch_metadata.txt` | LLM05 + LLM06 |
| `direct_system_prompt_leak_roleplay.txt` | LLM07 |
| `direct_output_html_script.txt` | LLM05 |
| `encoded_size_bomb_b64.txt` | LLM10 |
| `indirect_email_plus_zwsp.txt` | LLM01 composition |

**Multimodal (LLM01 scenario #7):** out of scope for the text fixture corpus; hosts that accept images must add their own vision-path controls.

## Evidence paths

| Path | Role |
| --- | --- |
| `policies/default_deny.yaml` | Least privilege + HITL + taint deny |
| `src/containment/url_guard.py` | SSRF-oriented URL helper (LLM05/06) |
| `src/containment/intent.py` / broker signed intent | Enterprise intent binding (LLM06) |
| `src/containment/capability_store.py` | Multi-process one-use consume |
| `fixtures/attacks/` / `fixtures/benign/` | Adversarial + FPR corpus |
| `docs/THREAT_MODEL.md` | Adversaries + residual risks |
