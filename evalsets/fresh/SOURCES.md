# Fresh evaluation set (1.10.0) — sources, licenses, construction

Built by `scripts/fresh/fetch_sources.py` (download, 2026-11-15) and
`scripts/fresh/build_fresh.py` (deterministic, seed 1100). Frozen by `MANIFEST.sha256`
before any 1.10.0 detector change. Not shipped in the wheel (this directory contains
CC BY-SA 4.0 text; that text stays under CC BY-SA 4.0 with the attribution below).

`holdout.jsonl` is **never** used for training or tuning (only aggregate numbers are read).
`train_pool.jsonl` is the only data used to train the zero-dependency scorer and tune fusion.

## Attack sources

| source | split | license | what is used |
| --- | --- | --- | --- |
| [microsoft/BIPIA](https://github.com/microsoft/BIPIA) `benchmark/{text,code}_attack_test.json` | holdout only | MIT (© Microsoft) | attack instruction strings only (BIPIA contexts come from third-party datasets and are not used) |
| BIPIA `{text,code}_attack_train.json` | train pool only | MIT | attack strings |
| [uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) `attacker_cases_{dh,ds}.jsonl` | holdout only | MIT | attacker instructions, base and "enhanced" (InjecAgent's `IMPORTANT!!! Ignore all previous instructions…` prefix) |
| [ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo) v1 injection-task goals × attack templates (`important_instructions`, `ignore_previous`, `system_message`, `direct`, `injecagent`) | holdout only | MIT | goal strings rendered with the published templates |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) test split, label 1 | holdout only | Apache-2.0 | text |
| deepset/prompt-injections train split, label 1 | train pool only | Apache-2.0 | text |
| [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) train | train pool only | MIT | text |

Independence from the ONNX model: Horizon-Labs/prompt-injection-guard-small lists its
training data as neuralchemy/Prompt-injection-dataset, S-Labs/prompt-injection-dataset,
TrustAIRLab in-the-wild jailbreaks, JailbreakV-28K, nvidia Nemotron-RL-Jailbreak-Robustness,
CohereLabs/aya and its own synthetic data, deduplicated against public eval sets — none of the
holdout attack sources above.

## Benign sources (security-adjacent heavy, multilingual)

Split by group hash `sha256("fresh-1.10:" + group) % 3 == 0` → holdout (all chunks and all
language versions of one Wikipedia topic share a group).

| source | license / attribution |
| --- | --- |
| Wikipedia security articles, EN/RU/JA/DE/FR/ES (≈110 topics: phishing, prompt injection, CVE, malware, red team…) | CC BY-SA 4.0 — text from Wikipedia contributors, https://www.wikipedia.org (article titles are in each item id) |
| OWASP Cheat Sheet Series (`cheatsheets/*.md`) | CC BY-SA 4.0 — © OWASP Foundation, https://github.com/OWASP/CheatSheetSeries |
| OWASP Top 10 for LLM Applications 2025 (`2_0_vulns/*.md`) | CC BY-SA 4.0 — © OWASP Foundation, https://github.com/OWASP/www-project-top-10-for-large-language-model-applications |
| NVD CVE descriptions (pub. 2025-03 and 2025-09), as single entries and 5-entry digests | public domain (US Government work), https://nvd.nist.gov |
| MITRE ATT&CK Enterprise technique descriptions | © The MITRE Corporation; reproduced under the ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/ |
| arXiv abstracts (prompt injection, LLM jailbreak, phishing detection, LLM red teaming) | arXiv metadata, CC0 1.0 |
| deepset/prompt-injections label 0 (test → holdout, train → train pool) | Apache-2.0 |

## Construction (a different process from the 1.8/1.9 mutation suite)

* Every attack appears bare, in two carriers, and (≈1 in 3) planted as its own paragraph at a
  random offset inside a long document of 8 benign same-split prose chunks (≈15–25 KB).
* Carrier template families are **disjoint** between splits: holdout uses email, HTML page
  (sometimes visually hidden), JSON tool output and chat log; the train pool uses memo,
  markdown, CSV and ticket.
* The same carriers wrap benign items containing benign, human-addressed requests ("Please
  complete the mandatory phishing-awareness module by next Monday."), and long benign
  documents are built the same way, so the carrier and the document length are never a signal.
