# Defense Against Prompt Injection for AI Agents, LLMs, Cloud Bots, and Grok-Based Systems

**Research date:** 7 October 2026  
**Scope:** Free and open-source defenses, libraries, framework patches, repositories, architectural patterns, runtime controls, MCP security, testing tools, and a build-it-yourself reference architecture.  
**Priority used for ranking:** Security effectiveness first, followed by architectural coverage, maturity, deployability, performance, openness, and maintenance status.

## Executive findings

Prompt injection is not reliably solvable with a stronger system prompt, a regex, or a single classifier. The underlying failure is that LLM applications place trusted instructions and attacker-controlled data into a shared semantic channel; adaptive attacks have bypassed eight published indirect-injection defenses at greater than 50% attack success, including defenses that looked strong against static tests. The correct engineering objective is therefore **consequence containment**: assume some injections will reach and influence the model, but make unauthorized effects impossible or tightly bounded through deterministic controls outside the model.[^1][^2]

The strongest current open-source strategy is a layered stack:

1. **Deterministic authorization outside the LLM:** mediate every tool call through policy-as-code; deny by default; validate identity, target, arguments, data provenance, and task scope.
2. **Information-flow control and isolation:** label untrusted/private data, propagate labels, prevent tainted values from reaching privileged sinks, and process raw external content in tool-less quarantined contexts.
3. **Control-flow integrity:** create a fixed plan before reading untrusted data, or use a constrained action selector / code-then-execute runtime so retrieved content cannot invent new actions.
4. **Detection in depth:** scan user messages and every retrieved chunk, tool response, memory write, inter-agent message, decoded payload, and generated output. Detection is a risk signal, not an authorization decision.
5. **Capability reduction:** short-lived credentials, per-task tools, read-only defaults, egress allowlists, sandboxes, transaction limits, and explicit approval for consequential actions.
6. **Continuous adversarial evaluation:** use agent-specific benchmarks plus adaptive attacks, and measure both compromise and utility/false positives.

For a greenfield, Python-first agent, the best practical base is **Microsoft Agent Framework FIDES** for deterministic information-flow control, supplemented by an external policy gateway such as **Microsoft Agent Governance Toolkit** or **Invariant Guardrails**, a fast local detector such as **LlamaFirewall / Prompt Guard 2** or **StackOne Defender**, and **AgentDojo + Promptfoo + garak/PyRIT** for regression and red-team testing.[^3][^4][^5][^6][^7][^8][^9][^10]

For a framework-neutral or TypeScript-heavy system, use an MCP/tool-call proxy with default-deny policies, contextual sequence rules, response inspection, and local scanning. Invariant Guardrails, Microsoft Agent Governance Toolkit, StackOne Defender, and MCP-Scan provide the most useful open building blocks in this category.[^9][^11][^12][^10]

For a high-assurance system, adapt **CaMeL’s privileged/quarantined-model architecture** or FIDES-style information-flow control rather than allowing a single tool-enabled model to read arbitrary content. CaMeL tracks dependencies and capabilities and enforces policies in an interpreter, but its public repository explicitly calls itself a research artifact that may contain bugs and may not be fully secure; it is an architectural blueprint, not a drop-in production control.[^13][^14]

## Threat model

### What counts as injection

- **Direct injection:** attacker instructions arrive through the authenticated user channel.
- **Indirect injection:** malicious instructions are embedded in a page, document, email, issue, database row, API response, search result, code comment, image text, or tool output.
- **Triggered injection:** dormant content activates after a later user action, system event, or condition.
- **Tool-description poisoning:** an MCP server or plugin places malicious directions in tool metadata, schemas, or changed definitions.
- **Memory poisoning:** malicious content is persisted and reintroduced in later sessions.
- **Cross-agent injection:** one compromised agent passes instruction-like content to another agent or orchestrator.
- **Multimodal and encoded injection:** payloads are hidden in images, invisible Unicode, Base64, Morse code, encrypted blobs, metadata, or markup.
- **Output-mediated injection:** model output is consumed by another bot, shell, browser, database, workflow engine, or financial service as if text were authorization.

OWASP recommends identifying untrusted content from every channel, validating proposed tool arguments outside the model, granting each tool only the minimum data and operations it needs, requiring approval for consequential actions, and monitoring tool use rather than trusting prompt wording as an enforcement boundary. MITRE ATLAS separately models direct, indirect, and triggered prompt injection and connects injection to downstream tool invocation, exfiltration, and destructive actions.[^15][^16][^1]

### Security properties to enforce

A defensible system should make the following properties explicit and testable:

- **Authority:** only an authenticated principal can authorize an operation; text inside retrieved content has no authority.
- **Integrity:** untrusted data cannot alter privileged control flow or expand the plan.
- **Confidentiality:** private values cannot flow to public or attacker-controlled destinations.
- **Least privilege:** the agent receives only the tools, data, credentials, and network access required for the current step.
- **Argument integrity:** destinations, resource IDs, paths, amounts, recipients, SQL, commands, and URLs are resolved and validated outside the LLM.
- **Provenance:** every value and action retains its origin, transformations, trust level, and authorizing user request.
- **Fail-closed behavior:** detector failure, policy-engine failure, ambiguous identity, unknown tool, or schema mismatch blocks the sensitive operation.
- **Replayability:** security teams can reconstruct the complete sequence from user intent through retrieval and tool execution without storing unnecessary secrets.

## Why common defenses fail

| Defense used alone | Value | Failure mode | Proper role |
|---|---|---|---|
| “Ignore instructions in data” system prompt | Cheap baseline | The model still interprets instructions and data through the same mechanism; adaptive phrasing can win | Advisory layer only |
| Delimiters / XML tags | Improves source clarity | Labels are semantic hints, not a hard trust boundary | Pair with isolation and policy enforcement |
| Regex / keyword blocklists | Very fast; catches commodity payloads | Obfuscation, paraphrase, multilingual text, images, encoding, and benign mentions produce bypasses or false positives | Tier-0 signal |
| Input-only filtering | Useful for direct injection | Misses retrieved pages, search/X results, tool outputs, memory, and downstream bot interactions | Scan every trust boundary |
| Classifier-only blocking | Good low-latency reduction | Distribution shift and adaptive attacks; over-defense can block benign security discussions | Risk signal plus deterministic containment |
| LLM-as-judge only | Better semantic awareness | Cost, latency, correlated model failures, and judge injection | Escalation or audit layer |
| Output filtering only | Can catch leakage | Dangerous calls may already have executed | Check before execution and after output |
| Human approval without resolved details | Adds friction | Users habituate to vague prompts or approve templates whose final arguments changed | Show exact operation, target, data, and provenance |
| Sandboxing only | Limits host damage | Does not prevent authorized API misuse, email exfiltration, or financial transactions | Pair with capabilities and egress policy |

Adaptive evaluation is essential. A peer-reviewed NAACL 2025 study bypassed eight indirect-prompt-injection defenses with attack success consistently above 50%, while a later broad adaptive assessment reported more than 90% success against most of 12 defenses that had often reported near-zero success under weaker tests. These results do not mean filters are useless; they mean filters must not be the component that authorizes consequential behavior.[^2][^17]

## Ranked open-source solutions

The tiers below rank solutions for **new deployments**, not by popularity. “Deterministic” means the final enforcement decision is made in code or policy outside the LLM; it does not imply that every policy or label is automatically correct.

### Tier S: strongest foundations

| Project | Best use | Core approach | Strengths | Limitations / maturity | License or status |
|---|---|---|---|---|---|
| [Microsoft Agent Framework — FIDES](https://github.com/microsoft/agent-framework) | Python agents needing strong prompt-injection and exfiltration containment | Integrity/confidentiality labels, automatic propagation, variable indirection, quarantined LLM, pre-tool policy enforcement | Deterministic sink enforcement; raw untrusted content can be hidden from the privileged context; per-item labels; auditability | Experimental in `agent_framework.security`; tied most directly to Microsoft Agent Framework; correct source labeling and policies remain critical | Open repository; ships in Agent Framework core from v1.3.0 according to Microsoft documentation[^18][^19] |
| [CaMeL](https://github.com/google-research/camel-prompt-injection) | High-assurance custom agent architecture and research reproduction | Privileged planner generates trusted control/data flow; quarantined model handles untrusted data; capability/dependency tracking enforces sink policies | Strong architectural separation and fine-grained information-flow control; directly targets dangerous consequences rather than text patterns | Repository says it is a research artifact, may have bugs, and may not be fully secure; production hardening and policy engineering required | Research artifact; verify repository terms before product incorporation[^13][^14] |
| [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) | Framework-neutral runtime governance, MCP, Python/.NET/TS ecosystems | Policy-as-code, identity, tool interception, sandboxing hooks, audit, rate limits, response sanitization | External pre-execution reference monitor; YAML plus OPA/Rego or Cedar; MCP proxy; broad framework integrations | Newer project; application-layer middleware is not an OS/network security boundary; claims and defaults require local verification | Open-source repository; Python full stack and multi-language SDKs[^8][^11][^20] |
| [Invariant Guardrails](https://github.com/invariantlabs-ai/invariant) + [MCP-Scan](https://github.com/invariantlabs-ai/mcp-scan) | Contextual tool/MCP policies and sequence-aware controls | Proxy or embedded policy engine over message/tool traces, prompt-injection detector, data-flow and tool-sequence rules | Expressive rules can block dangerous combinations such as external read followed by send; local proxy option; good MCP fit | Classifier is explicitly heuristic; policy quality determines coverage; evaluate performance and deployment mode | Open-source projects[^9][^21][^12] |

**Recommendation:** choose one primary deterministic foundation—FIDES, a hardened CaMeL-derived runtime, Microsoft AGT, or Invariant—and make it the only path to privileged tools. Adding several proxies without a single authoritative policy model can create inconsistent decisions and gaps.

### Tier A: best detection and guardrail layers

| Project | Best use | Technology | Strengths | Limitations | License / maintenance |
|---|---|---|---|---|---|
| [Meta LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) | Layered scanning around chat and multi-step agents | Prompt Guard 2 classifier, AlignmentCheck execution-trace auditor, CodeShield, regex | One coherent stack spanning direct injection, goal drift, and generated-code risk; scans traces, not only one message | AlignmentCheck is experimental and needs a capable guard model / trace; detector verdicts remain probabilistic | Framework code shown under MIT; model terms must be reviewed separately[^22][^23][^24] |
| [Llama Prompt Guard 2](https://github.com/meta-llama/PurpleLlama/tree/main/Llama-Prompt-Guard-2) | Fast local direct/indirect-text screening | 86M multilingual mDeBERTa or 22M DeBERTa-xsmall classifier | Small, local, low-latency; 22M model reduces stated latency/compute by 75% with limited trade-off | Text classifier; not an authorization boundary; benchmark locally for domain shift and false positives | Openly released model/code; inspect model-specific license[^25] |
| [StackOne Defender](https://github.com/StackOneHQ/defender) / [Python port](https://github.com/StackOneHQ/defender-py) | Inline scanning and sentence-level sanitization of tool results | Pattern checks plus bundled quantized 22 MB MiniLM classifier | CPU-only, package-local, designed for indirect injection in email/doc/API results; returns sanitized content and risk verdict | Newer and narrower than a complete firewall; vendor benchmark claims need independent testing; OSS edition lacks hosted deep scan | Apache-2.0; TypeScript and Python[^10][^26][^27] |
| [NVIDIA NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) | Programmable rails around conversational and RAG systems | Colang flows, input/output/retrieval rails, self-checks, heuristics, safety-model integrations | Mature orchestration surface; retrieval rails can reject or transform chunks before prompting; model-agnostic integration | A framework, not a guarantee; advanced NVIDIA detectors may involve NIM services, while some self-checks add model cost | Apache-2.0[^28][^29][^30] |
| [PIGuard / InjecGuard](https://github.com/leolee99/PIGuard) | Research-grade open detector with anti-over-defense focus | Fine-tuned guard model with Mitigating Over-defense for Free training | Open training data, code, and weights; explicitly optimizes benign/malicious and over-defense accuracy | Research model; independently test distribution shift, languages, long documents, and agent traces | Open repository with checkpoints and datasets[^31] |
| [SecAlign](https://github.com/facebookresearch/SecAlign) | Teams controlling their own base model and training stack | Preference optimization on secure vs injected response pairs | Model-level hardening can complement runtime controls and was designed for indirect injection | Requires fine-tuning/deployment control; adaptive evaluations can erase apparent gains; not a hard boundary | Open research repository[^32][^2] |
| [OpenAI Guardrails Python](https://github.com/openai/openai-guardrails-python) / TypeScript | OpenAI-centric apps needing quick tool-level checks | Configurable checks on input/output, function calls, and tool results using model analysis | Integrates with OpenAI Agents SDK; checks each tool call and result for alignment | Open library but normally depends on OpenAI models/services; probabilistic and vendor-centric | Open-source preview library[^33][^34][^35] |
| [Guardrails AI](https://github.com/guardrails-ai/guardrails) and Hub validators | Composable Python input/output validation | Validator pipeline; injection checks via classifier or secondary LLM | Useful framework for schema and output constraints; extensible | Individual validators vary in maintainer, license, quality, and dependencies; older Rebuff-based validator moved/archived | Core and validators are open source, but inspect each package[^36][^37][^38] |

### Tier A: runtime and tool-control components

| Project / method | Why it matters | Recommended use |
|---|---|---|
| [Progent](https://github.com/sunblaze-ucb/progent) | Uses a DSL and reference-monitor approach to restrict tool calls by task-specific privilege policy; paper reports AgentDojo ASR reduction from 41.2% to 2.2% with combined policies.[^39] | Borrow its fine-grained tool-policy model or evaluate the research implementation; manually review any LLM-generated policy before it controls high-risk tools. |
| [IPIGuard](https://github.com/Greysahy/ipiguard) | Builds a Tool Dependency Graph before execution and disallows tools outside the pre-approved graph, separating planning from untrusted interaction.[^40] | Strong pattern for repeatable workflows with predictable tool topology; less suitable when truly open-ended replanning is required. |
| Task Shield | Checks whether each instruction and proposed call contributes to the authenticated user’s objective; paper reports 2.07% ASR and 69.79% task utility on GPT-4o/AgentDojo.[^41] | Implement as a semantic pre-action reviewer behind deterministic allowlists, not as the sole authorization layer. |
| Tool-result extraction / CheckTool | Parses and validates tool results, returns only fields needed by the agent, and treats unexpected action-triggering content as suspicious.[^42] | Use typed extractors per tool to minimize context and eliminate free-form fields whenever possible. |
| [Spotlighting implementation](https://github.com/realArcherL/spotlighting-datamarking) | Marks or encodes untrusted data so models can better distinguish it from instructions.[^43] | Low-cost supporting layer for RAG and summarization; do not rely on it against adaptive adversaries. |
| [Secure-agent design-pattern demos](https://github.com/ReversecLabs/design-patterns-for-securing-llm-agents-code-samples) | Runnable examples of action-selector, plan-then-execute, map-reduce, dual-LLM, code-then-execute, and context-minimization patterns.[^44] | Excellent starting point for redesigning an agent so external text cannot determine privileged control flow. |

### Tier A: evaluation and red teaming

| Project | Primary role | Key capabilities | Recommendation |
|---|---|---|---|
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | Agent-specific indirect-injection benchmark | Realistic tool tasks, attack goals, defenses, utility and security measurements; installable Python package | Make this the base regression suite for tool-using agents; add organization-specific tasks and tools.[^45][^3] |
| [Promptfoo](https://github.com/promptfoo/promptfoo) | CI-friendly eval and red-team runner | Declarative tests, prompt injection/jailbreak/agent testing, multi-provider support, CI integration | Best general continuous security regression harness, especially for JS/TS teams; MIT licensed.[^4][^46] |
| [garak](https://github.com/NVIDIA/garak) | Broad LLM vulnerability scanner | Prompt-injection, latent-injection, jailbreak, leakage, toxicity and many other probes | Use for model/API breadth and nightly scans; Apache-2.0.[^5][^47] |
| [PyRIT](https://github.com/Azure/PyRIT) | Programmable multi-turn red-team orchestration | Adaptive conversations, converters/encodings, XPIA-style testing, extensible targets and scorers | Use for deeper Python red-team campaigns and custom multi-turn attack chains; MIT.[^6][^48] |
| [AdaptiveAttackAgent](https://github.com/uiuc-kang-lab/AdaptiveAttackAgent) | Defense-aware adaptive attack evaluation | Reproduces attacks against detectors, prompting defenses, paraphrasing, adversarial fine-tuning, and perplexity filtering | Mandatory before claiming a detector or prompt defense is robust.[^49] |
| [Prompt Injection Assessment](https://github.com/TrustAIRLab/Prompt_Injection_Assessment) | Comparative research harness | 21 attack methods, seven defenses, multiple LLM families | Useful for comparing paraphrase, spotlighting, defensive prompts, SecAlign, and StruQ under one pipeline.[^50] |
| [AgentDojo in UK Inspect Evals](https://ukgovernmentbeis.github.io/inspect_evals/evals/agentdojo/) | Reproducible eval integration | Reports benign utility, utility under attack, and security | Useful if the organization standardizes on Inspect Evals.[^51] |
| [Prompt Injection Detection Benchmark](https://github.com/directivecommons/prompt-injection-benchmark) | Detector test corpus | Attacks plus over-defense cases for RAG, tools, context windows, and code | Useful dataset and methodology, but repository was archived in March 2026; vendor and domain-specific suites should supplement it.[^52] |

### Tier B: useful scanners and ecosystem controls

- **[Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner):** scans live MCP servers/tools with YARA, prompt-defense, package behavioral analysis, and optional service-backed analysis. Its prompt-defense scan can run without API keys.[^53]
- **[Snyk Agent Scan](https://github.com/snyk/agent-scan):** discovers local agent components, MCP servers, and skills, then flags prompt injection, tool poisoning, toxic flows, malware-like content, secrets, and unsafe capabilities.[^54]
- **[MCP-Scan](https://github.com/invariantlabs-ai/mcp-scan):** combines static/dynamic scanning with a local proxy and policy constraints for tool calls, data flow, PII, and indirect injection.[^12]
- **[Microsoft Agent Governance Toolkit MCP proxy](https://github.com/microsoft/agent-governance-toolkit):** protects `tools/call` with input sanitization, ordered policies, path/argument checks, rate limits, and auditing; use allowlist-only `strict` behavior for sensitive deployments.[^11]
- **[Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules):** community detection-rule approach for prompt injection, tool poisoning, exfiltration, and MCP threats; useful for SIEM/runtime detection, but signature rules are supplementary.[^55]
- **[NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector):** pre-installation scanning for agent skills and supply-chain content is relevant because skill files and documentation can carry persistent injections.[^56]

Treat very new security repositories cautiously. Before adoption, verify releases, signed commits or provenance, issue response, test coverage, dependency hygiene, model/data licenses, benchmark leakage, maintainer activity, and whether advertised measurements are reproducible.

### Legacy / do not start new production deployments

| Project | Why it was notable | Current recommendation |
|---|---|---|
| [Protect AI Rebuff](https://github.com/protectai/rebuff) | Clear four-layer design: heuristics, LLM detector, vector similarity, and canary tokens | Repository was archived in May 2025 and labels itself a prototype without 100% protection; use as design reference only unless maintaining a fork.[^57] |
| [Protect AI LLM Guard](https://github.com/protectai/llm-guard) | Broad input/output scanner collection including injection, secrets, invisible text, regex, and toxicity | Repository was archived in July 2026; avoid as a new upstream dependency unless the team owns a maintained fork.[^58] |
| Guardrails AI’s old `detect_prompt_injection` repository | Convenient Rebuff-based validator | Archived and moved to the monorepo; use current Hub packages and inspect their implementation/dependencies.[^36] |
| Vigil and small regex-only packages | Lightweight and easy to embed | Useful as Tier-0 telemetry, not a security boundary; confirm maintenance and benchmark against local benign corpora. |

## Best build-it-yourself architecture

### Reference data flow

```text
Authenticated user / scheduler
          |
          v
[Intent & identity envelope] ---- signed task ID, tenant, user, scope, risk budget
          |
          v
[Privileged planner] ------------ sees trusted request and tool schemas only
          |
          v
[Immutable plan / capability set] ---- exact tools, resources, limits, expiry
          |
          v
[Policy reference monitor] <----- identity, policy-as-code, taint/provenance state
   | allow read-only step
   v
[Tool adapter / MCP proxy] ------ schema validation, SSRF/path/SQL/command controls
   |
   v
[Untrusted external result]
   |
   +--> normalize/decode/OCR safely
   +--> fast rules + local classifier
   +--> store raw object outside privileged context
   +--> quarantined, tool-less extractor -> typed minimal fields + provenance
   |
   v
[Privileged executor] ----------- receives references/typed fields, not raw text
   |
   v
[Pre-action policy gate] -------- validates tool, target, args, taint, sequence
   |          |
   |          +--> human approval for new destination/destructive/high-value action
   v
[Sandboxed tool execution] ------ short-lived credentials + network egress allowlist
   |
   v
[Output DLP / renderer safety] -- secret/PII scan, URL/HTML/Markdown sanitization
   |
   v
[Append-only trace + alerts] ---- redacted evidence, decisions, provenance, hashes
```

This architecture follows the common principle from secure-agent design research: after an agent consumes untrusted content, that content must not be able to trigger consequential actions. The safest patterns separate the privileged controller from tool-less processors, constrain outputs to typed formats, and fix the action plan before external content is read.[^59][^60]

### Core runtime objects

Use explicit structures rather than raw message strings:

```python
@dataclass(frozen=True)
class SecurityLabel:
    integrity: Literal["trusted", "untrusted"]
    confidentiality: Literal["public", "private", "identity"]
    source: str
    task_id: str
    transformations: tuple[str, ...]

@dataclass(frozen=True)
class ProposedAction:
    tool: str
    arguments: dict
    principal: str
    task_id: str
    reason_code: str
    input_labels: tuple[SecurityLabel, ...]
    plan_step: str
```

Do not ask the model whether it is authorized. The model may propose `ProposedAction`; a deterministic reference monitor must authenticate the principal, validate JSON Schema, verify the action appears in the immutable plan, resolve arguments, calculate taint, evaluate policy, require approval if needed, and only then mint a one-use capability for the executor.

### Example policy

```yaml
version: 1
default: deny

rules:
  - id: read-public-web
    effect: allow
    tool: web.fetch
    when:
      principal.authenticated: true
      args.url.scheme: https
      args.url.host_in: approved_public_hosts
      task.capabilities_contains: web.fetch
    limits:
      redirects: 0
      max_bytes: 2000000
      network: public_only

  - id: no-tainted-egress
    effect: deny
    tool_in: [email.send, http.post, social.publish, wallet.transfer]
    when:
      input.any_integrity: untrusted

  - id: approved-email
    effect: require_human
    tool: email.send
    when:
      task.capabilities_contains: email.send
      args.recipient_in: task.approved_recipients
      args.body_confidentiality_lte: private
    display:
      - resolved_recipient
      - resolved_subject
      - resolved_body
      - data_sources

  - id: transfer-limit
    effect: require_human_and_mfa
    tool: wallet.transfer
    when:
      args.amount_lte: task.transaction_limit
      args.destination_in: task.approved_wallets
      input.all_integrity: trusted
```

The crucial rule is not “block the phrase *ignore previous instructions*.” It is “untrusted or unauthorized data cannot reach a privileged sink,” regardless of how persuasive or obfuscated the text is.

### Ingestion patch

Patch every function that introduces content into context—not just the chat endpoint:

1. Assign source, tenant, user, integrity, confidentiality, and task labels.
2. Normalize Unicode and safely inspect common encodings; preserve the original object for forensic hashing.
3. Strip active HTML, remote images, scripts, CSS tricks, hidden text, and unsafe Markdown links before rendering.
4. Split structured objects by field and scan each field/sentence; never concatenate an entire tool response first.
5. Keep raw content outside the privileged context. Give it to a quarantined model with no tools, credentials, memory write, or network.
6. Request a narrow typed result such as `{invoice_number, total, currency}` rather than a prose summary.
7. Validate the output against a closed JSON Schema; reject extra keys, URLs, commands, markup, and instruction-like fields when not needed.
8. Propagate provenance and taint into every derived value.
9. Treat translation, OCR, decryption, decompression, and code output as newly revealed untrusted content and rescan it.
10. Prevent untrusted content from writing long-term memory unless it passes a separate approval and TTL policy.

### Tool-execution patch

All tool frameworks—LangChain, LangGraph, AutoGen, CrewAI, OpenAI Agents SDK, Google ADK, custom Grok apps, MCP clients, and cloud workflow bots—should route through a single broker:

```python
async def secure_execute(action: ProposedAction):
    schema_validate(action.tool, action.arguments)
    resolved = resolve_and_canonicalize(action)
    decision = policy_engine.evaluate(resolved, security_state())
    audit.append(resolved, decision)

    if decision.effect == "deny":
        raise SecurityViolation(decision.rule_id)
    if decision.effect.startswith("require_human"):
        await approval.verify_exact(resolved, require_mfa="mfa" in decision.effect)

    token = capability_minter.one_use(
        tool=resolved.tool,
        resources=resolved.resources,
        expiry_seconds=60,
    )
    return await sandbox.run(resolved, token=token)
```

The broker must reject unknown tools and fields, canonicalize paths and URLs before policy checks, resolve DNS and block private/link-local/metadata addresses, use parameterized database queries, avoid shell interpretation, enforce file-root confinement, cap output sizes and recursion, and bind approvals to a cryptographic hash of the exact resolved action.

### Detector cascade

Use risk-based escalation to control cost:

- **Stage 0 — deterministic parser:** Unicode normalization, hidden-character checks, markup stripping, MIME enforcement, decompression limits, encoded-content discovery, and strict schemas.
- **Stage 1 — local fast detector:** Prompt Guard 2 22M/86M, StackOne Defender, PIGuard, or an independently benchmarked local classifier.
- **Stage 2 — contextual detector:** evaluate source role, user goal, previous calls, candidate tool, arguments, and destinations. LlamaFirewall AlignmentCheck or Invariant-style sequence rules fit here.[^61][^21]
- **Stage 3 — policy decision:** deterministic allow/deny/review based on identity, capabilities, taint, and exact operation.
- **Stage 4 — postcondition check:** confirm actual effects, scan returned data, revoke one-use credentials, and compare execution with the approved action.

Run Stage 1 on all untrusted fields; run expensive Stage 2 only for ambiguity or sensitive workflows. Never let a “safe” classifier verdict bypass Stage 3.

## Grok and cloud-bot guidance

### Clarify the Grok surface

“Grok bot” can mean the public assistant on X, xAI’s collaborative Grok Bot product, or an application built with the Grok API. The controls differ:

- **Public Grok on X:** the application owner does not control xAI’s retrieval and execution harness. Do not connect public text output to authorization-sensitive automation.
- **Grok Bot:** xAI documents Auto Review for risky actions plus network policy, per-action approvals, per-user isolation, and marking external content as untrusted; xAI also states that these controls reduce but do not eliminate risk.[^62]
- **Custom Grok API application:** built-in tools execute server-side, while custom function calls return to the application for execution. The application fully controls whether custom calls run, so every call must pass the same external broker and policy checks used for any other model.[^63][^64]

### Grok-specific recommendations

1. **Never treat a Grok/X post, mention, reply, generated phrase, or decoded message as authority.** Authorization must be bound to an authenticated user and a signed, exact operation.
2. **Prefer custom function calling for consequential actions.** It pauses in application code, permitting schema validation, policy evaluation, approval, and one-use credentials before execution.[^64]
3. **Assume built-in Web Search and X Search can ingest attacker-controlled content.** Do not allow data learned through those tools to select an external recipient, URL, wallet, command, or privileged resource without a separate trusted decision path.
4. **Disable parallel function calls for sensitive workflows** so each call can be reviewed against updated state and provenance; xAI’s API exposes `parallel_tool_calls: false`.[^64]
5. **Turn on Grok Bot Auto Review and keep per-action approvals for shell, plugins, computer use, automation changes, cloud/subagent launches, outbound communications, and financial operations.**[^62]
6. **For public-facing bots, isolate identity and credentials per user/tenant**, cap actions and spend, and prohibit ambient authority inherited from the bot’s social account.
7. **Treat code-interpreter decoding as an untrusted-data transformation.** If an opaque/encrypted payload is decoded, the plaintext must re-enter the ingestion pipeline with no new authority.
8. **Record resolved tool traces**—model, task, user identity, retrieved source, exact function/arguments, policy result, approval hash, and effect—for incident response.

The key lesson from output-mediated bot failures is architectural: a downstream service must not interpret public model-generated text as authenticated approval. Text can express a proposal; a separate signed control channel must authorize the action.

## RAG, browser, email, and coding agents

### RAG and search

- Index-time scan documents and retain source-level trust metadata.
- Keep tenants and security domains in separate indexes.
- Retrieve only the minimum chunks; do not inject whole pages when a typed extractor can answer.
- Sanitize at both index and query time because stored content may change or evade the first detector.
- Never allow retrieved text to modify system prompts, tool schemas, policies, goals, or memory directly.
- Attach chunk provenance and taint through generation and downstream calls.
- Use NeMo retrieval rails or equivalent middleware to reject/mask chunks before they reach the main model.[^29]

### Browser agents

- Separate page-reading from action execution.
- Use browser/network isolation, origin allowlists, no ambient cookies where possible, download quarantine, and explicit approval for uploads, login, purchases, messages, and new domains.
- Treat DOM text, accessibility trees, image OCR, alt text, PDFs, and downloaded files as attacker-controlled.
- Disallow a page from instructing the agent to navigate to a new origin with private data in query strings.
- Bind every form submission to a user-approved origin, fields, and values.

### Email and office bots

- Treat subject, body, sender display name, signatures, quoted threads, calendar invites, attachments, hidden text, links, and metadata as data—not authority.
- Reading mail must not automatically grant `send`, `forward`, `delete`, `create_rule`, or `download_and_execute` capabilities.
- Extract typed fields in quarantine and require exact confirmation for recipients, body, attachments, and rule changes.
- Block secret/private-data egress to recipients not explicitly approved in the live task.

### Coding agents

- Assume repository files, issues, dependency docs, test fixtures, terminal output, compiler errors, and webpages can contain injections.
- Run generated code and tests in disposable sandboxes without production credentials; deny network by default.
- Protect agent configuration, hooks, CI files, package manifests, and skill/MCP definitions with code review and signed baselines.
- Require review for dependency installation, remote scripts, CI modification, secret access, publishing, pushing, merging, or commands outside the workspace.
- Apply static analysis to generated code; LlamaFirewall’s CodeShield is one open component for this layer, but normal SAST/SCA/secret scanning remains necessary.[^65][^23]

## Multi-agent and MCP security

### Multi-agent boundaries

Each agent needs its own identity, scope, tools, credentials, memory namespace, and policy. A subagent must not inherit the orchestrator’s full privileges. Inter-agent messages should carry authenticated origin, task ID, delegation scope, provenance, integrity/confidentiality labels, expiry, and a signature; receivers should reject unsigned or over-scoped requests.

Do not allow an agent’s natural-language claim—“the supervisor approved this”—to change authority. Delegation should be a machine-verifiable capability with exact permitted tools, resources, limits, and duration.

### MCP hardening checklist

- Pin server package/version and record a hash of tool definitions.
- Rescan when names, descriptions, schemas, binaries, or endpoints drift.
- Treat tool names/descriptions/resources/prompts as untrusted supply-chain input.
- Put an MCP proxy between clients and servers; enforce identity, allowlists, arguments, rate limits, sequence policy, and response scanning.
- Deny shell/eval tools by default; restrict file roots; canonicalize paths; block symlink escapes.
- Prevent SSRF by resolving destinations, blocking private/link-local/cloud-metadata ranges, limiting redirects, and applying DNS-rebinding defenses.
- Use per-server service accounts and short-lived credentials.
- Sanitize or quarantine tool responses before they return to the model.
- Log and alert on tool-definition drift, new capabilities, tainted-read-to-egress chains, and repeated denied calls.
- Scan local configurations and installed skills with MCP-Scan, Cisco MCP Scanner, Snyk Agent Scan, or comparable tools before activation.[^53][^54][^12]

## Deployment profiles

### Lightweight chatbot, no tools

- Structured instruction/data separation.
- Prompt Guard 2 or PIGuard on user input.
- Output secret/PII and renderer sanitization.
- Rate limits, abuse identity, logging, and Promptfoo/garak tests.
- No claim of “injection-proof”; impact is naturally lower because there are no privileged tools.

### RAG assistant, read-only

- All controls above.
- Per-source trust labels, index/query scanning, minimal chunk retrieval.
- Quarantined typed extraction for high-risk sources.
- No hidden tool or memory writes.
- AgentDojo-like indirect-injection tests adapted to local content.

### Enterprise action agent

- FIDES, hardened CaMeL pattern, AGT, or Invariant as authoritative runtime layer.
- Immutable plan or narrowly bounded replanning.
- Per-step capabilities and one-use credentials.
- Egress restrictions and sandboxed tools.
- Human approval tied to exact resolved actions.
- Local detector plus contextual trace monitor.
- Continuous AgentDojo, Promptfoo, PyRIT, garak, and adaptive-attack testing.

### High-risk finance, identity, health, infrastructure

- No autonomous irreversible action from an LLM-only decision.
- Separate authenticated transaction channel with MFA or cryptographic signing.
- Pre-registered recipients/resources and strict value limits.
- Dual control for high-value changes.
- Deterministic reconciliation and postconditions.
- Independent kill switch and credential revocation.
- Treat model output solely as a draft or proposal.

## Evaluation methodology

### Metrics

Measure at least:

- **Attack success rate:** malicious objective completed.
- **Benign utility:** ordinary tasks completed without attacks.
- **Utility under attack:** legitimate task still completes despite malicious content.
- **False-positive rate / over-defense:** benign discussions, security text, translations, code, and quoted attacks incorrectly blocked.
- **False-negative rate:** attacks accepted.
- **Consequence rate:** unauthorized side effect actually occurred; this is more important than whether the model repeated malicious text.
- **Detection latency:** p50/p95/p99 per stage.
- **Policy latency:** reference-monitor overhead.
- **Cost:** tokens/API calls and infrastructure per task.
- **Coverage:** percentage of ingress channels, tools, sinks, and agent-to-agent edges mediated.
- **Forensic completeness:** percentage of actions reconstructable from redacted logs.

AgentDojo explicitly separates benign utility, utility under attack, and security; preserve that three-way view so a defense cannot appear secure merely by refusing everything.[^51]

### Test corpus

Include:

- Direct, indirect, triggered, delayed, and multi-turn attacks.
- Benign content that discusses injections, system prompts, exploits, commands, and roleplay.
- Multilingual attacks, including Japanese given the deployment context, plus mixed scripts.
- Unicode/invisible text, HTML/CSS hiding, Base64/hex/URL encoding, Morse, compression, OCR, QR/image text, and encrypted blobs.
- Long-context placement, fragmented payloads across chunks/messages, and cross-document composition.
- Tool descriptions, schemas, tool results, MCP resources, skills/plugins, memory, and inter-agent messages.
- Goal hijacking, prompt extraction, secret exfiltration, confused-deputy chains, unauthorized recipients, destructive actions, SSRF, path traversal, SQL/shell injection, and social publishing.
- Adaptive attacks tuned against the exact detector thresholds and policy behavior.

### Release gates

A production release should fail if:

- Any consequential tool bypasses the reference monitor.
- Any untrusted source lacks provenance/taint labeling.
- Unknown tools or schema fields are allowed.
- A sensitive operation can run without exact argument validation.
- A new destination can receive private data without approval.
- Detector/policy outages fail open.
- Security regression increases consequence rate beyond the defined budget.
- Utility falls below the service target or false positives create unsafe workarounds.
- Red-team failures lack a reproducible test committed to the suite.

## Implementation roadmap

### First 72 hours

- Inventory every model, prompt, retrieval source, memory store, agent, MCP server, tool, credential, and external sink.
- Disable unnecessary tools and autonomous writes; rotate over-broad credentials.
- Put irreversible and outbound operations behind explicit approval.
- Block public model-generated text from acting as authorization.
- Add logging for resolved tool calls, policy decisions, and outcomes.
- Add a kill switch that revokes agent credentials and stops queued actions.

### First two weeks

- Introduce a central tool broker with default deny, JSON Schema validation, resource allowlists, and task-scoped capabilities.
- Add a fast local scanner at every external-content boundary and run it in monitor mode first to establish false-positive baselines.
- Quarantine raw retrieved content and return typed minimal fields.
- Enforce egress and sandbox controls.
- Add Promptfoo and AgentDojo-style tests to CI; run garak/PyRIT on a scheduled cadence.
- Scan MCP servers, skills, and agent configurations before use.

### First two months

- Adopt FIDES or implement equivalent integrity/confidentiality labels and propagation.
- Redesign open-ended agents toward plan-then-execute, dual-LLM, action-selector, or code-then-execute patterns.
- Add sequence-aware policies such as “untrusted web read cannot be followed by external send.”
- Bind approval to resolved action hashes and add MFA for high-risk operations.
- Build local attack/benign datasets and calibrate detector thresholds per workflow and language.
- Run adaptive attacks against the complete system, not only the base model.
- Establish incident response for injection: isolate session, revoke capabilities, preserve redacted evidence, identify affected sinks, patch policy, and add regression tests.

## Selection guide

| Need | First choice | Add-ons |
|---|---|---|
| Strongest Python agent containment | Microsoft Agent Framework FIDES | LlamaFirewall or StackOne detector; AgentDojo; external sandbox/egress |
| High-assurance custom design | Hardened CaMeL-derived dual-LLM + capability runtime | Independent policy audit, typed extractors, human approval |
| Framework-neutral tool/MCP governance | Microsoft Agent Governance Toolkit or Invariant Guardrails | MCP-Scan/Cisco/Snyk scanner; local detector |
| Fast local text/tool-output detector | Prompt Guard 2 or StackOne Defender | Contextual action alignment and deterministic policy gate |
| RAG guardrail orchestration | NeMo Guardrails retrieval rails | Prompt Guard 2/PIGuard; provenance and quarantined extraction |
| OpenAI Agents SDK | OpenAI Guardrails for convenient checks | External policy gateway; do not make model check the final authority |
| Grok API application | Custom function calls through a policy broker | Disable parallel calls for sensitive flows; scan custom tool results; approval |
| Broad CI red teaming | Promptfoo | AgentDojo for agents; garak for breadth; PyRIT/adaptive attacks for depth |
| MCP/skill supply-chain scan | MCP-Scan, Cisco MCP Scanner, Snyk Agent Scan | Version pinning, signed baselines, runtime proxy |
| Self-hosted model hardening | SecAlign/PIGuard experimentation | Runtime policy and isolation remain mandatory |

## Procurement and repository due diligence

Before adopting any “open-source prompt injection defense,” verify:

- OSI license for code and separate terms for model weights and datasets.
- Last release, commit activity, issue response, maintainers, security policy, and signed artifacts.
- Exact benchmark split, contamination controls, benign set, multilingual coverage, and adaptive evaluation.
- False-positive rate on the organization’s real corpus.
- Whether scans are local or send sensitive prompts/tool results to a third party.
- Fail-open vs fail-closed behavior, timeout handling, and size limits.
- Whether the component checks direct input only or also retrieval, tools, memory, multimodal content, and action traces.
- Whether it merely detects or can deterministically block at the executor boundary.
- How labels/provenance survive serialization, queues, retries, caching, and agent-to-agent calls.
- Whether an attacker can modify policies, thresholds, logs, detector models, tool schemas, or the proxy itself.

## Final assessment

The best available technology is no longer a single “prompt firewall.” It is a secure agent runtime that treats the model as an untrusted decision proposer, external content as tainted data, tools as privileged capabilities, and every consequential effect as a policy-mediated transaction. FIDES and CaMeL represent the strongest information-flow and isolation direction; Microsoft Agent Governance Toolkit and Invariant provide practical external enforcement; LlamaFirewall, Prompt Guard 2, StackOne Defender, NeMo Guardrails, PIGuard, and SecAlign add useful probabilistic resistance; AgentDojo, Promptfoo, garak, PyRIT, and adaptive-attack harnesses keep the stack honest.[^31][^23][^32][^14][^4][^5][^6][^7][^8][^49][^10][^29][^3][^9]

No current open-source component justifies an “injection-proof” claim. A defensible claim is narrower and testable: even if malicious content influences model text, untrusted data cannot acquire authority, privileged calls cannot bypass the reference monitor, sensitive data cannot cross forbidden flows, and irreversible actions require exact independent authorization.

---

## References

1. [LLM Prompt Injection Prevention - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) - Website with the collection of all the cheat sheets of the project.

2. [Adaptive Attacks Break Defenses Against Indirect Prompt ...](https://aclanthology.org/2025.findings-naacl.395/) - by Q Zhan · 2025 · Cited by 159 — we evaluate eight different defenses and bypass all of them using ...

3. [ethz-spylab/agentdojo: A Dynamic Environment to ...](https://github.com/ethz-spylab/agentdojo) - AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents Gi...

4. [Promptfoo: LLM evals & red teaming](https://github.com/promptfoo/promptfoo) - Test your prompts, agents, and RAGs. Red teaming/pentesting/vulnerability scanning for AI. Compare p...

5. [NVIDIA/garak: the LLM vulnerability scanner - GitHub](https://github.com/NVIDIA/garak/) - the LLM vulnerability scanner. Contribute to NVIDIA/garak development by creating an account on GitH...

6. [DemocratizingAIRedTeaming - commandline.microsoft.com](https://commandline.microsoft.com/wp-content/uploads/2026/08/PyRIT_Whitepaper_2026.pdf)

7. [agent-framework/docs/features/FIDES_IMPLEMENTATION ... - GitHub](https://github.com/microsoft/agent-framework/blob/main/docs/features/FIDES_IMPLEMENTATION_SUMMARY.md) - A framework for building, orchestrating and deploying AI agents and multi-agent workflows with suppo...

8. [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) - AGT enforces governance at the application middleware layer, not at the OS kernel level. The policy ...

9. [GitHub - invariantlabs-ai/invariant: Guardrails for secure and robust agent development](https://github.com/invariantlabs-ai/invariant/) - Guardrails for secure and robust agent development - invariantlabs-ai/invariant

10. [GitHub - StackOneHQ/defender: Open source prompt injection ...](https://github.com/stackoneHQ/defender) - Open source prompt injection protection for Agents calling tools (via MCP, CLI or direct function ca...

11. [Supplemental: MCP Governance Policies](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/tutorials/policy-as-code/mcp-governance.md) - AI Agent Governance Toolkit — Policy enforcement, zero-trust identity, execution sandboxing, and rel...

12. [invariantlabs-ai/mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) - Constrain, log and scan your MCP connections for security vulnerabilities. - invariantlabs-ai/mcp-sc...

13. [camel-prompt-injection/README.md at main · google-research ...](https://github.com/google-research/camel-prompt-injection/blob/main/README.md) - Code for the paper "Defeating Prompt Injections by Design" - google-research/camel-prompt-injection

14. [Defeating Prompt Injections by Design - arXiv](https://arxiv.org/html/2503.18813v2)

15. [MITRE ATLAS is now an agent security framework - Speakeasy](https://www.speakeasy.com/blog/mitre-atlas-explained) - MITRE ATLAS is a knowledge base of adversary tactics and techniques against AI systems, built on the...

16. [MITRE ATLAS Prompt Injection: Mapping Techniques to Workflows](https://witness.ai/blog/mitre-atlas-prompt-injection/) - Map MITRE ATLAS prompt injection techniques (AML.T0051) to runtime controls, guardrails, and respons...

17. [The Attacker Moves Second: Stronger Adaptive ...](https://www.alphaxiv.org/abs/2510.09023) - An assessment of 12 diverse Large Language Model (LLM) defenses reveals their overwhelming vulnerabi...

18. [Stop prompt injection from hijacking your agent, new security ...](https://devblogs.microsoft.com/agent-framework/fides/) - Prompt injection is the #1 risk on the OWASP LLM Top 10, and most agents in production today defend ...

19. [agent-framework/python/samples/02-agents/security ...](https://github.com/microsoft/agent-framework/blob/main/python/samples/02-agents/security/FIDES_DEVELOPER_GUIDE.md) - FIDES is a comprehensive security system for AI agents. This developer guide describes the determini...

20. [agent-governance-toolkit/docs/FAQ.md at main · microsoft ...](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/FAQ.md) - AI Agent Governance Toolkit — Policy enforcement, zero-trust identity, execution sandboxing, and rel...

21. [docs/docs/mcp-scan/guardrails-reference.md at main](https://github.com/invariantlabs-ai/docs/blob/main/docs/mcp-scan/guardrails-reference.md) - This chapter covers the fundamentals of guardrailing with Invariant, with a primary focus on how Inv...

22. [How to use LlamaFirewall | LlamaFirewall - meta-llama.github.io](https://meta-llama.github.io/PurpleLlama/LlamaFirewall/docs/documentation/getting-started/how-to-use-llamafirewall) - Prerequisites

23. [[2505.03574] LlamaFirewall: An open source guardrail system ...](https://ar5iv.labs.arxiv.org/html/2505.03574) - Large language models (LLMs) have evolved from simple chatbots into autonomous agents capable of per...

24. [Notebook: Standalone Agent with LlamaFirewall | LlamaFirewall](https://meta-llama.github.io/PurpleLlama/LlamaFirewall/docs/tutorials/standalone-agent-llamafirewall-tutorial) - This demo showcases a standalone agent implementation that integrates LlamaFirewall for security sca...

25. [PurpleLlama/Llama-Prompt-Guard-2/86M/MODEL_CARD.md ... - GitHub](https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Prompt-Guard-2/86M/MODEL_CARD.md) - Set of tools to assess and improve LLM security. Contribute to meta-llama/PurpleLlama development by...

26. [GitHub - StackOneHQ/stackone-defender](https://github.com/StackOneHQ/defender-py) - Contribute to StackOneHQ/defender-py development by creating an account on GitHub.

27. [Defender - Stackone](https://docs.stackone.com/secure/defender)

28. [GitHub - NVIDIA/NeMo-Guardrails: NeMo Guardrails is an open-source toolkit for easily adding programmable guardrails to LLM-based conversational systems.](https://github.com/nvidia/nemo-guardrails) - NeMo Guardrails is an open-source toolkit for easily adding programmable guardrails to LLM-based con...

29. [NeMo-Guardrails/README.md at main · NVIDIA/NeMo-Guardrails](https://github.com/NVIDIA/NeMo-Guardrails/blob/main/README.md) - NeMo Guardrails is an open-source toolkit for easily adding programmable guardrails to LLM-based con...

30. [NVIDIA NeMo Guardrails Library](https://github.com/NVIDIA-NeMo/Guardrails) - NeMo Guardrails is an open-source toolkit for easily adding programmable guardrails to LLM-based con...

31. [PIGuard: Prompt Injection Guardrail via Mitigating ...](https://github.com/leolee99/PIGuard) - [ACL 2025] The official implementation of the paper "PIGuard: Prompt Injection Guardrail via Mitigat...

32. [Repo for the research paper "SecAlign: Defending Against ...](https://github.com/facebookresearch/SecAlign) - Our defense first constructs a preference dataset with prompt-injected inputs, secure outputs (ones ...

33. [OpenAI Guardrails - Python](https://github.com/openai/openai-guardrails-python) - OpenAI Guardrails wraps the OpenAI Python client to validate inputs and outputs, and integrates with...

34. [openai-guardrails-python/docs/agents_sdk_integration.md at ...](https://github.com/openai/openai-guardrails-python/blob/main/docs/agents_sdk_integration.md) - OpenAI Guardrails - Python. Contribute to openai/openai-guardrails-python development by creating an...

35. [Prompt Injection Detection | OpenAI Guardrails TypeScript](https://openai.github.io/openai-guardrails-js/ref/checks/prompt_injection_detection/) - A TypeScript framework for building safe and reliable AI systems.

36. [guardrails-ai/detect_prompt_injection: A Guardrials Hub validator ...](https://github.com/guardrails-ai/detect_prompt_injection) - A Guardrials Hub validator used to detect if prompt injection is present - guardrails-ai/detect_prom...

37. [Prompt Injection Detector - Validator Details - Guardrails AI](https://guardrailsai.com/hub/validator/guardrails/prompt_injection_detector) - Detailed information about the Prompt Injection Detector validator, including performance benchmarks...

38. [Guardrails AI](https://github.com/guardrails-ai) - Guardrails AI has 97 repositories available. Follow their code on GitHub.

39. [Progent: Programmable Privilege Control for LLM Agents - arXiv](https://arxiv.org/html/2504.11703v1)

40. [[2508.15310] IPIGuard: A Novel Tool Dependency Graph-Based ...](https://ar5iv.labs.arxiv.org/html/2508.15310) - Large language model (LLM) agents are widely deployed in real-world applications, where they leverag...

41. [The Task Shield: Enforcing Task Alignment to Defend Against Indirect Prompt Injection in LLM Agents](https://ar5iv.labs.arxiv.org/html/2412.16682) - Large Language Model (LLM) agents are increasingly being deployed as conversational assistants capab...

42. [Defense Against Indirect Prompt Injection via Tool Result ...](https://arxiv.org/html/2601.04795v1)

43. [realArcherL/spotlighting-datamarking](https://github.com/realArcherL/spotlighting-datamarking) - Defend against indirect prompt injection using Spotlighting (Microsoft Research). Marks untrusted da...

44. [GitHub - ReversecLabs/design-patterns-for-securing-llm-agents-code-samples](https://github.com/ReversecLabs/design-patterns-for-securing-llm-agents-code-samples) - Contribute to ReversecLabs/design-patterns-for-securing-llm-agents-code-samples development by creat...

45. [AgentDojo: A Dynamic Environment to Evaluate Prompt ...](https://arxiv.org/html/2406.13352v3)

46. [.github/profile/README.md at main · promptfoo ...](https://github.com/promptfoo/.github/blob/main/profile/README.md) - Contribute to promptfoo/.github development by creating an account on GitHub.

47. [garak/LICENSE at main · NVIDIA/garak](https://github.com/NVIDIA/garak/blob/main/LICENSE) - the LLM vulnerability scanner. Contribute to NVIDIA/garak development by creating an account on GitH...

48. [PyRIT 2026: Microsoft's AI Red Teaming Framework](https://appsecsanta.com/pyrit) - PyRIT is Microsoft's open-source AI red teaming framework with ~4k GitHub stars and 117 contributors...

49. [uiuc-kang-lab/AdaptiveAttackAgent](https://github.com/uiuc-kang-lab/AdaptiveAttackAgent) - This repository contains the official code for the paper "Adaptive Attacks Break Defenses Against In...

50. [Rethinking Assessments of Prompt Injection Attacks - GitHub](https://github.com/TrustAIRLab/Prompt_Injection_Assessment) - Contribute to TrustAIRLab/Prompt_Injection_Assessment development by creating an account on GitHub.

51. [AgentDojo: A Dynamic Environment to Evaluate Prompt ...](https://ukgovernmentbeis.github.io/inspect_evals/evals/agentdojo/index.html) - The benchmark tests agents' ability to solve realistic tasks while defending against prompt injectio...

52. [github.com · directivecommons · prompt-injectionGitHub - directivecommons/prompt-injection-benchmark](https://github.com/directivecommons/prompt-injection-benchmark) - Contribute to directivecommons/prompt-injection-benchmark development by creating an account on GitH...

53. [cisco-ai-defense/mcp-scanner: Scan MCP servers ...](https://github.com/cisco-ai-defense/mcp-scanner) - Scan MCP servers for potential threats & security findings. - cisco-ai-defense/mcp-scanner

54. [snyk/agent-scan: Security scanner for AI ...](https://github.com/snyk/agent-scan) - It scans for common security vulnerabilities like prompt injections, tool poisoning, toxic flows, or...

55. [agent-security · GitHub Topics](https://github.com/topics/agent-security?l=typescript) - Runtime security for AI apps and agents: prompt injection detection, tool ... Open source. open-sour...

56. [prompt-injection · GitHub Topics](https://github.com/topics/prompt-injection) - Open-source antivirus for AI agents: block risky tools, secret access, prompt injection, malicious p...

57. [protectai/rebuff: LLM Prompt Injection Detector](https://github.com/protectai/rebuff) - Rebuff is designed to protect AI applications from prompt injection (PI) attacks through a multi-lay...

58. [protectai/llm-guard: The Security Toolkit for LLM Interactions](https://github.com/protectai/llm-guard) - By offering sanitization, detection of harmful language, prevention of data leakage, and resistance ...

59. [Design Patterns for Securing LLM Agents against Prompt Injections](https://arxiv.org/html/2506.08837v2)

60. [Design Patterns for Securing LLM Agents against Prompt Injections](https://simonwillison.net/2025/Jun/13/prompt-injection-design-patterns/) - This new paper by 11 authors from organizations including IBM, Invariant Labs, ETH Zurich, Google an...

61. [AlignmentCheck | LlamaFirewall](https://meta-llama.github.io/PurpleLlama/LlamaFirewall/docs/documentation/scanners/alignment-check) - AlignmentCheck is a pioneering, open-source guardrail that utilizes few-shot prompting to audit an a...

62. [Grok Bot security | SpaceXAI Docs](https://docs.x.ai/grok-bot/security) - Prompt injection Content a Bot reads from the outside world, like web pages, plugin results, and com...

63. [Tools Overview | SpaceXAI Docs - Grok API Documentation](https://docs.x.ai/developers/tools/overview) - Learn how to use tools with the xAI API.

64. [Function Calling | SpaceXAI Docs - Grok API Documentation](https://docs.x.ai/developers/tools/function-calling) - Define custom tools that the model can call to interact with external systems.

65. [meta-llama.github.io › PurpleLlama › LlamaFirewallLlamaFirewall Workflow and Detection Components](https://meta-llama.github.io/PurpleLlama/LlamaFirewall/docs/documentation/llamafirewall-architecture/workflow-and-detection-components) - LlamaFirewall is an extensible AI guardrail framework designed to mitigate a wide spectrum of AI age...

