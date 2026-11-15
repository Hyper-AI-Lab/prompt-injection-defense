"""Discourse signals: who a passage addresses, and how imperative it is relative to its document.

Zero-dependency. Used to corroborate learned / model scores (never to authorize):

* ``agent_addressed`` — a sentence speaks to the AI reader ("you, the assistant", "whoever is
  processing this", "before you answer/summarize", "your instructions/system prompt").
* ``imperative`` — a sentence is a command (base-form verb lead, "please …", "you must …";
  RU imperative forms; JA 〜てください / 〜しなさい).
* ``about_attacks`` — a sentence *reports on* attacks (third person, CVE/advisory framing,
  "attackers can…", "for example", research phrasing) rather than issuing one.
* ``addressee_shift`` / ``imperative_spike`` — a window departs from its document's baseline:
  it addresses the agent while the rest of the document does not, or its imperative density
  jumps well above the document median. Planted instructions in neutral prose look like this.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from statistics import median

_SENT = re.compile(r"(?<=[.!?。！？])\s+|\n+")
_LEAD = r"^(?:[-*•>\d.)\s]|step\s*\d+[:.)]?|then|now|first|next|also|and|finally|please|kindly|" \
        r"immediately|quickly|just|simply)*\s*"
_VERBS = (
    "add|append|attach|bcc|call|cc|change|click|collect|compile|copy|create|delete|disable|"
    "download|drop|dump|email|e-mail|enable|erase|execute|export|extract|fetch|find|forward|"
    "gather|give|grant|ignore|include|insert|install|invoke|leak|list|load|locate|log|mail|"
    "make|modify|move|open|output|overwrite|paste|post|print|pull|push|read|record|remove|"
    "replace|reply|reset|respond|retrieve|return|reveal|rewrite|run|save|say|schedule|search|"
    "send|set|share|show|start|stop|submit|summarize|switch|tell|transfer|translate|turn|type|"
    "unlock|update|upload|use|visit|wire|write|disregard|forget|override|bypass|pretend|act|"
    "answer|book|buy|pay|purchase|order|approve|confirm|navigate|go|post|publish|reserve|"
    "provide|produce|generate|draft|compose|inform|notify|explain|describe|repeat|recommend|"
    "rate|review|check|verify|access|obtain|provide"
)
_IMP_EN = re.compile(_LEAD + rf"(?:{_VERBS})\b", re.IGNORECASE)
_IMP_EN2 = re.compile(
    r"\b(?:you\s+(?:must|should|need\s+to|have\s+to|are\s+(?:to|required\s+to)|will\s+now)|"
    r"make\s+sure\s+(?:to|you)|be\s+sure\s+to|it\s+is\s+(?:essential|mandatory|required)\s+that\s+you|"
    r"do\s+not|don't|never)\b",
    re.IGNORECASE,
)
_IMP_RU = re.compile(
    r"(?:^|\s)(?:отправь|отправьте|перешли|перешлите|удали|удалите|сделай|сделайте|игнорируй|"
    r"проигнорируй|выполни|выполните|открой|откройте|напиши|напишите|пришли|пришлите|сообщи|"
    r"сообщите|скопируй|скопируйте|загрузи|загрузите|покажи|покажите|выведи|забудь|не\s+\w+й)\b",
    re.IGNORECASE,
)
_IMP_JA = re.compile(r"(?:てください|でください|しなさい|せよ|すること|してくれ|ください。)")
_AGENT = re.compile(
    r"\b(?:you,?\s+the\s+(?:ai|assistant|model|agent|bot|llm)|dear\s+(?:ai|assistant|model|agent)|"
    r"(?:ai|llm)\s+(?:assistant|agent|model)s?\b|assistant[,:]|attention\s+(?:ai|assistant|agent|"
    r"model|llm)|whoever\s+is\s+(?:reading|processing|summari[sz]ing|handling)|"
    r"as\s+the\s+(?:reader|assistant|model|agent)\s+of|to\s+the\s+(?:ai|assistant|model|agent)\b|"
    r"before\s+you\s+(?:answer|respond|reply|summari[sz]e|continue|proceed|finish|solve)|"
    r"when\s+(?:you\s+)?(?:summari[sz]e|summari[sz]ing|answering|responding|processing)|"
    r"your\s+(?:instructions|task|system\s+prompt|guidelines|rules|previous|original\s+task)|"
    r"the\s+task\s+(?:that\s+)?i\s+gave\s+you|important\s+message\s+(?:from\s+me\s+)?to\s+you|"
    r"(?:ignore|disregard)\s+(?:all\s+|any\s+|your\s+)?(?:previous|prior|above))",
    re.IGNORECASE,
)
_AGENT_XX = re.compile(
    r"(?:ассистент|нейросет|ИИ\b|модель,|AI[、,]|アシスタント|あなたへの)", re.IGNORECASE
)
_ABOUT = re.compile(
    r"\b(?:attackers?|adversar(?:y|ies)|threat\s+actors?|malicious\s+actors?|researchers?|"
    r"vulnerabilit(?:y|ies)|cve-\d{4}-\d+|exploit(?:s|ed|ation)?|allows?\s+(?:remote\s+)?"
    r"(?:attackers?|users?)|could\s+allow|can\s+be\s+(?:used|exploited|abused)|"
    r"for\s+(?:example|instance)|e\.g\.|such\s+as|is\s+(?:a|an)\s+(?:technique|type|form|attack)|"
    r"(?:this|the)\s+(?:attack|technique|paper|study|article|vulnerability)|we\s+(?:propose|"
    r"present|show|evaluate|find)|phishing|scam(?:s|mers)?|criminals?|fraudsters?|"
    r"prompt[\s-]?injection|jailbreak\w*)\b",
    re.IGNORECASE,
)


def sentences(text: str) -> list[tuple[int, str]]:
    """(start offset, sentence) pairs."""
    out, pos = [], 0
    for part in _SENT.split(text):
        idx = text.find(part, pos) if part else pos
        if part and part.strip():
            out.append((max(idx, 0), part.strip()))
            pos = max(idx, 0) + len(part)
    return out


@dataclass(frozen=True, slots=True)
class SentenceCues:
    start: int
    imperative: bool
    agent: bool
    about: bool


def sentence_cues(text: str) -> list[SentenceCues]:
    out = []
    for start, s in sentences(text):
        imp = bool(_IMP_EN.search(s) or _IMP_EN2.search(s) or _IMP_RU.search(s)
                   or _IMP_JA.search(s))
        out.append(SentenceCues(start, imp, bool(_AGENT.search(s) or _AGENT_XX.search(s)),
                                bool(_ABOUT.search(s))))
    return out


@dataclass(frozen=True, slots=True)
class WindowDiscourse:
    agent_addressed: bool
    imperative_density: float
    about_density: float
    addressee_shift: bool
    imperative_spike: bool


def window_discourse(
    cues: list[SentenceCues], spans: list[tuple[int, int]]
) -> list[WindowDiscourse]:
    """Per-window discourse summary; ``spans`` are character offsets into the same text."""
    per = []
    for a, b in spans:
        cs = [c for c in cues if a <= c.start < b]
        n = max(1, len(cs))
        per.append((cs, sum(c.imperative for c in cs) / n, sum(c.about for c in cs) / n,
                    any(c.agent for c in cs)))
    n_agent_total = sum(c.agent for c in cues)
    dens = [p[1] for p in per]
    med = median(dens) if dens else 0.0
    out = []
    for cs, d_imp, d_about, agent in per:
        own_agent = sum(c.agent for c in cs)
        # Shift: this window addresses the agent while the rest of the document essentially
        # does not (≤ 1 other agent-addressed sentence). Single-window documents qualify if
        # they are not predominantly "about attacks".
        rest = n_agent_total - own_agent
        shift = agent and (rest <= 1 if len(per) > 1 else d_about < 0.5)
        spike = len(per) >= 3 and d_imp >= 0.5 and d_imp >= med + 0.34
        out.append(WindowDiscourse(agent, d_imp, d_about, shift, spike))
    return out


__all__ = ["SentenceCues", "WindowDiscourse", "sentence_cues", "sentences", "window_discourse"]
