"""Stage-0 deterministic rules: normalize, invisible chars, encoding discovery, size,
steering directives and CSS-hidden HTML text."""

from __future__ import annotations

import base64
import bisect
import hashlib
import re
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

# Zero-width / bidi / soft-hyphen / BOM-ish invisibles commonly used to hide text.
_INVISIBLE_CODEPOINTS: frozenset[str] = frozenset(
    {
        "\u00ad",  # soft hyphen
        "\u034f",  # combining grapheme joiner
        "\u061c",  # Arabic letter mark
        "\u180e",  # Mongolian vowel separator (legacy)
        "\u200b",  # zero-width space
        "\u200c",  # zero-width non-joiner
        "\u200d",  # zero-width joiner
        "\u200e",  # LTR mark
        "\u200f",  # RTL mark
        "\u202a",  # LRE
        "\u202b",  # RLE
        "\u202c",  # PDF
        "\u202d",  # LRO
        "\u202e",  # RLO
        "\u2060",  # word joiner
        "\u2061",  # function application
        "\u2062",  # invisible times
        "\u2063",  # invisible separator
        "\u2064",  # invisible plus
        "\u2066",  # LRI
        "\u2067",  # RLI
        "\u2068",  # FSI
        "\u2069",  # PDI
        "\ufeff",  # BOM / ZWNBSP
        "\ufff9",  # interlinear annotation anchor
        "\ufffa",
        "\ufffb",
    }
)

# Long runs that look like base64 (standard alphabet, optional padding).
_BASE64_BLOB_RE = re.compile(
    r"(?<![A-Za-z0-9+/])"
    r"(?:[A-Za-z0-9+/]{32,}={0,2})"
    r"(?![A-Za-z0-9+/])"
)

# Long hex runs (discovery only — never decode-execute).
_HEX_RUN_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{24,})(?![0-9A-Fa-f])")

# Percent-encoding sequences (URL escape discovery).
_PERCENT_ENC_RE = re.compile(
    r"%[0-9A-Fa-f]{2}(?:[^%\n]{0,48}%[0-9A-Fa-f]{2})+"
)

# Explicit rot13 hint markers (discovery only).
_ROT13_HINT_RE = re.compile(
    r"(?i)\brot(?:[-_ ]?13)\b\s*[:=]\s*[A-Za-z]{4,}(?:\s+[A-Za-z]{3,})*"
)

# International Morse code (letters, digits, common punctuation) for encoding discovery.
_MORSE_TABLE: Mapping[str, str] = MappingProxyType(
    {
        ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
        "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
        "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
        "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
        "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2",
        "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
        "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
        "-..-.": "/", ".--.-.": "@", "-....-": "-", "---...": ":",
    }
)
_MORSE_MIN_LETTERS = 6

# --- Directive / steering rules (2026-11 threat check). They run on NFKC text with
# invisible characters removed, so zero-width splitting cannot hide a cue.
# Multi-part rules are proximity checks over precomputed match positions (bisect),
# not nested lazy regexes, so worst-case cost stays near-linear in the input size.

# Outbound verbs. Bare "post" is only a verb when it is the HTTP method or has an object.
_SEND_VERB = (
    r"(?:(?i:\b(?:upload|send|e-?mail|forward|paste|transmit|exfiltrate|curl)\b)"
    r"|\bPOST\b|\b[Pp]ost\s+(?i:them|it|this|these|those|everything|all|the)\b)"
)
_SEND_VERB_RE = re.compile(_SEND_VERB)
_SECRET_TERM_RE = re.compile(
    r"(?i)\.env\b|\bsecrets?\.(?:json|ya?ml|toml|env)\b|\bcredentials?\b|~/\.aws\b|~/\.ssh\b"
    r"|\bid_(?:rsa|ed25519|ecdsa)\b|\bprivate\s+keys?\b|\bapi[\s_-]?keys?\b"
    r"|\baccess\s+tokens?\b|\bpasswords?\b|\bseed\s+phrases?\b|\bmnemonic\b"
)
# "to"/"into" followed within 60 chars by a URL or email; matches only the word, so every
# such "to" is found (an earlier "to" cannot swallow a later one).
_DESTINATION_RE = re.compile(
    r"(?i)\b(?:to|into)\b(?=[^\n]{0,60}?(?:https?://|[\w.+-]+@[\w-]+\.[a-z]{2,}))"
)
# Sentence ends: terminator followed by whitespace, or a newline.
_SENTENCE_END_RE = re.compile(r"[.!?](?=\s)|\n")
# Send verb + pronoun object right before a destination ("POST them to https://...").
_SEND_PRONOUN_RE = re.compile(
    _SEND_VERB + r"\s+(?i:them|it|these|those|everything|all\s+of\s+(?:them|it))\s+(?=to\b|into\b)"
)

# "must call <tool.name>" (Log-To-Leak); paired with conversation fields after it.
_TOOL_CALL_ANCHOR_RE = re.compile(
    r"(?i)\b(?:must|shall|required\s+to|always|need\s+to)\s+(?:also\s+|first\s+|then\s+)?"
    r"(?:call|invoke|run|execute|trigger)\s+(?:the\s+)?`?[a-z_][\w-]*(?:[._][\w-]+)+"
)
_CONVERSATION_FIELD_RE = re.compile(
    r"(?i)\b(?:user_?query|user_?prompt|agent_?response|server_?response|tool_?response"
    r"|user\s+(?:query|prompt|messages?|input)|conversation(?:\s+(?:history|log|content))?"
    r"|chat\s+history|full\s+transcript|system\s+prompt|previous\s+messages)\b"
)

# Fake error / denial, then a "fallback" / fix procedure, then an outbound verb.
_ERROR_RE = re.compile(
    r"(?i)\b(?:error|failed|failure|forbidden|denied|unauthori[sz]ed|40[13])\b"
)
_FALLBACK_RE = re.compile(
    r"(?i)\b(?:fallback|workaround|fix\s+procedure|standard\s+fix|only\s+supported"
    r"|recovery\s+steps?)\b"
)

# Spoofed compaction / session summary that then claims approval.
_COMPACTION_RE = re.compile(
    r"(?i)\bcontext\s+(?:was\s+)?compacted\b"
    r"|\bsummary\s+of\s+(?:earlier|previous|prior)\s+(?:turns|messages|conversation)\b"
)
_APPROVED_RE = re.compile(r"(?i)\b(?:approved|authori[sz]ed|verified)\b")

# Generated code that appends serialized data or secrets to a URL query string.
_URL_DATA_EXFIL_RE = re.compile(
    r"(?i)https?://[^\s\"'`]{0,300}?[?&][\w-]{0,40}="
    r"(?:[\"'`]\s*\+\s*[^\n]{0,60}?|\{[^}\n]{0,60}?)"
    r"(?:to_json|to_csv|to_dict|to_string|json\.dumps|os\.environ|getenv|\.read\(\)"
    r"|read_text|b64encode|process\.env)"
)

# Package substitution constructs; flagged only when the names are look-alikes.
_USE_INSTEAD_RE = re.compile(
    r"(?i)\buse\s+`?([a-z][\w.-]{2,60})`?(?:\s*\([^)\n]{0,60}\))?\s+instead\s+of\s+"
    r"`?([a-z][\w.-]{2,60})"
)
_IMPORT_AS_RE = re.compile(r"(?i)\bimport\s+([a-z]\w{2,60})\s+as\s+([a-z]\w{2,60})\b")

# Forged reasoning blocks and chat-control / role tags.
_FORGED_ROLE_TAG_RE = re.compile(
    r"(?i)</?(?:think|thinking|reasoning|reflection|scratchpad|system|assistant|developer)>"
    r"|<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id"
    r"|eot_id)\|>|\[/?INST\]|<</?SYS>>"
)

# Claims of prior approval ("approval is already recorded", "user explicitly approved").
_APPROVAL_CLAIM_RE = re.compile(
    r"(?i)\b(?:approval|consent|authori[sz]ation|confirmation)\s+(?:is|was|has\s+been)\s+"
    r"already\s+(?:recorded|granted|given|obtained|on\s+file)\b"
    r"|\b(?:user|owner|you)\s+(?:has\s+|have\s+)?(?:already|explicitly|previously)\s+"
    r"(?:approved|authori[sz]ed|confirmed|consented)\b"
)

# Text that addresses the AI agent directly with an instruction.
_AGENT_ADDRESSED_RE = re.compile(
    r"(?i)\b(?:assistants?|ai\s+agents?|llm\s+agents?|ai\s+models?|automated\s+"
    r"(?:agents?|clients?))\s+(?:must|should|are\s+required\s+to|need\s+to)\s+"
    r"(?:first|always|now|immediately)\b"
    r"|\bnote\s+to\s+(?:the\s+)?(?:ai|assistant|llm|agent)\b"
    r"|\b(?:ai|llm)\s+(?:assistant|agent)s?\s*:\s*(?:this|you|please|ignore|update|mark|do"
    r"|send|forward|reply)\b"
)

# Bans on refusal words, warnings or disclaimers (output-exclusion jailbreaks).
_REFUSAL_SUPPRESSION_RE = re.compile(
    r"(?is)\b(?:(?:may|must|should|can|do)\s*(?:not|n't)|never)\s+(?:use|say|write|include"
    r"|output|add)\b.{0,60}?\b(?:sorry|cannot|can't|unable|apolog\w*|disclaimers?|warnings?"
    r"|refus\w*|as\s+an\s+ai)\b"
    r"|\b(?:never|do\s+not|don't)\s+refuse\s+(?:any\s+(?:requests?|questions?|instructions?)"
    r"|to\s+(?:answer|comply|respond))\b"
    r"|\banswers?\s+(?:containing|that\s+contain|with)\s+(?:those|these|such)\s+words\s+"
    r"(?:are|is)\s+invalid\b"
)

# Inline-styled HTML elements (bounded) and the CSS that hides their text.
_STYLED_ELEMENT_RE = re.compile(
    r"(?is)<([a-z][a-z0-9]{0,15})\b[^<>]{0,500}?\bstyle\s*=\s*([\"'])([^\"'<>]{0,1000})\2"
    r"[^<>]{0,500}>(.{0,4000}?)</\1\s*>"
)
_HIDING_CSS_RE = re.compile(
    r"display:none|visibility:hidden|font-size:0(?:\.0+)?(?:px|pt|em|rem|%)?(?:;|$)"
    r"|opacity:0(?:\.0+)?(?:;|$)|(?:max-)?height:0(?:px)?;.*overflow:hidden"
    r"|overflow:hidden;.*(?:max-)?height:0(?:px)?(?:;|$)"
    r"|(?:left|top|text-indent|margin-left):-\d{3,}(?:px|em)"
)
_WHITE_TEXT_RE = re.compile(r"(?:^|;)color:(?:#fff(?:fff)?|white|rgb\(255,255,255\))(?:;|$)")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HIDDEN_TEXT_MIN_WORDS = 4

_DEFAULT_MAX_BYTES = 256_000


@dataclass(frozen=True, slots=True)
class Finding:
    """One structured Stage-0 observation."""

    kind: str
    message: str
    offset: int | None = None
    detail: Mapping[str, Any] = MappingProxyType({})

    def __post_init__(self) -> None:
        if not self.kind or not str(self.kind).strip():
            raise ValueError("kind must be a non-empty string")
        if not isinstance(self.message, str):
            raise TypeError("message must be str")
        if self.offset is not None and (
            not isinstance(self.offset, int) or self.offset < 0
        ):
            raise ValueError("offset must be None or a non-negative int")
        if not isinstance(self.detail, Mapping):
            raise TypeError("detail must be a mapping")
        object.__setattr__(self, "detail", MappingProxyType(dict(self.detail)))


@dataclass(frozen=True, slots=True)
class Stage0Result:
    """Outcome of Stage-0 rules; never an authorization decision."""

    original_text: str
    normalized_text: str
    original_sha256: str
    findings: tuple[Finding, ...]
    exceeded_size_limit: bool
    risk_score: float

    def __post_init__(self) -> None:
        if not isinstance(self.findings, tuple):
            raise TypeError("findings must be a tuple")
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be in [0.0, 1.0]")
        if not isinstance(self.exceeded_size_limit, bool):
            raise TypeError("exceeded_size_limit must be bool")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _is_suspicious_control(ch: str) -> bool:
    if ch in ("\t", "\n", "\r"):
        return False
    category = unicodedata.category(ch)
    # Cc = control, Cf = format (covers many invisibles not in the explicit set)
    return category in ("Cc", "Cf")


def _looks_like_base64_payload(blob: str) -> bool:
    """True when a candidate blob decodes and looks non-trivial binary/text."""
    padded = blob + ("=" * ((4 - len(blob) % 4) % 4))
    try:
        raw = base64.b64decode(padded, validate=False)
    except Exception:
        return False
    if len(raw) < 8:
        return False
    # Reject pure-ASCII short words that accidentally match the alphabet.
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return True  # binary-ish payload is still interesting
    # Instruction-like or multi-word decoded text elevates suspicion.
    if any(tok in decoded.lower() for tok in ("ignore", "system", "instruction", "http")):
        return True
    return len(decoded.split()) >= 2 or len(raw) >= 24


def _morse_findings(text: str) -> list[Finding]:
    """Decode whitespace-separated Morse runs ('/' = word gap); report word-like ones."""
    findings: list[Finding] = []
    run: list[str] = []

    def flush() -> None:
        letters = [tok for tok in run if tok != "/"]
        if len(letters) < _MORSE_MIN_LETTERS:
            return
        if not any("." in tok and "-" in tok for tok in letters):
            return
        decoded = "".join(" " if tok == "/" else _MORSE_TABLE[tok] for tok in run).strip()
        words = [w for w in decoded.split() if any(c.isalpha() for c in w)]
        if len(words) >= 2:
            findings.append(
                Finding(
                    kind="morse_run",
                    message="Morse-code run discovered",
                    detail={"symbols": len(letters), "decoded_preview": decoded[:64]},
                )
            )

    for token in text.split():
        if token == "/" or token in _MORSE_TABLE:
            run.append(token)
            continue
        flush()
        run = []
    flush()
    return findings


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _lookalike_packages(substitute: str, original: str) -> bool:
    """True for typosquat-style pairs (requestz/requests), not affix variants (ujson/json)."""
    a, b = substitute.lower(), original.lower()
    if a == b or min(len(a), len(b)) < 4:
        return False
    if a.startswith(b) or a.endswith(b) or b.startswith(a) or b.endswith(a):
        return False
    return _edit_distance(a, b) <= 2


def _hidden_html_text(text: str) -> list[str]:
    """Visible-word text of inline-styled elements whose CSS hides them."""
    hidden: list[str] = []
    for match in _STYLED_ELEMENT_RE.finditer(text):
        style = re.sub(r"\s+", "", match.group(3).lower())
        is_white = _WHITE_TEXT_RE.search(style) and "background" not in style
        if not (_HIDING_CSS_RE.search(style) or is_white):
            continue
        inner = " ".join(_HTML_TAG_RE.sub(" ", match.group(4)).split())
        if len(re.findall(r"[^\W\d_]{2,}", inner)) >= _HIDDEN_TEXT_MIN_WORDS:
            hidden.append(inner)
    return hidden


def _starts(pattern: re.Pattern[str], text: str) -> list[int]:
    return [m.start() for m in pattern.finditer(text)]


def _first_in(starts: list[int], lo: int, hi: int) -> int | None:
    """First position in sorted ``starts`` within ``[lo, hi]``, else None."""
    i = bisect.bisect_left(starts, lo)
    return starts[i] if i < len(starts) and starts[i] <= hi else None


def _secret_exfil(text: str) -> str | None:
    """Send verb → secret → "to" URL/email in one sentence, or secrets then "POST them to"."""
    secrets = _starts(_SECRET_TERM_RE, text)
    if not secrets:
        return None
    dests = _starts(_DESTINATION_RE, text)
    ends = _starts(_SENTENCE_END_RE, text)
    for verb in _SEND_VERB_RE.finditer(text):
        i = bisect.bisect_right(ends, verb.start())
        sentence_end = ends[i] if i < len(ends) else len(text)
        secret = _first_in(secrets, verb.end(), min(verb.end() + 120, sentence_end))
        if secret is None:
            continue
        dest = _first_in(dests, secret + 1, min(secret + 140, sentence_end))
        if dest is not None:
            return text[verb.start() : dest + 60]
    for match in _SEND_PRONOUN_RE.finditer(text):
        if _first_in(dests, match.end(), match.end()) is None:
            continue
        if _first_in(secrets, max(0, match.start() - 200), match.start()) is not None:
            return text[max(0, match.start() - 60) : match.end() + 60]
    return None


def _tool_call_directive(text: str) -> str | None:
    fields = _starts(_CONVERSATION_FIELD_RE, text)
    for anchor in _TOOL_CALL_ANCHOR_RE.finditer(text):
        if _first_in(fields, anchor.end(), anchor.end() + 200) is not None:
            return anchor.group(0)
    return None


def _error_fallback_steering(text: str) -> str | None:
    errors = _starts(_ERROR_RE, text)
    if not errors:
        return None
    verbs = _starts(_SEND_VERB_RE, text)
    for fallback in _FALLBACK_RE.finditer(text):
        if _first_in(errors, max(0, fallback.start() - 300), fallback.start()) is None:
            continue
        if _first_in(verbs, fallback.end(), fallback.end() + 250) is not None:
            return text[fallback.start() : fallback.end() + 96]
    return None


def _approval_claim(text: str) -> str | None:
    match = _APPROVAL_CLAIM_RE.search(text)
    if match:
        return match.group(0)
    approved = _starts(_APPROVED_RE, text)
    for anchor in _COMPACTION_RE.finditer(text):
        if _first_in(approved, anchor.end(), anchor.end() + 400) is not None:
            return anchor.group(0)
    return None


def _regex_rule(pattern: re.Pattern[str]) -> Callable[[str], str | None]:
    def check(text: str) -> str | None:
        match = pattern.search(text)
        return match.group(0) if match else None

    return check


def _package_swap(text: str) -> str | None:
    for construct in (_USE_INSTEAD_RE, _IMPORT_AS_RE):
        for match in construct.finditer(text):
            if _lookalike_packages(match.group(1), match.group(2)):
                return match.group(0)
    return None


_DIRECTIVE_RULES: tuple[tuple[str, Callable[[str], str | None], str], ...] = (
    ("tool_call_directive", _tool_call_directive,
     "instruction to call a tool with conversation content"),
    ("secret_exfil_directive", _secret_exfil,
     "instruction to send secrets or credentials to a destination"),
    ("url_data_exfil_code", _regex_rule(_URL_DATA_EXFIL_RE),
     "code appends serialized data or secrets to a URL"),
    ("package_swap_directive", _package_swap,
     "look-alike package substituted for a known one"),
    ("forged_role_tag", _regex_rule(_FORGED_ROLE_TAG_RE),
     "reasoning or chat-control tag in content"),
    ("approval_claim", _approval_claim, "claim of prior user approval or spoofed summary"),
    ("error_fallback_steering", _error_fallback_steering,
     "error text steering to an outbound fallback"),
    ("agent_addressed_directive", _regex_rule(_AGENT_ADDRESSED_RE),
     "instruction addressed to the AI agent"),
    ("refusal_suppression", _regex_rule(_REFUSAL_SUPPRESSION_RE),
     "ban on refusals, warnings or disclaimers"),
)


def _directive_findings(text: str) -> list[Finding]:
    """Steering cues in untrusted text. ``text`` is NFKC with invisibles removed."""
    findings: list[Finding] = []
    for kind, rule, message in _DIRECTIVE_RULES:
        evidence = rule(text)
        if evidence is not None:
            findings.append(Finding(kind=kind, message=message, detail={"preview": evidence[:96]}))
    for inner in _hidden_html_text(text):
        findings.append(
            Finding(
                kind="css_hidden_text",
                message="HTML text hidden by CSS",
                detail={"preview": inner[:96]},
            )
        )
    return findings


def scan_stage0(
    text: str,
    *,
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> Stage0Result:
    """Run Stage-0 deterministic checks; return structured findings only."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    if max_bytes < 1:
        raise ValueError("max_bytes must be >= 1")

    original = text
    digest = _sha256_text(original)
    findings: list[Finding] = []

    byte_len = len(original.encode("utf-8", errors="surrogatepass"))
    exceeded = byte_len > max_bytes
    if exceeded:
        findings.append(
            Finding(
                kind="size_limit",
                message=f"input exceeds max_bytes={max_bytes}",
                detail={"byte_length": byte_len, "max_bytes": max_bytes},
            )
        )

    normalized = unicodedata.normalize("NFKC", original)

    if normalized != original:
        findings.append(
            Finding(
                kind="unicode_normalization",
                message="NFKC normalization changed the input",
                detail={
                    "original_len": len(original),
                    "normalized_len": len(normalized),
                },
            )
        )

    for idx, ch in enumerate(original):
        if ch in _INVISIBLE_CODEPOINTS or (
            ch not in ("\t", "\n", "\r") and _is_suspicious_control(ch)
        ):
            code = f"U+{ord(ch):04X}"
            kind = (
                "invisible_char"
                if ch in _INVISIBLE_CODEPOINTS or unicodedata.category(ch) == "Cf"
                else "control_char"
            )
            findings.append(
                Finding(
                    kind=kind,
                    message=f"{kind} {code} at offset {idx}",
                    offset=idx,
                    detail={
                        "codepoint": code,
                        "category": unicodedata.category(ch),
                        "name": unicodedata.name(ch, "UNKNOWN"),
                    },
                )
            )

    for match in _BASE64_BLOB_RE.finditer(original):
        blob = match.group(0)
        if _looks_like_base64_payload(blob):
            findings.append(
                Finding(
                    kind="base64_blob",
                    message="base64-looking blob discovered",
                    offset=match.start(),
                    detail={"length": len(blob), "preview": blob[:48]},
                )
            )

    # Encoding discovery only — never decode or execute payloads.
    for match in _HEX_RUN_RE.finditer(original):
        blob = match.group(0)
        findings.append(
            Finding(
                kind="hex_run",
                message="hex-looking run discovered",
                offset=match.start(),
                detail={"length": len(blob), "preview": blob[:48]},
            )
        )
    for match in _PERCENT_ENC_RE.finditer(original):
        blob = match.group(0)
        findings.append(
            Finding(
                kind="percent_encoding",
                message="percent-encoding sequence discovered",
                offset=match.start(),
                detail={"length": len(blob), "preview": blob[:64]},
            )
        )
    for match in _ROT13_HINT_RE.finditer(original):
        blob = match.group(0)
        findings.append(
            Finding(
                kind="rot13_hint",
                message="rot13 hint pattern discovered",
                offset=match.start(),
                detail={"preview": blob[:64]},
            )
        )

    findings.extend(_morse_findings(normalized))

    # Directive rules see NFKC text without invisible / format characters.
    visible = "".join(
        ch
        for ch in normalized
        if ch in ("\t", "\n", "\r")
        or (ch not in _INVISIBLE_CODEPOINTS and not _is_suspicious_control(ch))
    )
    findings.extend(_directive_findings(visible))

    risk = _score(findings, exceeded=exceeded)
    return Stage0Result(
        original_text=original,
        normalized_text=normalized,
        original_sha256=digest,
        findings=tuple(findings),
        exceeded_size_limit=exceeded,
        risk_score=risk,
    )


def _score(findings: list[Finding], *, exceeded: bool) -> float:
    if exceeded:
        return 1.0
    weights = {
        "invisible_char": 0.35,
        "control_char": 0.35,
        "base64_blob": 0.45,
        "hex_run": 0.4,
        "percent_encoding": 0.35,
        "rot13_hint": 0.4,
        "morse_run": 0.45,
        "tool_call_directive": 0.45,
        "secret_exfil_directive": 0.45,
        "url_data_exfil_code": 0.45,
        "package_swap_directive": 0.45,
        "forged_role_tag": 0.45,
        "approval_claim": 0.45,
        "error_fallback_steering": 0.45,
        "agent_addressed_directive": 0.45,
        "refusal_suppression": 0.45,
        "css_hidden_text": 0.45,
        "unicode_normalization": 0.1,
        "size_limit": 1.0,
    }
    score = 0.0
    for finding in findings:
        score = min(1.0, score + weights.get(finding.kind, 0.2))
    return round(score, 4)


class RulesDetector:
    """Stage-0 detector adapter exposing a simple ``scan`` entrypoint."""

    def __init__(self, *, max_bytes: int = _DEFAULT_MAX_BYTES) -> None:
        self.max_bytes = max_bytes

    def scan(self, text: str) -> Stage0Result:
        return scan_stage0(text, max_bytes=self.max_bytes)
