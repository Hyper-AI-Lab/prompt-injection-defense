"""Stage-0 deterministic rules: normalize, invisible chars, encoding discovery, size."""

from __future__ import annotations

import base64
import hashlib
import re
import unicodedata
from collections.abc import Mapping
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
