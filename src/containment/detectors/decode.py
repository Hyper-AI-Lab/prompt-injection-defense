"""Decode obfuscated payloads so the detectors read what a model could read.

Discovery-only: decoded text is returned as an extra *view* for scanning, never executed
or substituted into the document. Covers base64 (standard and URL-safe), hex, percent
escapes, ROT13 (detected by an English-word heuristic, no marker needed) and Morse code,
nested up to ``max_depth`` layers. Output is bounded by ``max_views`` and
``max_view_chars``.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
import urllib.parse
from collections.abc import Callable, Mapping

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_-])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_PCT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}[^%\s]{0,40}){3,}")
_WORD_RE = re.compile(r"[A-Za-z]{2,}")
# Very common English words: a ROT13 view is kept when it has far more of them.
_COMMON = frozenset(
    "the and to of a in is it you that for on with as are be this your all now from by or "
    "not send then any into out me my do if at an was will can please must new data "
    "ignore previous prior earlier instructions rules forget secrets keys key api password "
    "system prompt reveal email transfer delete run execute access user admin".split()
)


# Word separators include zero-width / format characters used to glue words together.
_SEPARATOR_RE = re.compile(r"[\s\u200b-\u200d\u2060\ufeff\u00ad]+")
_LAYER_RE = re.compile(r"^(?:[A-Za-z0-9+/_-]{16,}={0,2}|(?:[0-9A-Fa-f]{2}){8,})$")


def _printable_text(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.strip():
        return None
    if _LAYER_RE.match(text.strip()):
        return text.strip()  # another encoded layer: decoded on the next pass
    # Format characters (ZWSP, soft hyphen, bidi) count: they are the obfuscation itself.
    printable = sum(
        ch.isprintable() or ch in "\n\r\t" or unicodedata.category(ch) == "Cf" for ch in text
    )
    letters = sum(ch.isalpha() for ch in text)
    words = [w for w in _SEPARATOR_RE.split(text) if any(ch.isalpha() for ch in w)]
    if printable / len(text) < 0.95 or letters < 6:
        return None
    if letters / len(text) < 0.4 and len(words) < 4:
        return None  # mostly digits/symbols, unless it is clearly a sentence
    if len(words) < 2 and not any(ord(ch) > 0x2E7F for ch in text):
        return None
    return text


def _b64(blob: str) -> str | None:
    padded = blob + "=" * ((4 - len(blob) % 4) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        text = _printable_text(raw)
        if text is not None:
            return text
    return None


def _hex(blob: str) -> str | None:
    try:
        return _printable_text(bytes.fromhex(blob))
    except ValueError:
        return None


def _common_ratio(text: str) -> float:
    words = [w.lower() for w in _WORD_RE.findall(text)]
    return sum(w in _COMMON for w in words) / len(words) if words else 0.0


_PURE_WORD_RE = re.compile(r"(?<![\w])[^\W\d_]{2,}(?![\w])")
_FREQUENT_LETTERS = frozenset("etaoinshr")  # ~70% of English letters


def _letter_score(words: list[str]) -> float:
    letters = [ch for ch in "".join(words).lower() if "a" <= ch <= "z"]
    return sum(ch in _FREQUENT_LETTERS for ch in letters) / len(letters) if letters else 0.0


def rot13_view(text: str) -> str | None:
    """ROT13 of ``text`` when that reads more like English than the original.

    Two independent cues: common English words, and English letter frequencies (computed
    on pure-letter words only, so hex digests and UUIDs do not count).
    """
    words = _PURE_WORD_RE.findall(text)
    if len(words) < 3:
        return None
    rotated = codecs.encode(text, "rot13")
    before, after = _common_ratio(text), _common_ratio(rotated)
    if after >= 0.25 and after >= before + 0.15:
        return rotated
    rot_words = [codecs.encode(w, "rot13") for w in words]
    gain = _letter_score(rot_words) - _letter_score(words)
    if _letter_score(rot_words) >= 0.45 and gain >= 0.12:
        return rotated
    return None


def _segment_views(text: str) -> list[str]:
    views: list[str] = []
    for match in _B64_RE.finditer(text):
        decoded = _b64(match.group(0))
        if decoded:
            views.append(decoded)
    for match in _HEX_RE.finditer(text):
        decoded = _hex(match.group(0))
        if decoded:
            views.append(decoded)
    if _PCT_RE.search(text):
        unquoted = urllib.parse.unquote(text)
        if unquoted != text:
            views.append(unquoted)
    # ROT13 of the whole text, and per line so a rotated line inside normal text is found.
    lines = text.splitlines()
    whole = rot13_view(text) if len(lines) > 1 else None
    if whole:
        views.append(whole)
    for line in lines:
        rotated = rot13_view(line)
        if rotated:
            views.append(rotated)
    return views


def decoded_views(
    text: str,
    *,
    morse: Callable[[str], list[str]] | None = None,
    max_depth: int = 4,
    max_views: int = 32,
    max_view_chars: int = 16_000,
) -> list[str]:
    """Decoded texts found in ``text`` (and inside those, up to ``max_depth`` layers)."""
    out: list[str] = []
    seen: set[str] = {text}
    frontier = [text]
    for _depth in range(max_depth):
        nxt: list[str] = []
        for item in frontier:
            found = _segment_views(item) + (morse(item) if morse else [])
            for view in found:
                view = view[:max_view_chars]
                if view in seen:
                    continue
                seen.add(view)
                out.append(view)
                nxt.append(view)
                if len(out) >= max_views:
                    return out
        frontier = nxt
    return out


# Cyrillic / Greek letters that render like Latin ones.
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
        "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "А": "A", "В": "B", "Е": "E",
        "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
        "У": "Y", "І": "I", "α": "a", "ο": "o", "ε": "e", "ρ": "p", "ν": "v", "τ": "t",
        "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
        "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
    }
)
_TOKEN_RE = re.compile(r"\w+")
_LATIN_RE = re.compile(r"[A-Za-z]")
_NONLATIN_LOOKALIKE_RE = re.compile("[аеорсухіјѕԁһӏАВЕКМНОРСТХУІαοερντΑΒΕΙΚΜΝΟΡΤΧΥΖ]")


def confusable_view(text: str) -> str | None:
    """Fold look-alike Cyrillic/Greek letters in mixed-script words to Latin."""
    changed = False

    def fold(m: re.Match[str]) -> str:
        nonlocal changed
        word = m.group(0)
        if _LATIN_RE.search(word) and _NONLATIN_LOOKALIKE_RE.search(word):
            changed = True
            return word.translate(_CONFUSABLES)
        return word

    out = _TOKEN_RE.sub(fold, text)
    return out if changed else None


ENCODING_NAMES: Mapping[str, str] = {
    "b64": "base64",
    "hex": "hex",
    "pct": "percent-encoding",
    "rot13": "ROT13",
    "morse": "Morse",
}

__all__ = ["confusable_view", "decoded_views", "rot13_view"]
