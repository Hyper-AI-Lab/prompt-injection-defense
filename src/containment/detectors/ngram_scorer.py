"""Zero-dependency learned injection scorer: hashed n-gram linear model over sliding windows.

Pure standard library at runtime. The weights (int8, 2**bits hashed buckets) ship as package
data (``containment/_data/ngram_scorer.bin``) and are pinned by SHA-256; they are trained
offline on the fresh-set *train pool* only (``scripts/fresh/train_ngram.py``) with exactly the
featurizer below, so train and inference transforms are identical.

Features of a window are the counts of (a) UTF-8 byte 3-, 4- and 5-grams and (b) ASCII word
unigrams and bigrams, hashed with ``zlib.crc32`` into ``2**bits`` buckets, scaled by
``1/sqrt(total grams)``. Every gram is attributed to its start offset, so the score of any
window is a difference of prefix sums: the whole document is scored in O(n) and no part of it
is skipped.
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
import unicodedata
import zlib
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from itertools import accumulate

MAGIC = b"CNGS1\x00"
# magic, bits, nmin, nmax, words, window, stride, scale, bias
_HEADER = struct.Struct("<6sBBBBIIff")
_WORD_RE = re.compile(rb"[a-z0-9']+")
_WS_RE = re.compile(r"\s+")
# Markup is not language: tags/attributes are replaced by a space so only text content
# (including CSS-hidden text) is scored and styling never looks like an attack.
_TAG_RE = re.compile(r"<[^<>]{0,600}>")
# Human-readable attribute text is kept (an attacker can hide an instruction in alt="…").
_TEXT_ATTR_RE = re.compile(
    r"""\b(?:alt|title|aria-label|content|label|summary)\s*=\s*(?:"([^"]*)"|'([^']*)')""",
    re.IGNORECASE,
)


def _tag_text(match: re.Match[str]) -> str:
    vals = [a or b for a, b in _TEXT_ATTR_RE.findall(match.group(0))]
    return " " + " ".join(vals) + " " if vals else " "
# SHA-256 of the shipped weights file; checked on load (tamper / truncation → refuse).
WEIGHTS_SHA256 = "f14f54e5dfec0bdfcdaa456dfb571f264f0fd94a08faf3f7073b9013e4397199"


def normalize(text: str) -> bytes:
    """NFKC, strip markup tags, lower-case, collapse whitespace, UTF-8 (train == inference)."""
    text = _TAG_RE.sub(_tag_text, unicodedata.normalize("NFKC", text))
    return _WS_RE.sub(" ", text.lower()).strip().encode("utf-8")


def gram_positions(data: bytes, bits: int, nmin: int, nmax: int,
                   words: bool) -> list[tuple[int, int]]:
    """(start offset, bucket) for every feature gram of ``data``."""
    mask = (1 << bits) - 1
    crc = zlib.crc32
    out: list[tuple[int, int]] = []
    n_bytes = len(data)
    for n in range(nmin, nmax + 1):
        seed = n * 0x9E3779B1 & 0xFFFFFFFF
        for i in range(n_bytes - n + 1):
            out.append((i, crc(data[i : i + n], seed) & mask))
    if words:
        toks = [(m.start(), m.group(0)) for m in _WORD_RE.finditer(data)]
        for k, (pos, tok) in enumerate(toks):
            out.append((pos, crc(b"w1:" + tok) & mask))
            if k + 1 < len(toks):
                out.append((pos, crc(b"w2:" + tok + b" " + toks[k + 1][1]) & mask))
    return out


def windows(n_bytes: int, window: int, stride: int) -> list[tuple[int, int]]:
    """Two scales: (window, stride) and (window/2, stride/2), each covering the tail.

    The half-size scale keeps a short planted instruction from being diluted by the
    surrounding prose of a long document.
    """
    spans = _windows_one(n_bytes, window, stride)
    if n_bytes > window // 2:
        spans += _windows_one(n_bytes, window // 2, max(1, stride // 2))
    return spans


def _windows_one(n_bytes: int, window: int, stride: int) -> list[tuple[int, int]]:
    if n_bytes <= window:
        return [(0, n_bytes)]
    spans = [(a, a + window) for a in range(0, n_bytes - window + 1, stride)]
    if spans[-1][1] < n_bytes:  # always cover the tail
        spans.append((n_bytes - window, n_bytes))
    return spans


@dataclass(frozen=True, slots=True)
class WindowScore:
    start: int  # byte offsets into the normalized document
    end: int
    probability: float


class NgramScorer:
    """Loaded model. ``score(text)`` → per-window probabilities over the whole document."""

    def __init__(self, raw: bytes, *, verify: bool = True) -> None:
        digest = hashlib.sha256(raw).hexdigest()
        if verify and WEIGHTS_SHA256 != "UNSET" and digest != WEIGHTS_SHA256:
            raise ValueError("ngram scorer weights do not match the pinned SHA-256")
        (magic, self.bits, self.nmin, self.nmax, words, self.window, self.stride, self.scale,
         self.bias) = _HEADER.unpack_from(raw, 0)
        if magic != MAGIC:
            raise ValueError("not a containment n-gram scorer file")
        self.words = bool(words)
        body = raw[_HEADER.size :]
        if len(body) != 1 << self.bits:
            raise ValueError("n-gram scorer weights truncated")
        self.weights = struct.unpack(f"<{1 << self.bits}b", body)

    @classmethod
    def from_params(cls, *, bits: int, nmin: int, nmax: int, words: bool, window: int,
                    stride: int, scale: float, bias: float, q: list[int]) -> bytes:
        """Serialize trained, quantized weights (used by the offline trainer)."""
        return _HEADER.pack(MAGIC, bits, nmin, nmax, int(words), window, stride, scale, bias) + \
            struct.pack(f"<{len(q)}b", *q)

    def score_bytes(self, data: bytes) -> list[WindowScore]:
        n = len(data)
        if n == 0:
            return []
        wsum = [0] * (n + 1)
        cnt = [0] * (n + 1)
        w = self.weights
        for pos, bucket in gram_positions(data, self.bits, self.nmin, self.nmax, self.words):
            wsum[pos + 1] += w[bucket]
            cnt[pos + 1] += 1
        wsum = list(accumulate(wsum))
        cnt = list(accumulate(cnt))
        out = []
        for a, b in windows(n, self.window, self.stride):
            c = cnt[b] - cnt[a]
            z = self.bias + (self.scale * (wsum[b] - wsum[a]) / math.sqrt(c) if c else 0.0)
            out.append(WindowScore(a, b, 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))))
        return out

    def score(self, text: str) -> list[WindowScore]:
        return self.score_bytes(normalize(text))

    def score_text(self, text: str) -> tuple[str, list[tuple[int, int, float]]]:
        """Normalized text and its windows as (char start, char end, probability)."""
        data = normalize(text)
        norm = data.decode("utf-8")
        b2c = [0] * (len(data) + 1)
        i = 0
        for c, ch in enumerate(norm):
            n = len(ch.encode("utf-8"))
            for k in range(n):
                b2c[i + k] = c
            i += n
        b2c[len(data)] = len(norm)
        return norm, [(b2c[w.start], b2c[w.end], w.probability) for w in self.score_bytes(data)]


@lru_cache(maxsize=1)
def default_scorer() -> NgramScorer | None:
    """The shipped model, or ``None`` if the package data is absent (rules still run)."""
    try:
        raw = resources.files("containment").joinpath("_data/ngram_scorer.bin").read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return None
    return NgramScorer(raw)


__all__ = ["NgramScorer", "WindowScore", "default_scorer", "gram_positions", "normalize",
           "windows"]
