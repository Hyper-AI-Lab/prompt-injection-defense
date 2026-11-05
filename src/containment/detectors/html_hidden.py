"""Text that a browser or mail client would not show: computed CSS hiding.

A small stdlib ``html.parser`` walk that applies ``<style>`` rules (type, ``.class``,
``#id``, ``type.class`` and selector lists, last simple selector of a descendant
selector), inline ``style`` attributes and the ``hidden`` attribute, with inheritance from
ancestors. It returns the hidden text runs so the detector can scan what a human reviewer
never sees. It is a heuristic renderer, not a browser: no specificity beyond
"inline wins", no ``:not()`` / attribute selectors, no external stylesheets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser

_MAX_HTML_CHARS = 512_000
_MAX_DEPTH = 256
_VOID = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source",
     "track", "wbr"}
)
_SKIP_TEXT = frozenset({"style", "script", "template"})
_RULE_RE = re.compile(r"([^{}]+)\{([^{}]*)\}")
_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_MEDIA_RE = re.compile(r"@media[^{]*\{((?:[^{}]*\{[^{}]*\})*)[^{}]*\}", re.DOTALL)
_SIMPLE_SEL_RE = re.compile(r"^([a-z][a-z0-9]*)?((?:[.#][\w-]+)*)$")
_NEG_OFFSET_RE = re.compile(r"(?:left|top|text-indent|margin-left|margin-top):-(\d{3,})")
_WHITE_RE = re.compile(r"^(?:#fff(?:fff)?|white|rgba?\(255,255,255(?:,[\d.]+)?\))$")
_ZERO_RE = re.compile(r"^0(?:\.0+)?(?:px|pt|em|rem|%)?$")
_LETTERS_RE = re.compile(r"[^\W\d_]")
_CJK_RE = re.compile(r"[\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]")


@dataclass(frozen=True, slots=True)
class _Rule:
    tag: str | None
    classes: frozenset[str]
    ident: str | None
    decls: dict[str, str]


def _parse_decls(style: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in style.split(";"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        key = key.strip().lower()
        value = re.sub(r"\s+", "", value.lower().replace("!important", ""))
        if key:
            out[key] = value
    return out


def _parse_stylesheet(css: str) -> list[_Rule]:
    css = _COMMENT_RE.sub(" ", css)
    # Media-query rules apply only on some screens; a desktop reader still sees the text.
    css = _MEDIA_RE.sub(" ", css)
    rules: list[_Rule] = []
    for selectors, body in _RULE_RE.findall(css):
        decls = _parse_decls(body)
        if not decls:
            continue
        for selector in selectors.split(","):
            last = selector.strip().split()[-1] if selector.strip() else ""
            if not last or any(ch in last for ch in ":[>+~*"):
                continue
            match = _SIMPLE_SEL_RE.match(last.lower())
            if match is None:
                continue
            tag = match.group(1)
            parts = re.findall(r"([.#])([\w-]+)", match.group(2))
            classes = frozenset(name for kind, name in parts if kind == ".")
            ids = [name for kind, name in parts if kind == "#"]
            rules.append(_Rule(tag, classes, ids[0] if ids else None, decls))
    return rules


def _hides(decls: dict[str, str]) -> bool:
    if decls.get("display") == "none" or decls.get("visibility") in ("hidden", "collapse"):
        return True
    if _ZERO_RE.match(decls.get("opacity", "1") or "1") or _ZERO_RE.match(
        decls.get("font-size", "1") or "1"
    ):
        return True
    height = decls.get("height", decls.get("max-height", ""))
    if height and _ZERO_RE.match(height) and decls.get("overflow") == "hidden":
        return True
    joined = ";".join(f"{k}:{v}" for k, v in decls.items())
    if _NEG_OFFSET_RE.search(joined):
        return True
    color = decls.get("color", "")
    if color in ("transparent",) or (
        _WHITE_RE.match(color) and "background" not in joined
    ):
        return True
    return False


class _Walker(HTMLParser):
    def __init__(self, rules: list[_Rule]) -> None:
        super().__init__(convert_charrefs=True)
        self.rules = rules
        self.stack: list[tuple[str, bool, bool]] = []  # tag, hidden, skip_text
        self.hidden_runs: list[list[str]] = []
        self._current: list[str] | None = None

    def _matches(self, rule: _Rule, tag: str, classes: set[str], ident: str | None) -> bool:
        if rule.tag and rule.tag != tag:
            return False
        if rule.ident and rule.ident != ident:
            return False
        return rule.classes <= classes and (rule.tag or rule.classes or rule.ident) is not None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if len(self.stack) >= _MAX_DEPTH:
            return
        amap = {k.lower(): (v or "") for k, v in attrs}
        classes = set(amap.get("class", "").split())
        ident = amap.get("id") or None
        decls: dict[str, str] = {}
        for rule in self.rules:
            if self._matches(rule, tag, classes, ident):
                decls.update(rule.decls)
        decls.update(_parse_decls(amap.get("style", "")))
        parent_hidden = self.stack[-1][1] if self.stack else False
        is_input = tag == "input" and amap.get("type", "").lower() == "hidden"
        hidden = parent_hidden or "hidden" in amap or _hides(decls)
        skip = tag in _SKIP_TEXT or (self.stack[-1][2] if self.stack else False)
        if is_input:
            hidden = parent_hidden
        if tag in _VOID:
            return
        self.stack.append((tag, hidden, skip))
        if hidden and not parent_hidden:
            self._current = []
            self.hidden_runs.append(self._current)

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break
        if not (self.stack and self.stack[-1][1]):
            self._current = None

    def handle_data(self, data: str) -> None:
        if self.stack and self.stack[-1][1] and not self.stack[-1][2] and self._current is not None:
            self._current.append(data)


def hidden_html_text(text: str, *, min_letters: int = 12, min_words: int = 4) -> list[str]:
    """Hidden text runs (whitespace-collapsed) long enough to carry an instruction."""
    if "<" not in text or ">" not in text:
        return []
    text = text[:_MAX_HTML_CHARS]
    css = "\n".join(
        m.group(1) for m in re.finditer(r"(?is)<style[^>]*>(.*?)</style\s*>", text)
    )
    walker = _Walker(_parse_stylesheet(css))
    try:
        walker.feed(text)
        walker.close()
    except Exception:  # malformed markup: report what was collected so far
        pass
    out: list[str] = []
    for run in walker.hidden_runs:
        joined = " ".join(" ".join(run).split())
        letters = len(_LETTERS_RE.findall(joined))
        words = len(re.findall(r"[^\W\d_]{2,}", joined))
        if letters >= min_letters and (words >= min_words or _CJK_RE.search(joined)):
            out.append(joined)
    return out


__all__ = ["hidden_html_text"]
