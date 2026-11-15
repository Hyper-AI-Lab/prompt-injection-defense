"""Fresh independent evaluation set (1.10.0): public-benchmark attacks + security-heavy benign.

The set lives in ``evalsets/fresh/`` of a source checkout (not shipped in the wheel; it holds
CC BY-SA text). Built by ``scripts/fresh/build_fresh.py`` and frozen by ``MANIFEST.sha256``.
``holdout.jsonl`` is never used for tuning; ``train_pool.jsonl`` is for training/tuning.
Detector-only: an attack counts as detected when the cascade marks it high risk; a benign
item is a false positive when it is marked high risk.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SPLITS = ("holdout", "train_pool")


def default_evalsets_root() -> Path:
    env = os.environ.get("CONTAINMENT_EVALSETS")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "evalsets"


@dataclass(frozen=True, slots=True)
class FreshItem:
    id: str
    kind: str  # "attack" | "benign"
    source: str
    subsource: str
    carrier: str
    lang: str
    text: str


def verify_manifest(root: Path) -> None:
    """Fail loudly if a frozen file changed after it was frozen."""
    manifest = root / "fresh" / "MANIFEST.sha256"
    for line in manifest.read_text().splitlines():
        digest, name = line.split()
        actual = hashlib.sha256((root / "fresh" / name).read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"evalsets/fresh/{name} does not match MANIFEST.sha256")


def _insert(filler: str, payload: str, frac: float) -> str:
    """Insert ``payload`` as its own paragraph at the paragraph boundary nearest ``frac``."""
    cut = int(len(filler) * frac)
    para = filler.rfind("\n\n", 0, cut)
    cut = para if para > 0 else cut
    return f"{filler[:cut]}\n\n{payload}\n\n{filler[cut:].lstrip()}"


def load_fresh(split: str = "holdout", root: Path | None = None) -> list[FreshItem]:
    if split not in SPLITS:
        raise ValueError(f"split must be one of {SPLITS}")
    root = root or default_evalsets_root()
    verify_manifest(root)
    rows = [json.loads(line) for line in
            (root / "fresh" / f"{split}.jsonl").read_text(encoding="utf-8").splitlines() if line]
    by_id = {r["id"][2:]: r.get("text", "") for r in rows if r["kind"] == "benign"}
    items = []
    for r in rows:
        if r.get("carrier") == "long":
            filler = "\n\n".join(by_id[f] for f in r["filler"])
            text = _insert(filler, r["payload"], float(r["offset_frac"]))
        else:
            text = r["text"]
        items.append(FreshItem(r["id"], r["kind"], r["source"], r.get("subsource", ""),
                               r.get("carrier", "doc"), r.get("lang", "en"), text))
    return items


@dataclass(frozen=True, slots=True)
class FreshOutcome:
    item: FreshItem
    flagged: bool
    instruction_text: bool
    seconds: float


def run_fresh(scan: Callable[[str], Any], items: Iterable[FreshItem]) -> list[FreshOutcome]:
    out = []
    for it in items:
        t = time.perf_counter()
        res = scan(it.text)
        out.append(FreshOutcome(it, bool(res.high_risk),
                                bool(getattr(res, "contains_instruction_text", False)),
                                time.perf_counter() - t))
    return out


def summarize(outcomes: list[FreshOutcome]) -> dict[str, Any]:
    def cell() -> list[int]:
        return [0, 0]

    by: dict[str, dict[str, list[int]]] = {
        "attack_by_source": defaultdict(cell), "attack_by_subsource": defaultdict(cell),
        "attack_by_carrier": defaultdict(cell), "benign_by_source": defaultdict(cell),
        "benign_by_carrier": defaultdict(cell),
    }
    tot = {"attack": [0, 0], "benign": [0, 0]}
    secs = 0.0
    chars = 0
    for o in outcomes:
        it = o.item
        tot[it.kind][0] += int(o.flagged)
        tot[it.kind][1] += 1
        secs += o.seconds
        chars += len(it.text)
        if it.kind == "attack":
            for key, val in (("attack_by_source", it.source),
                             ("attack_by_subsource", f"{it.source}/{it.subsource}"),
                             ("attack_by_carrier", it.carrier)):
                by[key][val][0] += int(o.flagged)
                by[key][val][1] += 1
        else:
            for key, val in (("benign_by_source", it.source), ("benign_by_carrier", it.carrier)):
                by[key][val][0] += int(o.flagged)
                by[key][val][1] += 1
    summary: dict[str, Any] = {
        "recall": {"hit": tot["attack"][0], "n": tot["attack"][1]},
        "false_positives": {"hit": tot["benign"][0], "n": tot["benign"][1]},
        "ms_per_kb": round(1000 * secs / max(1.0, chars / 1024), 2),
    }
    for key, d in by.items():
        summary[key] = {k: {"hit": v[0], "n": v[1]} for k, v in sorted(d.items())}
    return summary


def _pct(c: dict[str, int]) -> str:
    return f"{c['hit']}/{c['n']} ({100 * c['hit'] / max(1, c['n']):.1f}%)"


def format_report(summary: dict[str, Any], *, title: str) -> str:
    lines = [title,
             f"  recall (attacks flagged):   {_pct(summary['recall'])}",
             f"  false positives (benign):   {_pct(summary['false_positives'])}",
             f"  latency: {summary['ms_per_kb']} ms/KB"]
    for key in ("attack_by_source", "attack_by_carrier", "benign_by_source", "benign_by_carrier"):
        lines.append(f"  {key}:")
        for k, c in summary[key].items():
            lines.append(f"    {k:32s} {_pct(c)}")
    return "\n".join(lines)


__all__ = ["FreshItem", "FreshOutcome", "default_evalsets_root", "format_report", "load_fresh",
           "run_fresh", "summarize", "verify_manifest"]
