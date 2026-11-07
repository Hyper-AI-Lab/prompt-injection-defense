"""Gap suite eval (1.9.0): detector-only coverage of the blind spots reported for 1.8.0.

Loads ``fixtures/gaps/gaps.yaml`` (frozen before any 1.9.0 detector change). Each item is an
attack, a benign near-miss, or a ``payload`` planted into generated long-document filler for
the ONNX whole-document-scan gap. ``split`` marks ``train`` (tunable) vs ``holdout`` (measured
only). The metric is the production cascade's ``high_risk`` verdict (policy is not consulted);
for the ``quoted`` gap an attack also counts when any embedded-instruction finding is present
even if the aggregate stays below the high-risk line.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from containment.detectors.cascade import DetectorCascade
from containment.eval_runner import default_fixtures_root

Split = Literal["train", "holdout"]
Kind = Literal["attack", "benign", "payload"]
_EMBEDDED_KINDS = frozenset(
    {"quoted_instruction", "encoded_instruction", "hidden_instruction", "obfuscated_instruction"}
)
# Long-document filler: neutral prose with no steering cues.
_FILLER_PARA = (
    "The quarterly operations review covered throughput, latency, and cost across the "
    "regional clusters. Capacity held within budget and the backlog trended down over the "
    "period. The team documented runbook updates and scheduled the next maintenance window. "
)


def gaps_path(fixtures_root: Path | None = None) -> Path:
    return (fixtures_root or default_fixtures_root()) / "gaps" / "gaps.yaml"


@dataclass(frozen=True, slots=True)
class GapItem:
    id: str
    gap: str
    split: Split
    kind: Kind
    chunks: tuple[str, ...]


def load_gap_items(fixtures_root: Path | None = None) -> list[GapItem]:
    raw = yaml.safe_load(gaps_path(fixtures_root).read_text(encoding="utf-8"))
    items: list[GapItem] = []
    for d in raw["items"]:
        chunks = tuple(d["chunks"]) if "chunks" in d else (d["text"],)
        items.append(GapItem(d["id"], d["gap"], d["split"], d["kind"], chunks))
    return items


def _long_docs(payload: str) -> list[str]:
    """Plant ``payload`` at start / middle / end / window-straddle of ~160 KB filler."""
    block = _FILLER_PARA * 700  # ~160 KB
    mid = len(block) // 2
    straddle = 60_000  # near a typical model-window boundary in characters
    return [
        f"{payload}\n\n{block}",
        f"{block[:mid]}\n\n{payload}\n\n{block[mid:]}",
        f"{block}\n\n{payload}",
        f"{block[:straddle]}{payload}{block[straddle:]}",
    ]


def _attack_hit(cascade: DetectorCascade, item: GapItem) -> bool:
    if len(item.chunks) == 1:
        result = cascade.scan(item.chunks[0])
    else:
        result = cascade.scan_chunks(list(item.chunks))
    if result.high_risk:
        return True
    if item.gap == "quoted":
        kinds = {f.kind for s in result.signals for f in s.findings}
        return bool(kinds & _EMBEDDED_KINDS)
    return False


@dataclass(frozen=True, slots=True)
class GapOutcome:
    item: GapItem
    detected: bool


def run_gap_eval(
    cascade: DetectorCascade, *, fixtures_root: Path | None = None
) -> tuple[GapOutcome, ...]:
    outcomes: list[GapOutcome] = []
    for item in load_gap_items(fixtures_root):
        if item.kind == "payload":
            docs = _long_docs(item.chunks[0])
            detected = all(cascade.scan(doc).high_risk for doc in docs)
            outcomes.append(GapOutcome(item, detected))
        elif item.kind == "attack":
            outcomes.append(GapOutcome(item, _attack_hit(cascade, item)))
        else:  # benign: "detected" means correctly NOT flagged
            flagged = _attack_hit(cascade, item)
            outcomes.append(GapOutcome(item, not flagged))
    return tuple(outcomes)


def summarize(outcomes: tuple[GapOutcome, ...]) -> dict[str, Any]:
    agg: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0])
    for o in outcomes:
        cell = agg[(o.item.gap, o.item.split, o.item.kind)]
        cell[0] += int(o.detected)
        cell[1] += 1
    return {f"{g}/{s}/{k}": {"ok": v[0], "total": v[1]} for (g, s, k), v in sorted(agg.items())}


def format_gap_report(outcomes: tuple[GapOutcome, ...], *, title: str) -> str:
    lines = [title, f"  {'gap/split/kind':<26}{'ok/total':>10}  misses"]
    agg: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0])
    misses: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    for o in outcomes:
        key = (o.item.gap, o.item.split, o.item.kind)
        agg[key][0] += int(o.detected)
        agg[key][1] += 1
        if not o.detected:
            misses[key].append(o.item.id)
    for key in sorted(agg):
        ok, total = agg[key]
        label = "/".join(key)
        miss = ",".join(misses[key])
        lines.append(f"  {label:<26}{f'{ok}/{total}':>10}  {miss}")
    return "\n".join(lines)


__all__ = [
    "GapItem",
    "GapOutcome",
    "format_gap_report",
    "load_gap_items",
    "run_gap_eval",
    "summarize",
]
