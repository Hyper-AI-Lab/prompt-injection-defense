#!/usr/bin/env python3
# ruff: noqa: E501  (data-heavy offline script; long literal lines are clearer)
"""Train the zero-dependency n-gram scorer on TRAIN data only (offline; numpy/scipy/sklearn).

Usage: PYTHONPATH=src python scripts/fresh/train_ngram.py OUT.bin [--bits 17] [--C 4.0] [--cv]

Training data: evalsets/fresh/train_pool.jsonl + the 1.8/1.9 *train* splits (mutation train
variants without encoded families, gap-suite train items, benign train fixtures). Never any
holdout. Windows use exactly the runtime featurizer (containment.detectors.ngram_scorer).
"""

from __future__ import annotations

import argparse
import hashlib
import random
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from scipy import sparse
from sklearn.linear_model import LogisticRegression

from containment.detectors.ngram_scorer import NgramScorer, gram_positions, normalize, windows
from containment.fresh_eval import load_fresh
from containment.mutation_eval import case_split, load_variants

WINDOW, STRIDE, NMIN, NMAX, WORDS = 512, 256, 3, 5, True
ENCODED = {"b64", "hex", "url_escape", "rot13"}
REPO = Path(__file__).resolve().parents[2]


def window_vecs(data: bytes, bits: int) -> tuple[list[tuple[int, int]], list[Counter]]:
    grams = gram_positions(data, bits, NMIN, NMAX, WORDS)
    spans = windows(len(data), WINDOW, STRIDE)
    vecs = []
    for a, b in spans:
        vecs.append(Counter(bk for pos, bk in grams if a <= pos < b))
    return spans, vecs


def examples(bits: int, rng: random.Random) -> tuple[list[Counter], list[int], list[str]]:
    X: list[Counter] = []
    y: list[int] = []
    g: list[str] = []

    def add_doc(text: str, label: int, group: str, payload: str | None = None,
                max_neg: int = 6) -> None:
        data = normalize(text)
        if not data:
            return
        spans, vecs = window_vecs(data, bits)
        pspan = None
        if payload is not None:
            p = normalize(payload)
            k = data.find(p)
            if k >= 0:
                pspan = (k, k + len(p))
            elif len(spans) <= 2:
                pspan = (0, len(data))  # short doc: whole thing positive
            else:
                return
        negs = []
        for (a, b), v in zip(spans, vecs, strict=True):
            if pspan is None:
                negs.append(v)
                continue
            ov = max(0, min(b, pspan[1]) - max(a, pspan[0]))
            need = min(pspan[1] - pspan[0], 200)
            if ov >= need:
                X.append(v)
                y.append(1)
                g.append(group)
            elif ov == 0:
                negs.append(v)
        for v in (negs if len(negs) <= max_neg else rng.sample(negs, max_neg)):
            X.append(v)
            y.append(0)
            g.append(group)

    for it in load_fresh("train_pool"):
        group = it.id.split(":")[1] + ":" + (it.id.split(":")[2] if it.kind == "attack" else it.id)
        if it.kind == "attack":
            payload = None if it.carrier == "bare" else _payload_of(it)
            add_doc(it.text, 1, group, payload if payload else it.text)
        else:
            add_doc(it.text, 0, group)
    for v in load_variants():
        if case_split(v.case_id) == "train" and v.family not in ENCODED:
            add_doc("\n".join(v.chunks), 1, f"mut:{v.case_id}", "\n".join(v.chunks))
    import yaml

    for item in yaml.safe_load((REPO / "fixtures/gaps/gaps.yaml").read_text())["items"]:
        if item.get("split") != "train":
            continue
        text = item.get("text") or "\n".join(item.get("chunks", []))
        if item["kind"] in ("attack", "payload"):
            add_doc(text, 1, f"gap:{item['id']}", text)
        else:
            add_doc(text, 0, f"gap:{item['id']}")
    for f in sorted((REPO / "fixtures/benign").glob("*.txt")):
        if case_split(f.stem) == "train":
            add_doc(f.read_text(encoding="utf-8", errors="replace"), 0, f"ben:{f.stem}")
    return X, y, g


_PAYLOADS: dict[str, str] = {}


def _payload_of(it) -> str | None:  # noqa: ANN001
    return _PAYLOADS.get(it.id.rsplit(":", 1)[0])


def to_matrix(X: list[Counter], bits: int) -> sparse.csr_matrix:
    rows, cols, vals = [], [], []
    for i, c in enumerate(X):
        tot = sum(c.values()) or 1
        s = tot ** 0.5
        for k, v in c.items():
            rows.append(i)
            cols.append(k)
            vals.append(v / s)
    return sparse.csr_matrix((vals, (rows, cols)), shape=(len(X), 1 << bits), dtype=np.float32)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--bits", type=int, default=17)
    ap.add_argument("--C", type=float, default=4.0)
    ap.add_argument("--cv", action="store_true")
    args = ap.parse_args()
    rng = random.Random(7)
    # Payload lookup for carrier items (bare item text == payload).
    for it in load_fresh("train_pool"):
        if it.kind == "attack" and it.carrier == "bare":
            _PAYLOADS[it.id.rsplit(":", 1)[0]] = it.text
    X, y, groups = examples(args.bits, rng)
    M = to_matrix(X, args.bits)
    yv = np.array(y)
    print(f"windows: {len(y)}  pos={int(yv.sum())}  neg={int((1 - yv).sum())}", file=sys.stderr)
    if args.cv:
        uniq = sorted(set(groups))
        fold = {gname: int(hashlib.sha256(gname.encode()).hexdigest(), 16) % 5 for gname in uniq}
        gf = np.array([fold[gname] for gname in groups])
        probs = np.zeros(len(y))
        for k in range(5):
            tr, te = gf != k, gf == k
            m = LogisticRegression(C=args.C, class_weight="balanced", max_iter=2000,
                                   solver="liblinear")
            m.fit(M[tr], yv[tr])
            probs[te] = m.predict_proba(M[te])[:, 1]
        from sklearn.metrics import average_precision_score
        print(f"CV AP={average_precision_score(yv, probs):.4f}", file=sys.stderr)
        for t in (0.5, 0.7, 0.8, 0.9, 0.95, 0.98):
            tp = ((probs >= t) & (yv == 1)).sum() / max(1, yv.sum())
            fp = ((probs >= t) & (yv == 0)).sum() / max(1, (1 - yv).sum())
            print(f"  t={t:.2f} window recall={tp:.3f} window FPR={fp:.4f}", file=sys.stderr)
    m = LogisticRegression(C=args.C, class_weight="balanced", max_iter=2000, solver="liblinear")
    m.fit(M, yv)
    w = m.coef_[0]
    scale = float(np.abs(w).max() / 127.0) or 1e-6
    q = np.clip(np.round(w / scale), -127, 127).astype(int).tolist()
    raw = NgramScorer.from_params(bits=args.bits, nmin=NMIN, nmax=NMAX, words=WORDS,
                                  window=WINDOW, stride=STRIDE, scale=scale,
                                  bias=float(m.intercept_[0]), q=q)
    Path(args.out).write_bytes(raw)
    print(f"wrote {args.out} ({len(raw)} bytes) sha256={hashlib.sha256(raw).hexdigest()}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
