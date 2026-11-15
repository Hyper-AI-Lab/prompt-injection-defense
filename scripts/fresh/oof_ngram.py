#!/usr/bin/env python3
"""Out-of-fold document scores on the fresh TRAIN POOL (for choosing fusion thresholds).

Usage: PYTHONPATH=src python scripts/fresh/oof_ngram.py OUT.jsonl [--bits 17] [--C 4.0]

5 group folds (same grouping/hash as train_ngram --cv). Each fold's model is quantized exactly
like the shipped file and the held-out fold's whole documents are scored with the runtime
NgramScorer, so thresholds are chosen on document-level behaviour without touching the holdout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random

import numpy as np
from sklearn.linear_model import LogisticRegression

import train_ngram as T
from containment.detectors.ngram_scorer import NgramScorer
from containment.fresh_eval import load_fresh


def _group(it) -> str:  # noqa: ANN001
    return it.id.split(":")[1] + ":" + (it.id.split(":")[2] if it.kind == "attack" else it.id)


def _fold(g: str) -> int:
    return int(hashlib.sha256(g.encode()).hexdigest(), 16) % 5


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--bits", type=int, default=17)
    ap.add_argument("--C", type=float, default=4.0)
    a = ap.parse_args()
    items = load_fresh("train_pool")
    for it in items:
        if it.kind == "attack" and it.carrier == "bare":
            T._PAYLOADS[it.id.rsplit(":", 1)[0]] = it.text
    X, y, groups = T.examples(a.bits, random.Random(7))
    M = T.to_matrix(X, a.bits)
    yv = np.array(y)
    gf = np.array([_fold(g) for g in groups])
    with open(a.out, "w", encoding="utf-8") as fh:
        for k in range(5):
            m = LogisticRegression(C=a.C, class_weight="balanced", max_iter=2000,
                                   solver="liblinear").fit(M[gf != k], yv[gf != k])
            w = m.coef_[0]
            scale = float(np.abs(w).max() / 127.0) or 1e-6
            q = np.clip(np.round(w / scale), -127, 127).astype(int).tolist()
            raw = NgramScorer.from_params(
                bits=a.bits, nmin=T.NMIN, nmax=T.NMAX, words=T.WORDS, window=T.WINDOW,
                stride=T.STRIDE, scale=scale, bias=float(m.intercept_[0]), q=q)
            with open(f"{a.out}.fold{k}.bin", "wb") as mf:
                mf.write(raw)
            sc = NgramScorer(raw, verify=False)
            for it in items:
                if _fold(_group(it)) != k:
                    continue
                ws = sc.score(it.text)
                fh.write(json.dumps({"id": it.id, "kind": it.kind, "source": it.source,
                                     "carrier": it.carrier,
                                     "p": [round(x.probability, 4) for x in ws],
                                     "spans": [[x.start, x.end] for x in ws]}) + "\n")
            print("fold", k, "done", flush=True)


if __name__ == "__main__":
    main()
