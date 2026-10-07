#!/usr/bin/env python3
"""Host residual microbench: stdlib time.perf_counter only; no LLM / network I/O."""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

# Allow running without install when PYTHONPATH=src
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from containment.egress_resolve import resolve_and_pin
from containment.host import (
    EnvSecretProvider,
    FileAuditShipper,
    HostChecklist,
    TokenBucketRateLimit,
)


def _pct(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def _stats_ms(samples_s: list[float]) -> tuple[float, float, float]:
    ms = [s * 1000.0 for s in samples_s]
    ms_sorted = sorted(ms)
    mean = statistics.fmean(ms) if ms else 0.0
    return mean, _pct(ms_sorted, 50), _pct(ms_sorted, 95)


def _bench_resolve_pin(n: int) -> list[float]:
    def resolver(host: str, port: int) -> list[tuple[int, str]]:
        del host, port
        import socket

        return [(socket.AF_INET, "93.184.216.34")]  # example.com public A

    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        pin = resolve_and_pin(
            "https://example.com/path",
            resolver=resolver,
        )
        t1 = time.perf_counter()
        assert pin.pinned_ip == "93.184.216.34"
        samples.append(t1 - t0)
    return samples


def _bench_checklist(n: int) -> list[float]:
    checklist = HostChecklist(
        isolation_declared=True,
        secret_provider=EnvSecretProvider(),
        egress_configured=True,
        audit_shipper=FileAuditShipper("/tmp/containment-microbench-audit.jsonl"),
    )
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        ok = checklist.ok()
        t1 = time.perf_counter()
        assert ok is True
        samples.append(t1 - t0)
    return samples


def _bench_rate_limit(n: int) -> list[float]:
    # High capacity so allow() never denies during the loop.
    gate = TokenBucketRateLimit(rate=1e9, capacity=float(n) + 10.0)
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        allowed = gate.allow("tool.bench", cost=1.0)
        t1 = time.perf_counter()
        assert allowed is True
        samples.append(t1 - t0)
    return samples


def _report(name: str, samples: list[float]) -> None:
    mean, p50, p95 = _stats_ms(samples)
    print(
        f"{name}: n={len(samples)} mean_ms={mean:.4f} p50_ms={p50:.4f} p95_ms={p95:.4f}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-n", "--iterations", type=int, default=2000)
    args = parser.parse_args()
    n = max(1, args.iterations)

    print(f"microbench_host n={n} (perf_counter; injected resolver; no LLM)")
    _report("resolve_and_pin", _bench_resolve_pin(n))
    _report("HostChecklist.ok", _bench_checklist(n))
    _report("TokenBucketRateLimit.allow", _bench_rate_limit(n))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
