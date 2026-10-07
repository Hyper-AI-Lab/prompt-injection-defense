"""CLI: containment-reference-host — hermetic attack/benign/human demo."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from containment.moltbook import LIVE_ENV, MoltbookError, read_posts
from containment.reference_host.scenarios import (
    ScenarioResult,
    run_all,
    run_attack,
    run_benign,
    run_human,
)

_SCENARIOS = frozenset({"attack", "benign", "human", "all"})


def _format_result(result: ScenarioResult) -> str:
    status = "PASS" if result.ok else "FAIL"
    return (
        f"[{status}] {result.path}: effect={result.effect} "
        f"rule_id={result.rule_id} — {result.detail}"
    )


def _run_live_moltbook() -> int:
    """Optional live ingest smoke; fail closed on network/API errors."""
    if os.environ.get(LIVE_ENV, "").strip() != "1":
        print(
            f"refusing --live-moltbook without {LIVE_ENV}=1 (fail closed)",
            file=sys.stderr,
        )
        return 2
    try:
        posts = read_posts(sort="new", limit=1)
    except MoltbookError as exc:
        print(f"live moltbook failed (fail closed): {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — surface unexpected network faults
        print(f"live moltbook error (fail closed): {exc}", file=sys.stderr)
        return 1
    if not posts:
        print("live moltbook: no posts returned", file=sys.stderr)
        return 1
    item = posts[0]
    label = item.ingest.label
    print(
        f"[LIVE] moltbook post_id={item.post_id} "
        f"integrity={label.integrity} ok={item.ok} "
        f"high_risk={item.ingest.high_risk}"
    )
    if label.integrity != "untrusted":
        print("live moltbook: expected untrusted integrity", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="containment-reference-host",
        description=(
            "Hermetic reference host demo: enterprise compose + BrokeredRegistry. "
            "Runs attack (deny), benign (allow), and human (require_human) paths."
        ),
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="Working directory for secrets/audit (default: temp dir)",
    )
    parser.add_argument(
        "--scenario",
        choices=sorted(_SCENARIOS),
        default="all",
        help="Which path to run (default: all)",
    )
    parser.add_argument(
        "--live-moltbook",
        action="store_true",
        help=f"Optional: fetch one Moltbook post (requires {LIVE_ENV}=1)",
    )
    args = parser.parse_args(argv)

    if args.live_moltbook:
        live_rc = _run_live_moltbook()
        if live_rc != 0:
            return live_rc

    if args.work_dir is not None:
        work = Path(args.work_dir)
        work.mkdir(parents=True, exist_ok=True)
        cleanup = None
    else:
        cleanup = tempfile.TemporaryDirectory(prefix="containment-ref-host-")
        work = Path(cleanup.name)

    try:
        if args.scenario == "all":
            results = run_all(work)
        elif args.scenario == "attack":
            results = [run_attack(work / "attack")]
        elif args.scenario == "benign":
            results = [run_benign(work / "benign")]
        else:
            results = [run_human(work / "human")]

        print(f"containment-reference-host  work_dir={work}")
        for result in results:
            print(_format_result(result))
        failed = [r for r in results if not r.ok]
        if failed:
            print(f"{len(failed)} scenario(s) failed", file=sys.stderr)
            return 1
        print(f"OK — {len(results)} scenario(s) passed")
        return 0
    finally:
        if cleanup is not None:
            cleanup.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
