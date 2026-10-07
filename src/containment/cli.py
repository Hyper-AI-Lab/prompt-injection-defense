"""Command-line interface for containment eval and helpers."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from containment import __version__
from containment.eval_runner import default_fixtures_root, run_eval


def _cmd_eval(args: argparse.Namespace) -> int:
    root = Path(args.fixtures) if args.fixtures else default_fixtures_root()
    if args.suite == "fixtures":
        fixtures_root = root
    else:
        fixtures_root = root / args.suite if (root / args.suite).is_dir() else root

    policy_path = Path(args.policy) if args.policy else None
    metrics, _outcomes = run_eval(
        fixtures_root=fixtures_root,
        policy_path=policy_path,
        policy_enabled=not args.no_policy,
    )
    payload = metrics.as_dict()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        mode = "policy ON" if metrics.policy_enabled else "policy OFF (control)"
        print(f"containment eval — suite={args.suite} — {mode}")
        print(f"  attacks:  {metrics.n_attack}")
        print(f"  benign:   {metrics.n_benign}")
        print(f"  ASR:      {metrics.asr:.4f}  (attack success rate; lower is better)")
        print(f"  FPR:      {metrics.fpr:.4f}  (benign false-positive rate)")
        print(f"  utility:  {metrics.utility:.4f}  (benign usable fraction)")
        print(
            f"  blocked:  {metrics.attacks_blocked}/{metrics.n_attack} attacks; "
            f"flagged {metrics.benign_flagged}/{metrics.n_benign} benign"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="containment",
        description="containment — prompt-injection defense kit CLI",
    )
    parser.add_argument("--version", action="version", version=f"containment {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    ev = sub.add_parser("eval", help="Run offline fixture evaluation (ASR/FPR/utility)")
    ev.add_argument(
        "--suite",
        default="fixtures",
        help="Suite name (default: fixtures). Loads fixtures/attacks and fixtures/benign.",
    )
    ev.add_argument(
        "--fixtures",
        default=None,
        help="Override fixtures root directory",
    )
    ev.add_argument(
        "--policy",
        default=None,
        help="Path to policy YAML (default: policies/default_deny.yaml)",
    )
    ev.add_argument(
        "--no-policy",
        action="store_true",
        help="Control experiment: disable policy (ASR should rise)",
    )
    ev.add_argument(
        "--json",
        action="store_true",
        help="Print metrics as JSON",
    )
    ev.set_defaults(func=_cmd_eval)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
