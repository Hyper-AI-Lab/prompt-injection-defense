"""Command-line interface: ``containment eval`` and ``containment doctor``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from containment import __version__
from containment.doctor import DoctorConfig, config_from_env, format_report, run_doctor
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
            f"  detector_block_rate: {metrics.detector_block_rate:.4f}  "
            "(attacks flagged high-risk by cascade/hints)"
        )
        print(
            f"  policy_block_rate:   {metrics.policy_block_rate:.4f}  "
            "(attacks denied by per-case privileged policy)"
        )
        print(
            f"  blocked:  {metrics.attacks_blocked}/{metrics.n_attack} attacks; "
            f"flagged {metrics.benign_flagged}/{metrics.n_benign} benign"
        )
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    config = config_from_env(
        DoctorConfig(
            policy_path=Path(args.policy) if args.policy else None,
            secrets_dir=Path(args.secrets_dir) if args.secrets_dir else None,
            secrets_env_prefix=args.secrets_env_prefix,
            capability_secret_name=args.capability_secret,
            intent_secret_name=args.intent_secret,
            isolation_declared=args.isolation_declared,
            egress_proxy_url=args.egress_proxy,
            egress_pinned=args.egress_pinned,
            audit_ship_destination=Path(args.audit_ship) if args.audit_ship else None,
            install_only=args.install_only,
        ),
        os.environ,
    )
    report = run_doctor(config)
    if args.json:
        print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    else:
        print(format_report(report))
    return report.exit_code


def _add_doctor_parser(sub: argparse._SubParsersAction) -> None:
    doc = sub.add_parser(
        "doctor",
        help="Offline install + host wiring check (exit 0 ready, 1 not ready, 2 usage)",
        description=(
            "Check the install and the host settings passed to build_enterprise_host. "
            "No network; secret values are never printed."
        ),
    )
    doc.add_argument(
        "--install-only",
        action="store_true",
        help="Only check package data and the policy (skip host checks)",
    )
    doc.add_argument("--policy", default=None, help="Policy YAML (default: shipped default_deny)")
    secrets = doc.add_mutually_exclusive_group()
    secrets.add_argument("--secrets-dir", default=None, help="FileSecretProvider root directory")
    secrets.add_argument(
        "--secrets-env-prefix", default=None, help="EnvSecretProvider prefix (CONTAINMENT_SECRET_)"
    )
    doc.add_argument("--capability-secret", default="capability", help="Capability secret name")
    doc.add_argument("--intent-secret", default="intent", help="Intent secret name")
    doc.add_argument(
        "--isolation-declared",
        action="store_true",
        help="Declare that the agent runs in a real OS/container sandbox",
    )
    egress = doc.add_mutually_exclusive_group()
    egress.add_argument(
        "--egress-proxy", default=None, help="Forward proxy URL (env CONTAINMENT_EGRESS_PROXY)"
    )
    egress.add_argument(
        "--egress-pinned",
        action="store_true",
        help="Resolve-pin client egress (env CONTAINMENT_EGRESS_PINNED=1)",
    )
    doc.add_argument("--audit-ship", default=None, help="Audit JSONL ship destination path")
    doc.add_argument("--json", action="store_true", help="Print the report as JSON")
    doc.set_defaults(func=_cmd_doctor)


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
    _add_doctor_parser(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
