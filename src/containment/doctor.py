"""``containment doctor``: offline check of an install and of a host's wiring.

The report is built from the same types the runtime uses: the declared settings
become a :class:`~containment.host.checklist.HostChecklist` (its ``failures()``
codes are reported verbatim) and the final check composes
:func:`~containment.enterprise.build_enterprise_host` against a temporary audit
log. Nothing touches the network; secret bytes are never printed.
"""

from __future__ import annotations

import importlib.util
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml

from containment import __version__, resources
from containment.enterprise import build_enterprise_host
from containment.host.audit_ship import AuditShipper, FileAuditShipper
from containment.host.checklist import HostChecklist
from containment.host.egress import EgressProvider, PinnedEgressProvider, ProxyEgressProvider
from containment.host.secrets import (
    EnvSecretProvider,
    FileSecretProvider,
    SecretError,
    SecretProvider,
)
from containment.moltbook import PINNED_ENV, PROXY_ENV
from containment.policy import PolicyEngine

Status = Literal["pass", "fail", "skip"]
Scope = Literal["install", "host"]

# Host duties no declaration can prove (docs/BOT_PLAYBOOK.md §8).
HOST_RESIDUALS: tuple[str, ...] = (
    "OS/container isolation is declared, not verified",
    "egress enforcement (proxy / resolve-pin) runs in the host network path",
    "audit retention: ship audit.jsonl to WORM/SIEM (hash chain is tamper-evidence only)",
    "secret storage and rotation",
    "spend caps on model and tool APIs beyond RateLimitGate",
    "Claude Code hooks must be enabled and kept on by the host",
)

# Optional extras: (check id, import names, extra name, purpose).
_EXTRAS: tuple[tuple[str, tuple[str, ...], str, str], ...] = (
    ("extra.ml", ("transformers", "torch"), "ml", "PIGuard Stage-1"),
    ("extra.crypto", ("cryptography",), "crypto", "Ed25519 intents"),
    ("extra.redis", ("redis",), "redis", "shared consume store"),
)
# GitHub source only: the name `containment` on PyPI is not this project.
_SOURCE = "git+https://github.com/Hyper-AI-Lab/prompt-injection-defense.git"


def extra_install_hint(extra: str) -> str:
    """pip command for an optional extra, pinned to this version's tag on GitHub."""
    return f'pip install "containment[{extra}] @ {_SOURCE}@v{__version__}"'


@dataclass(frozen=True, slots=True)
class DoctorConfig:
    """Host settings as passed to ``build_enterprise_host`` (all optional)."""

    policy_path: Path | None = None
    secrets_dir: Path | None = None
    secrets_env_prefix: str | None = None
    capability_secret_name: str = "capability"
    intent_secret_name: str = "intent"
    isolation_declared: bool = False
    egress_proxy_url: str | None = None
    egress_pinned: bool = False
    audit_ship_destination: Path | None = None
    install_only: bool = False

    def __post_init__(self) -> None:
        if self.secrets_dir is not None and self.secrets_env_prefix is not None:
            raise ValueError("pass only one of secrets_dir, secrets_env_prefix")
        if self.egress_proxy_url is not None and self.egress_pinned:
            raise ValueError("pass only one of egress_proxy_url, egress_pinned")


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """One line of the report. ``required`` checks decide the exit code."""

    id: str
    required: bool
    status: Status
    detail: str
    fix: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "required": self.required,
            "status": self.status,
            "detail": self.detail,
            "fix": self.fix,
        }


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Full doctor result; ``ok`` iff every required check passed."""

    version: str
    scope: Scope
    checks: tuple[DoctorCheck, ...]
    checklist_failures: tuple[str, ...] = ()
    residuals: tuple[str, ...] = field(default=HOST_RESIDUALS)

    @property
    def ok(self) -> bool:
        return all(c.status == "pass" for c in self.checks if c.required)

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1

    def as_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "scope": self.scope,
            "ok": self.ok,
            "checks": [c.as_dict() for c in self.checks],
            "checklist_failures": list(self.checklist_failures),
            "residuals": list(self.residuals),
        }


def config_from_env(config: DoctorConfig, env: Mapping[str, str]) -> DoctorConfig:
    """Fill egress from ``CONTAINMENT_EGRESS_PROXY`` / ``CONTAINMENT_EGRESS_PINNED=1``
    when neither egress setting was given (same env contract as ``moltbook``)."""
    if config.egress_proxy_url is not None or config.egress_pinned:
        return config
    proxy = env.get(PROXY_ENV, "").strip()
    if proxy:
        return replace(config, egress_proxy_url=proxy)
    if env.get(PINNED_ENV, "").strip() == "1":
        return replace(config, egress_pinned=True)
    return config


def _check_package() -> DoctorCheck:
    policy = resources.default_policy_path()
    fixtures = resources.default_fixtures_root()
    missing = [
        str(p)
        for p in (policy, fixtures / "attacks", fixtures / "benign")
        if not p.exists()
    ]
    if missing:
        return DoctorCheck(
            "install.package",
            True,
            "fail",
            f"containment {__version__}; shipped data missing: {', '.join(missing)}",
            "reinstall from a release wheel or a full checkout",
        )
    return DoctorCheck(
        "install.package",
        True,
        "pass",
        f"containment {__version__}; default policy + eval fixtures present",
    )


def _check_policy(path: Path) -> DoctorCheck:
    try:
        engine = PolicyEngine.from_yaml_path(path)
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as exc:
        return DoctorCheck(
            "install.policy", True, "fail", f"{path}: {exc}", "fix the policy YAML or --policy path"
        )
    return DoctorCheck("install.policy", True, "pass", f"{path}: {len(engine.rules)} rules")


def _secret_provider(cfg: DoctorConfig) -> tuple[SecretProvider | None, str]:
    if cfg.secrets_dir is not None:
        return FileSecretProvider(cfg.secrets_dir), f"file:{cfg.secrets_dir}"
    if cfg.secrets_env_prefix is not None:
        return EnvSecretProvider(prefix=cfg.secrets_env_prefix), f"env:{cfg.secrets_env_prefix}*"
    return None, ""


def _proxy_url_ok(url: str) -> bool:
    """True if ``url`` is ``http(s)://HOST[:PORT]`` with a valid port."""
    try:
        parts = urlsplit(url.strip())
        parts.port  # noqa: B018 - raises ValueError for a non-numeric or out-of-range port
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def _redact_url(url: str) -> str:
    """``url`` with everything between the scheme and the last ``@`` shown as ``***``."""
    if "@" not in url:
        return url
    scheme, sep, rest = url.partition("://")
    if not sep:
        scheme, rest = "", url
    return f"{scheme}{sep}***@{rest.rsplit('@', 1)[1]}"


def _egress_provider(cfg: DoctorConfig) -> EgressProvider | None:
    if cfg.egress_proxy_url is not None:
        return ProxyEgressProvider(cfg.egress_proxy_url)
    if cfg.egress_pinned:
        return PinnedEgressProvider()
    return None


def _writable_target(path: Path) -> bool:
    """True if ``path`` can be appended to, or created under its nearest existing parent."""
    if path.exists():
        return path.is_file() and os.access(path, os.W_OK)
    parent = path.parent
    while not parent.exists():
        if parent == parent.parent:
            return False
        parent = parent.parent
    return parent.is_dir() and os.access(parent, os.W_OK | os.X_OK)


def _host_checks(
    cfg: DoctorConfig, policy_path: Path, policy_ok: bool
) -> tuple[list[DoctorCheck], tuple[str, ...]]:
    provider, provider_desc = _secret_provider(cfg)
    proxy_bad = cfg.egress_proxy_url is not None and not _proxy_url_ok(cfg.egress_proxy_url)
    egress = None if proxy_bad else _egress_provider(cfg)
    shipper: AuditShipper | None = (
        FileAuditShipper(cfg.audit_ship_destination)
        if cfg.audit_ship_destination is not None
        else None
    )
    checklist = HostChecklist(
        isolation_declared=cfg.isolation_declared,
        secret_provider=provider,
        egress_provider=egress,
        audit_shipper=shipper,
        capability_secret_name=cfg.capability_secret_name,
    )
    codes = checklist.failures()
    checks: list[DoctorCheck] = []

    if "isolation_not_declared" in codes:
        checks.append(DoctorCheck(
            "host.isolation", True, "fail", "isolation_not_declared",
            "run the agent in an OS/container sandbox, then pass --isolation-declared",
        ))
    else:
        checks.append(DoctorCheck(
            "host.isolation", True, "pass", "declared (honor-system; doctor cannot verify)"
        ))

    if "secret_provider_missing" in codes:
        checks.append(DoctorCheck(
            "host.secret_provider", True, "fail", "secret_provider_missing",
            "pass --secrets-dir DIR or --secrets-env-prefix PREFIX",
        ))
    elif cfg.secrets_dir is not None and not cfg.secrets_dir.is_dir():
        checks.append(DoctorCheck(
            "host.secret_provider", True, "fail", f"{provider_desc}: not a directory",
            "create the secrets directory (mode 0700)",
        ))
    else:
        checks.append(DoctorCheck("host.secret_provider", True, "pass", provider_desc))

    if proxy_bad:
        assert cfg.egress_proxy_url is not None
        checks.append(DoctorCheck(
            "host.egress", True, "fail",
            f"proxy: malformed URL {_redact_url(cfg.egress_proxy_url)!r}",
            "use http://HOST:PORT (e.g. containment-egress-proxy)",
        ))
    elif "egress_not_configured" in codes:
        checks.append(DoctorCheck(
            "host.egress", True, "fail", "egress_not_configured",
            f"pass --egress-pinned or --egress-proxy URL (or set {PINNED_ENV}=1 / {PROXY_ENV})",
        ))
    else:
        assert egress is not None
        url = egress.proxy_url
        detail = f"proxy {_redact_url(url)}" if url is not None else "pinned (resolve-pin client)"
        checks.append(DoctorCheck("host.egress", True, "pass", detail))

    if "audit_shipper_missing" in codes:
        checks.append(DoctorCheck(
            "host.audit_shipper", True, "fail", "audit_shipper_missing",
            "pass --audit-ship PATH (JSONL destination your SIEM/WORM collects)",
        ))
    elif cfg.audit_ship_destination is not None and not _writable_target(
        cfg.audit_ship_destination
    ):
        checks.append(DoctorCheck(
            "host.audit_shipper", True, "fail",
            f"{cfg.audit_ship_destination}: not writable",
            "fix permissions or choose a writable destination",
        ))
    else:
        checks.append(DoctorCheck(
            "host.audit_shipper", True, "pass", f"file:{cfg.audit_ship_destination}"
        ))

    names = (cfg.capability_secret_name, cfg.intent_secret_name)
    if provider is None:
        checks.append(DoctorCheck(
            "host.secrets", True, "skip", "no secret provider", "configure host.secret_provider"
        ))
    else:
        problems: list[str] = []
        for name in names:
            try:
                provider.get_bytes(name)
            except (SecretError, OSError) as exc:
                problems.append(str(exc))
        if problems:
            checks.append(DoctorCheck(
                "host.secrets", True, "fail", "; ".join(problems),
                "create the secret (e.g. openssl rand -hex 32 > DIR/NAME; chmod 600)",
            ))
        else:
            checks.append(DoctorCheck(
                "host.secrets", True, "pass", f"loaded: {', '.join(names)} (values not shown)"
            ))

    if not policy_ok or any(c.status != "pass" for c in checks):
        checks.append(DoctorCheck(
            "host.compose", True, "skip", "not attempted until the checks above pass"
        ))
    else:
        checks.append(_check_compose(cfg, policy_path, provider, egress))
    return checks, codes


def _check_compose(
    cfg: DoctorConfig,
    policy_path: Path,
    provider: SecretProvider | None,
    egress: EgressProvider | None,
) -> DoctorCheck:
    assert cfg.audit_ship_destination is not None
    with tempfile.TemporaryDirectory(prefix="containment-doctor-") as tmp:
        try:
            host = build_enterprise_host(
                policy_path=policy_path,
                audit_path=Path(tmp) / "audit.jsonl",
                audit_ship_destination=cfg.audit_ship_destination,
                secret_provider=provider,
                isolation_declared=cfg.isolation_declared,
                egress_provider=egress,
                capability_secret_name=cfg.capability_secret_name,
                intent_secret_name=cfg.intent_secret_name,
            )
        except (ValueError, SecretError, OSError) as exc:
            return DoctorCheck(
                "host.compose", True, "fail", f"build_enterprise_host: {exc}",
                "fix the reported setting",
            )
    return DoctorCheck(
        "host.compose",
        True,
        "pass",
        "build_enterprise_host OK (HostGate on, signed intents, "
        f"egress={host.egress_provider.mode})",
    )


def _extra_checks() -> list[DoctorCheck]:
    checks: list[DoctorCheck] = []
    for check_id, modules, extra, purpose in _EXTRAS:
        missing = [m for m in modules if importlib.util.find_spec(m) is None]
        if missing:
            checks.append(DoctorCheck(
                check_id,
                False,
                "skip",
                f"not installed ({', '.join(missing)}); {purpose}",
                extra_install_hint(extra),
            ))
        else:
            checks.append(DoctorCheck(check_id, False, "pass", f"installed ({', '.join(modules)})"))
    return checks


def run_doctor(config: DoctorConfig) -> DoctorReport:
    """Run every check for ``config`` and return the report (no network, no output)."""
    policy_path = config.policy_path or resources.default_policy_path()
    checks = [_check_package(), _check_policy(policy_path)]
    policy_ok = checks[1].status == "pass"
    codes: tuple[str, ...] = ()
    if not config.install_only:
        host_checks, codes = _host_checks(config, policy_path, policy_ok)
        checks.extend(host_checks)
    checks.extend(_extra_checks())
    return DoctorReport(
        version=__version__,
        scope="install" if config.install_only else "host",
        checks=tuple(checks),
        checklist_failures=codes,
        residuals=() if config.install_only else HOST_RESIDUALS,
    )


_MARK: dict[Status, str] = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP"}


def format_report(report: DoctorReport) -> str:
    """Human-readable report (one line per check, fix hints indented)."""
    lines = [f"containment doctor — {report.version} — scope={report.scope}"]
    for c in report.checks:
        tag = _MARK[c.status] if c.required else _MARK[c.status].lower()
        lines.append(f"  [{tag}] {c.id}: {c.detail}")
        if c.fix and c.status != "pass":
            lines.append(f"         fix: {c.fix}")
    if report.checklist_failures:
        lines.append(f"  HostChecklist.failures(): {', '.join(report.checklist_failures)}")
    if report.scope == "host":
        lines.append("  host-owned (not checkable here):")
        lines.extend(f"    - {r}" for r in report.residuals)
    required = [c for c in report.checks if c.required]
    passed = sum(1 for c in required if c.status == "pass")
    verdict = "OK" if report.ok else "NOT READY"
    lines.append(f"{verdict} — {passed}/{len(required)} required checks passed")
    return "\n".join(lines)


__all__ = [
    "HOST_RESIDUALS",
    "DoctorCheck",
    "DoctorConfig",
    "DoctorReport",
    "config_from_env",
    "extra_install_hint",
    "format_report",
    "run_doctor",
]
