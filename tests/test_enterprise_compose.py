"""build_enterprise_host composition (LEFTOVERS step 10)."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.enterprise import EnterpriseHost, build_enterprise_host
from containment.host import (
    FileAuditShipper,
    FileSecretProvider,
    PinnedEgressProvider,
    ProxyEgressProvider,
    TokenBucketRateLimit,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "default_deny.yaml"


def _secrets(tmp_path: Path) -> Path:
    root = tmp_path / "secrets"
    root.mkdir()
    (root / "capability").write_bytes(b"c" * 32)
    (root / "intent").write_bytes(b"i" * 32)
    return root


def test_build_enterprise_host_checklist_and_gate(tmp_path: Path) -> None:
    secrets = _secrets(tmp_path)
    ship_dest = tmp_path / "shipped.jsonl"
    host = build_enterprise_host(
        policy_path=POLICY_PATH,
        audit_path=tmp_path / "audit.jsonl",
        audit_ship_destination=ship_dest,
        secrets_dir=secrets,
        isolation_declared=True,
        egress_configured=True,
        known_tools=frozenset({"web.fetch"}),
    )
    assert isinstance(host, EnterpriseHost)
    assert host.checklist.ok()
    assert host.broker.require_host_gate is True
    assert host.broker.enterprise_profile is True
    assert host.broker.require_signed_intent is True
    assert host.broker.host_checklist is host.checklist
    assert isinstance(host.secret_provider, FileSecretProvider)
    assert isinstance(host.shipper, FileAuditShipper)
    assert host.proxy_url is None
    assert host.rate_limit is None
    assert isinstance(host.egress_provider, PinnedEgressProvider)
    assert host.checklist.egress_provider is host.egress_provider
    assert host.checklist.egress_configured is True


def test_proxy_url_sets_egress_and_hint(tmp_path: Path) -> None:
    secrets = _secrets(tmp_path)
    host = build_enterprise_host(
        policy_path=POLICY_PATH,
        audit_path=tmp_path / "audit.jsonl",
        audit_ship_destination=tmp_path / "ship.jsonl",
        secret_provider=FileSecretProvider(secrets),
        isolation_declared=True,
        egress_configured=False,
        proxy_url="http://127.0.0.1:8888",
    )
    assert host.checklist.ok()
    assert host.proxy_url == "http://127.0.0.1:8888"
    assert isinstance(host.egress_provider, ProxyEgressProvider)


def test_rate_limit_wired(tmp_path: Path) -> None:
    secrets = _secrets(tmp_path)
    gate = TokenBucketRateLimit(rate=1.0, capacity=2.0)
    host = build_enterprise_host(
        policy_path=POLICY_PATH,
        audit_path=tmp_path / "a.jsonl",
        audit_ship_destination=tmp_path / "s.jsonl",
        secrets_dir=secrets,
        isolation_declared=True,
        egress_configured=True,
        rate_limit=gate,
    )
    assert host.rate_limit is gate
    assert host.broker.rate_limit is gate


def test_rejects_missing_isolation(tmp_path: Path) -> None:
    secrets = _secrets(tmp_path)
    with pytest.raises(ValueError, match="isolation_declared"):
        build_enterprise_host(
            policy_path=POLICY_PATH,
            audit_path=tmp_path / "a.jsonl",
            audit_ship_destination=tmp_path / "s.jsonl",
            secrets_dir=secrets,
            isolation_declared=False,
            egress_configured=True,
        )


def test_rejects_missing_egress(tmp_path: Path) -> None:
    secrets = _secrets(tmp_path)
    with pytest.raises(ValueError, match="egress"):
        build_enterprise_host(
            policy_path=POLICY_PATH,
            audit_path=tmp_path / "a.jsonl",
            audit_ship_destination=tmp_path / "s.jsonl",
            secrets_dir=secrets,
            isolation_declared=True,
            egress_configured=False,
            proxy_url=None,
        )


def test_rejects_no_secret_backend(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="secret"):
        build_enterprise_host(
            policy_path=POLICY_PATH,
            audit_path=tmp_path / "a.jsonl",
            audit_ship_destination=tmp_path / "s.jsonl",
            isolation_declared=True,
            egress_configured=True,
        )


def test_rejects_multiple_secret_backends(tmp_path: Path) -> None:
    secrets = _secrets(tmp_path)
    with pytest.raises(ValueError, match="only one"):
        build_enterprise_host(
            policy_path=POLICY_PATH,
            audit_path=tmp_path / "a.jsonl",
            audit_ship_destination=tmp_path / "s.jsonl",
            secrets_dir=secrets,
            secrets_env_prefix="CONTAINMENT_SECRET_",
            isolation_declared=True,
            egress_configured=True,
        )



def test_explicit_egress_provider(tmp_path: Path) -> None:
    secrets = _secrets(tmp_path)
    ep = ProxyEgressProvider("http://127.0.0.1:9999")
    host = build_enterprise_host(
        policy_path=POLICY_PATH,
        audit_path=tmp_path / "a.jsonl",
        audit_ship_destination=tmp_path / "s.jsonl",
        secrets_dir=secrets,
        isolation_declared=True,
        egress_provider=ep,
    )
    assert host.egress_provider is ep
    assert host.proxy_url == "http://127.0.0.1:9999"
