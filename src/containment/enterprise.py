"""Compose an enterprise host: secrets, checklist, broker, egress provider."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from containment.audit import AuditLog
from containment.broker import ToolBroker
from containment.capability import CapabilityMinter
from containment.capability_store import CapabilityConsumeStore
from containment.host.audit_ship import AuditShipper, FileAuditShipper
from containment.host.checklist import HostChecklist
from containment.host.egress import (
    EgressProvider,
    PinnedEgressProvider,
    ProxyEgressProvider,
)
from containment.host.rate_limit import RateLimitGate
from containment.host.secrets import (
    EnvSecretProvider,
    FileSecretProvider,
    SecretProvider,
)
from containment.intent import IntentSigner, IntentVerifier
from containment.policy import PolicyEngine


@dataclass(frozen=True, slots=True)
class EnterpriseHost:
    """Wired enterprise stack returned by ``build_enterprise_host``."""

    policy: PolicyEngine
    audit: AuditLog
    shipper: AuditShipper
    secret_provider: SecretProvider
    checklist: HostChecklist
    broker: ToolBroker
    minter: CapabilityMinter
    intent_signer: IntentVerifier
    rate_limit: RateLimitGate | None
    proxy_url: str | None
    egress_provider: EgressProvider


def _resolve_secret_provider(
    *,
    secret_provider: SecretProvider | None,
    secrets_dir: Path | str | None,
    secrets_env_prefix: str | None,
) -> SecretProvider:
    provided = sum(
        1
        for x in (secret_provider, secrets_dir, secrets_env_prefix)
        if x is not None
    )
    if provided == 0:
        raise ValueError(
            "provide secret_provider, secrets_dir, or secrets_env_prefix "
            "(no hardcoded production secrets)"
        )
    if provided > 1:
        raise ValueError(
            "pass only one of secret_provider, secrets_dir, secrets_env_prefix"
        )
    if secret_provider is not None:
        return secret_provider
    if secrets_dir is not None:
        return FileSecretProvider(secrets_dir)
    assert secrets_env_prefix is not None
    return EnvSecretProvider(prefix=secrets_env_prefix)


def _resolve_egress_provider(
    *,
    egress_provider: EgressProvider | None,
    proxy_url: str | None,
    egress_configured: bool,
) -> EgressProvider:
    """Require a real provider: explicit, from proxy_url, or pinned flag."""
    if egress_provider is not None:
        return egress_provider
    if proxy_url is not None and str(proxy_url).strip():
        return ProxyEgressProvider(str(proxy_url).strip())
    if egress_configured:
        return PinnedEgressProvider()
    raise ValueError(
        "pass egress_provider=, proxy_url=, or egress_configured=True "
        "(pinned); a boolean checklist lie without a provider is rejected"
    )


def build_enterprise_host(
    *,
    policy_path: Path | str,
    audit_path: Path | str,
    audit_ship_destination: Path | str,
    secret_provider: SecretProvider | None = None,
    secrets_dir: Path | str | None = None,
    secrets_env_prefix: str | None = None,
    isolation_declared: bool = False,
    egress_provider: EgressProvider | None = None,
    egress_configured: bool = False,
    proxy_url: str | None = None,
    capability_secret_name: str = "capability",
    intent_secret_name: str = "intent",
    intent_signer: IntentVerifier | None = None,
    rate_limit: RateLimitGate | None = None,
    known_tools: frozenset[str] | None = None,
    consume_store: CapabilityConsumeStore | None = None,
) -> EnterpriseHost:
    """Build a fail-closed enterprise host composition.

    Caller must declare OS/container isolation (``isolation_declared=True``)
    and supply egress via ``egress_provider``, ``proxy_url``, or
    ``egress_configured=True`` (constructs ``PinnedEgressProvider``).
    Secrets come from a ``SecretProvider`` (env or file); this factory never
    embeds production HMAC material.

    Raises ``ValueError`` if the host checklist is incomplete.
    """
    provider = _resolve_secret_provider(
        secret_provider=secret_provider,
        secrets_dir=secrets_dir,
        secrets_env_prefix=secrets_env_prefix,
    )
    if not isolation_declared:
        raise ValueError(
            "isolation_declared must be True "
            "(host must declare OS/container isolation)"
        )
    ep = _resolve_egress_provider(
        egress_provider=egress_provider,
        proxy_url=proxy_url,
        egress_configured=egress_configured,
    )

    shipper: AuditShipper = FileAuditShipper(audit_ship_destination)
    checklist = HostChecklist(
        isolation_declared=True,
        secret_provider=provider,
        egress_provider=ep,
        audit_shipper=shipper,
        capability_secret_name=capability_secret_name,
    )
    if not checklist.ok():
        codes = ",".join(checklist.failures())
        raise ValueError(f"host checklist failed: {codes}")

    cap_secret = provider.get_bytes(capability_secret_name)
    minter = CapabilityMinter(secret=cap_secret, store=consume_store)

    signer: IntentVerifier
    if intent_signer is not None:
        signer = intent_signer
    else:
        signer = IntentSigner(provider.get_bytes(intent_secret_name))

    policy = PolicyEngine.from_yaml_path(policy_path)
    audit = AuditLog(audit_path)
    proxy = ep.proxy_url

    broker = ToolBroker(
        policy=policy,
        audit=audit,
        minter=minter,
        known_tools=known_tools,
        enterprise_profile=True,
        intent_signer=signer,
        host_checklist=checklist,
        rate_limit=rate_limit,
    )

    return EnterpriseHost(
        policy=policy,
        audit=audit,
        shipper=shipper,
        secret_provider=provider,
        checklist=checklist,
        broker=broker,
        minter=minter,
        intent_signer=signer,
        rate_limit=rate_limit,
        proxy_url=proxy,
        egress_provider=ep,
    )
