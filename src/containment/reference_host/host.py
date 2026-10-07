"""Reference host: enterprise compose + BrokeredRegistry + demo tools."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from containment.adapters import BrokeredRegistry
from containment.broker import ApprovalHook, ApprovalOutcome
from containment.enterprise import EnterpriseHost, build_enterprise_host
from containment.intent import IntentSigner, SignedIntent
from containment.labels import SecurityLabel
from containment.plan import IntentEnvelope, Plan, PlanStep

_PKG_ROOT = Path(__file__).resolve().parent
_REPO_ROOT = _PKG_ROOT.parents[2]
_DEFAULT_POLICY = _REPO_ROOT / "policies" / "default_deny.yaml"
_FIXTURES = _PKG_ROOT / "fixtures"

TASK_ID = "ref-host-demo"
PRINCIPAL = "operator"
TENANT = "demo"
APPROVED_RECIPIENT = "alice@acme.test"
APPROVED_HOST = "example.com"

STEP_FETCH = "s_fetch"
STEP_EMAIL = "s_email"


def fixture_dir() -> Path:
    """Directory containing packaged scenario fixture texts."""
    return _FIXTURES


def load_fixture(name: str) -> str:
    """Load a fixture text file by basename (e.g. ``attack_inject.txt``)."""
    path = _FIXTURES / name
    if not path.is_file():
        raise FileNotFoundError(f"reference host fixture missing: {path}")
    return path.read_text(encoding="utf-8")


def default_policy_path() -> Path:
    """Path to ``policies/default_deny.yaml`` in the repo checkout."""
    if _DEFAULT_POLICY.is_file():
        return _DEFAULT_POLICY
    raise FileNotFoundError(
        f"default policy not found at {_DEFAULT_POLICY}; "
        "pass policy_path= to build_reference_host"
    )


@dataclass(frozen=True, slots=True)
class ReferenceHostConfig:
    """Immutable knobs for the reference host demo."""

    policy_path: Path | None = None
    task_id: str = TASK_ID
    tenant: str = TENANT
    user: str = PRINCIPAL
    approved_public_hosts: frozenset[str] = frozenset({APPROVED_HOST})
    approved_recipients: frozenset[str] = frozenset({APPROVED_RECIPIENT})
    capabilities: frozenset[str] = frozenset({"web.fetch", "email.send"})
    isolation_declared: bool = True
    egress_configured: bool = True


@dataclass(slots=True)
class ReferenceHost:
    """Wired demo host: EnterpriseHost + plan + BrokeredRegistry + stubs."""

    work_dir: Path
    config: ReferenceHostConfig
    enterprise: EnterpriseHost
    plan: Plan
    registry: BrokeredRegistry
    fetch_log: list[dict[str, Any]] = field(default_factory=list)
    send_log: list[dict[str, Any]] = field(default_factory=list)

    @property
    def broker(self):
        return self.enterprise.broker

    @property
    def audit(self):
        return self.enterprise.audit

    @property
    def intent_signer(self) -> IntentSigner:
        signer = self.enterprise.intent_signer
        if not isinstance(signer, IntentSigner):
            raise TypeError(
                "reference host requires IntentSigner (HMAC) for demo signing; "
                f"got {type(signer).__name__}"
            )
        return signer

    def envelope(
        self,
        *,
        scope: frozenset[str] | None = None,
        risk_budget: str = "low",
        principal_authenticated: bool = True,
    ) -> IntentEnvelope:
        caps = scope if scope is not None else self.plan.capabilities
        return IntentEnvelope(
            task_id=self.plan.task_id,
            tenant=self.config.tenant,
            user=self.config.user,
            scope=frozenset(caps),
            risk_budget=risk_budget,
            principal_authenticated=principal_authenticated,
        )

    def sign_intent(
        self,
        *,
        scope: frozenset[str] | None = None,
        ttl_seconds: float = 3600.0,
        plan: Plan | None = None,
    ) -> SignedIntent:
        """Sign an IntentEnvelope bound to the host plan (enterprise gate)."""
        resolved = plan if plan is not None else self.plan
        return self.intent_signer.sign(
            self.envelope(scope=scope if scope is not None else resolved.capabilities),
            plan=resolved,
            ttl_seconds=ttl_seconds,
        )

    def trusted_label(self, *, source: str = "user") -> SecurityLabel:
        return SecurityLabel(
            integrity="trusted",
            confidentiality="private",
            source=source,
            task_id=self.plan.task_id,
        )

    def untrusted_label(self, *, source: str = "web") -> SecurityLabel:
        return SecurityLabel(
            integrity="untrusted",
            confidentiality="public",
            source=source,
            task_id=self.plan.task_id,
        )

    def set_approval(self, hook: ApprovalHook | None) -> None:
        """Install or clear the broker human-approval hook."""
        if hook is None:
            from containment.broker import default_approval_hook

            self.broker.approval = default_approval_hook
        else:
            self.broker.approval = hook

    def approve_all(self) -> None:
        """Install a hook that approves require_human without MFA."""

        def _hook(action, decision) -> ApprovalOutcome:
            del action, decision
            return ApprovalOutcome(mfa_verified=False)

        self.set_approval(_hook)

    def call(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        input_labels: tuple[SecurityLabel, ...],
        plan_step: str,
        intent: SignedIntent | None = None,
        **broker_kwargs: Any,
    ) -> Any:
        """Invoke a registered tool through the broker with a signed intent."""
        signed = intent if intent is not None else self.sign_intent()
        return self.registry.call(
            name,
            arguments,
            input_labels=input_labels,
            plan_step=plan_step,
            intent=signed,
            **broker_kwargs,
        )

    def audit_decisions(self) -> list[dict[str, Any]]:
        """Return decision payloads from the audit log (newest last)."""
        out: list[dict[str, Any]] = []
        for event in self.audit.read_all():
            detail = event.detail
            if not isinstance(detail, Mapping):
                continue
            decision = detail.get("decision")
            if isinstance(decision, Mapping):
                out.append(dict(decision))
        return out


def _ensure_secrets(work_dir: Path) -> Path:
    secrets = work_dir / "secrets"
    secrets.mkdir(parents=True, exist_ok=True)
    cap = secrets / "capability"
    intent = secrets / "intent"
    if not cap.is_file() or cap.stat().st_size < 32:
        cap.write_bytes(b"c" * 32)
    if not intent.is_file() or intent.stat().st_size < 32:
        intent.write_bytes(b"i" * 32)
    return secrets


def _demo_plan(config: ReferenceHostConfig) -> Plan:
    return Plan(
        task_id=config.task_id,
        steps=(
            PlanStep(
                step_id=STEP_FETCH,
                tool="web.fetch",
                description="Hermetic public HTTPS fetch stub",
            ),
            PlanStep(
                step_id=STEP_EMAIL,
                tool="email.send",
                description="Recorded email send stub (privileged)",
            ),
        ),
        capabilities=frozenset(config.capabilities),
        approved_public_hosts=frozenset(config.approved_public_hosts),
        approved_recipients=frozenset(config.approved_recipients),
    )


def build_reference_host(
    work_dir: Path | str,
    *,
    config: ReferenceHostConfig | None = None,
) -> ReferenceHost:
    """Compose enterprise host + registry + hermetic demo tool stubs.

    ``work_dir`` holds ``secrets/``, ``audit.jsonl``, and ``audit-shipped.jsonl``.
    Isolation is declared for the demo (honor-system residual — see docs).
    """
    root = Path(work_dir)
    root.mkdir(parents=True, exist_ok=True)
    cfg = config if config is not None else ReferenceHostConfig()
    policy = cfg.policy_path if cfg.policy_path is not None else default_policy_path()
    secrets = _ensure_secrets(root)
    audit_path = root / "audit.jsonl"
    ship_path = root / "audit-shipped.jsonl"

    enterprise = build_enterprise_host(
        policy_path=policy,
        audit_path=audit_path,
        audit_ship_destination=ship_path,
        secrets_dir=secrets,
        isolation_declared=cfg.isolation_declared,
        egress_configured=cfg.egress_configured,
        known_tools=frozenset(cfg.capabilities),
    )
    plan = _demo_plan(cfg)
    host = ReferenceHost(
        work_dir=root,
        config=cfg,
        enterprise=enterprise,
        plan=plan,
        registry=BrokeredRegistry(
            enterprise.broker,
            plan,
            principal=cfg.user,
            task_id=cfg.task_id,
            reason_code="reference_host",
            plan_step=STEP_FETCH,
        ),
    )

    def web_fetch(*, url: str, **_kwargs: Any) -> str:
        record = {"url": url}
        host.fetch_log.append(record)
        return f"[hermetic-fetch] ok body for {url}"

    def email_send(
        *,
        recipient: str,
        subject: str = "",
        body: str = "",
        **_kwargs: Any,
    ) -> str:
        record = {"recipient": recipient, "subject": subject, "body": body}
        host.send_log.append(record)
        return f"[hermetic-send] queued to {recipient}"

    host.registry.register("web.fetch", web_fetch)
    host.registry.register("email.send", email_send)
    return host


__all__ = [
    "APPROVED_HOST",
    "APPROVED_RECIPIENT",
    "PRINCIPAL",
    "STEP_EMAIL",
    "STEP_FETCH",
    "TASK_ID",
    "TENANT",
    "ReferenceHost",
    "ReferenceHostConfig",
    "build_reference_host",
    "default_policy_path",
    "fixture_dir",
    "load_fixture",
]
