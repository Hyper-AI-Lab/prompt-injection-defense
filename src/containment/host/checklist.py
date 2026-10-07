"""Host residual checklist (fail-closed when incomplete under HostGate)."""

from __future__ import annotations

from dataclasses import dataclass

from containment.host.audit_ship import AuditShipper
from containment.host.secrets import SecretProvider


@dataclass(frozen=True, slots=True)
class HostChecklist:
    """Declared host controls required for enterprise / require_host_gate.

    ``egress_configured`` is a bool in this step; later steps set it when an
    egress provider or proxy URL is present.
    """

    isolation_declared: bool
    secret_provider: SecretProvider | None
    egress_configured: bool
    audit_shipper: AuditShipper | None

    def ok(self) -> bool:
        return (
            self.isolation_declared
            and self.secret_provider is not None
            and self.egress_configured
            and self.audit_shipper is not None
        )

    def failures(self) -> tuple[str, ...]:
        codes: list[str] = []
        if not self.isolation_declared:
            codes.append("isolation_not_declared")
        if self.secret_provider is None:
            codes.append("secret_provider_missing")
        if not self.egress_configured:
            codes.append("egress_not_configured")
        if self.audit_shipper is None:
            codes.append("audit_shipper_missing")
        return tuple(codes)
