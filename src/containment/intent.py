"""HMAC-signed IntentEnvelope (enterprise profile)."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

from containment.plan import IntentEnvelope, Plan


class IntentError(Exception):
    """Raised when an intent cannot be signed or verified."""


def plan_hash(plan: Plan) -> str:
    """Stable SHA-256 hex digest of canonical plan fields."""
    payload = {
        "task_id": plan.task_id,
        "steps": [
            {"step_id": s.step_id, "tool": s.tool, "description": s.description}
            for s in plan.steps
        ],
        "capabilities": sorted(plan.capabilities),
        "approved_recipients": sorted(plan.approved_recipients),
        "approved_wallets": sorted(plan.approved_wallets),
        "approved_public_hosts": sorted(plan.approved_public_hosts),
        "transaction_limit": plan.transaction_limit,
        "expiry_unix": plan.expiry_unix,
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SignedIntent:
    """IntentEnvelope plus HMAC binding fields."""

    envelope: IntentEnvelope
    issued_at_unix: float
    expiry_unix: float
    nonce: str
    plan_hash: str
    mac: str
    alg: str = "hmac-sha256"
    key_id: str = "default"


class IntentSigner:
    """Signs IntentEnvelope with HMAC-SHA256 over bound fields."""

    def __init__(self, secret: bytes, *, key_id: str = "default") -> None:
        if not secret:
            raise IntentError("secret must be non-empty")
        self._secret = secret
        self.key_id = key_id

    def sign(
        self,
        envelope: IntentEnvelope,
        *,
        plan: Plan,
        ttl_seconds: float = 3600.0,
        now: float | None = None,
        nonce: str | None = None,
    ) -> SignedIntent:
        if ttl_seconds <= 0:
            raise IntentError("ttl_seconds must be positive")
        if envelope.task_id != plan.task_id:
            raise IntentError("envelope.task_id must match plan.task_id")
        stamp = time.time() if now is None else now
        ph = plan_hash(plan)
        signed = SignedIntent(
            envelope=envelope,
            issued_at_unix=stamp,
            expiry_unix=stamp + float(ttl_seconds),
            nonce=nonce if nonce is not None else secrets.token_urlsafe(16),
            plan_hash=ph,
            mac="",
            alg="hmac-sha256",
            key_id=self.key_id,
        )
        mac = self._mac(signed)
        return SignedIntent(
            envelope=envelope,
            issued_at_unix=signed.issued_at_unix,
            expiry_unix=signed.expiry_unix,
            nonce=signed.nonce,
            plan_hash=ph,
            mac=mac,
            alg=signed.alg,
            key_id=signed.key_id,
        )

    def verify(
        self,
        signed: SignedIntent,
        *,
        plan: Plan,
        now: float | None = None,
    ) -> IntentEnvelope:
        if not isinstance(signed, SignedIntent):
            raise IntentError("invalid signed intent type")
        if signed.alg != "hmac-sha256":
            raise IntentError(f"unsupported alg {signed.alg!r}")
        stamp = time.time() if now is None else now
        if stamp > signed.expiry_unix:
            raise IntentError("intent expired")
        if stamp < signed.issued_at_unix:
            raise IntentError("intent not yet valid")
        expected = self._mac(signed)
        if not hmac.compare_digest(signed.mac, expected):
            raise IntentError("intent MAC invalid")
        env = signed.envelope
        if env.task_id != plan.task_id:
            raise IntentError("intent task_id mismatch")
        if signed.plan_hash != plan_hash(plan):
            raise IntentError("intent plan_hash mismatch")
        missing = plan.capabilities - env.scope
        if missing:
            raise IntentError(
                f"plan capabilities not in intent scope: {sorted(missing)}"
            )
        return env

    def _mac(self, signed: SignedIntent) -> str:
        env = signed.envelope
        payload = {
            "alg": signed.alg,
            "key_id": signed.key_id,
            "task_id": env.task_id,
            "tenant": env.tenant,
            "user": env.user,
            "scope": sorted(env.scope),
            "risk_budget": env.risk_budget,
            "principal_authenticated": env.principal_authenticated,
            "issued_at_unix": f"{signed.issued_at_unix:.6f}",
            "expiry_unix": f"{signed.expiry_unix:.6f}",
            "nonce": signed.nonce,
            "plan_hash": signed.plan_hash,
        }
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
        return hmac.new(self._secret, raw.encode("utf-8"), hashlib.sha256).hexdigest()
