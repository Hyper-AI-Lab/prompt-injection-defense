"""Signed IntentEnvelope: HMAC-SHA256 and optional Ed25519."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

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
    """IntentEnvelope plus authenticity binding fields.

    ``mac`` holds an opaque authenticator: HMAC-SHA256 hex for
    ``alg="hmac-sha256"``, or Ed25519 signature hex for ``alg="ed25519"``.
    """

    envelope: IntentEnvelope
    issued_at_unix: float
    expiry_unix: float
    nonce: str
    plan_hash: str
    mac: str
    alg: str = "hmac-sha256"
    key_id: str = "default"


def intent_payload_bytes(signed: SignedIntent) -> bytes:
    """Canonical UTF-8 JSON bytes bound by HMAC or Ed25519."""
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
    return json.dumps(
        payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True
    ).encode("utf-8")


def _check_intent_time(signed: SignedIntent, *, now: float | None) -> None:
    """Reject expired or not-yet-valid intents (same order as historical HMAC)."""
    stamp = time.time() if now is None else now
    if stamp > signed.expiry_unix:
        raise IntentError("intent expired")
    if stamp < signed.issued_at_unix:
        raise IntentError("intent not yet valid")


def _check_intent_plan_binding(signed: SignedIntent, *, plan: Plan) -> IntentEnvelope:
    """Task / plan_hash / scope binding after authenticator verifies."""
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


@runtime_checkable
class IntentVerifier(Protocol):
    """Broker-facing verify surface; HMAC and Ed25519 signers both satisfy."""

    def verify(
        self,
        signed: SignedIntent,
        *,
        plan: Plan,
        now: float | None = None,
    ) -> IntentEnvelope: ...


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
        _check_intent_time(signed, now=now)
        expected = self._mac(signed)
        if not hmac.compare_digest(signed.mac, expected):
            raise IntentError("intent MAC invalid")
        return _check_intent_plan_binding(signed, plan=plan)

    def _mac(self, signed: SignedIntent) -> str:
        return hmac.new(
            self._secret, intent_payload_bytes(signed), hashlib.sha256
        ).hexdigest()


class Ed25519IntentSigner:
    """Signs and verifies intents with Ed25519 (optional ``cryptography`` extra).

    Prefer public-only construction on the broker verify path. Signing requires
    a private key. Install with ``pip install containment[crypto]``.
    """

    ALG = "ed25519"

    def __init__(
        self,
        private_key: bytes | object | None = None,
        *,
        public_key: bytes | object | None = None,
        key_id: str = "default",
    ) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
                Ed25519PublicKey,
            )
        except ImportError as exc:
            raise IntentError(
                "Ed25519IntentSigner requires the cryptography package; "
                'install with pip install "containment[crypto]"'
            ) from exc

        self.key_id = key_id
        self._private: Ed25519PrivateKey | None = None
        self._public: Ed25519PublicKey | None = None

        if private_key is not None:
            if isinstance(private_key, Ed25519PrivateKey):
                self._private = private_key
            elif isinstance(private_key, (bytes, bytearray)):
                raw = bytes(private_key)
                if len(raw) != 32:
                    raise IntentError(
                        "Ed25519 private_key bytes must be 32 raw seed bytes"
                    )
                self._private = Ed25519PrivateKey.from_private_bytes(raw)
            else:
                raise IntentError("unsupported Ed25519 private_key type")
            self._public = self._private.public_key()

        if public_key is not None:
            if isinstance(public_key, Ed25519PublicKey):
                pub = public_key
            elif isinstance(public_key, (bytes, bytearray)):
                raw = bytes(public_key)
                if len(raw) != 32:
                    raise IntentError(
                        "Ed25519 public_key bytes must be 32 raw public bytes"
                    )
                pub = Ed25519PublicKey.from_public_bytes(raw)
            else:
                raise IntentError("unsupported Ed25519 public_key type")
            if self._public is not None:
                if self._public.public_bytes_raw() != pub.public_bytes_raw():
                    raise IntentError(
                        "public_key does not match private_key public half"
                    )
            else:
                self._public = pub

        if self._public is None:
            raise IntentError(
                "Ed25519IntentSigner requires private_key and/or public_key"
            )

    @classmethod
    def generate(cls, *, key_id: str = "default") -> Ed25519IntentSigner:
        """Create a signer with a fresh Ed25519 keypair (needs cryptography)."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError as exc:
            raise IntentError(
                "Ed25519IntentSigner requires the cryptography package; "
                'install with pip install "containment[crypto]"'
            ) from exc
        return cls(Ed25519PrivateKey.generate(), key_id=key_id)

    def public_bytes(self) -> bytes:
        """Raw 32-byte public key (for verify-only broker wiring)."""
        assert self._public is not None
        return self._public.public_bytes_raw()

    def sign(
        self,
        envelope: IntentEnvelope,
        *,
        plan: Plan,
        ttl_seconds: float = 3600.0,
        now: float | None = None,
        nonce: str | None = None,
    ) -> SignedIntent:
        if self._private is None:
            raise IntentError("Ed25519 sign requires a private key")
        if ttl_seconds <= 0:
            raise IntentError("ttl_seconds must be positive")
        if envelope.task_id != plan.task_id:
            raise IntentError("envelope.task_id must match plan.task_id")
        stamp = time.time() if now is None else now
        ph = plan_hash(plan)
        unsigned = SignedIntent(
            envelope=envelope,
            issued_at_unix=stamp,
            expiry_unix=stamp + float(ttl_seconds),
            nonce=nonce if nonce is not None else secrets.token_urlsafe(16),
            plan_hash=ph,
            mac="",
            alg=self.ALG,
            key_id=self.key_id,
        )
        sig = self._private.sign(intent_payload_bytes(unsigned))
        return SignedIntent(
            envelope=envelope,
            issued_at_unix=unsigned.issued_at_unix,
            expiry_unix=unsigned.expiry_unix,
            nonce=unsigned.nonce,
            plan_hash=ph,
            mac=sig.hex(),
            alg=self.ALG,
            key_id=self.key_id,
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
        if signed.alg != self.ALG:
            raise IntentError(f"unsupported alg {signed.alg!r}")
        _check_intent_time(signed, now=now)
        assert self._public is not None
        try:
            sig = bytes.fromhex(signed.mac)
        except ValueError as exc:
            raise IntentError("intent MAC invalid") from exc
        try:
            self._public.verify(sig, intent_payload_bytes(signed))
        except Exception as exc:
            raise IntentError("intent MAC invalid") from exc
        return _check_intent_plan_binding(signed, plan=plan)
