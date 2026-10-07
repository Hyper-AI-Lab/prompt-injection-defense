"""One-use capability tokens for sandboxed tool execution."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass

from containment.capability_store import CapabilityConsumeStore, MemoryConsumeStore


class CapabilityError(Exception):
    """Raised when a capability cannot be minted or verified."""


@dataclass(frozen=True, slots=True)
class CapabilityToken:
    """Opaque one-use authorization for a single tool invocation."""

    token_id: str
    tool: str
    resources: tuple[str, ...]
    expiry_unix: float
    mac: str


class CapabilityMinter:
    """Mints and verifies HMAC-bound one-use capability tokens."""

    def __init__(
        self,
        secret: bytes | None = None,
        *,
        store: CapabilityConsumeStore | None = None,
    ) -> None:
        self._secret = secret if secret is not None else os.urandom(32)
        self._store: CapabilityConsumeStore = store or MemoryConsumeStore()

    def one_use(
        self,
        *,
        tool: str,
        resources: tuple[str, ...] = (),
        expiry_seconds: float = 60.0,
        now: float | None = None,
    ) -> CapabilityToken:
        if not tool or not str(tool).strip():
            raise CapabilityError("tool must be a non-empty string")
        if expiry_seconds <= 0:
            raise CapabilityError("expiry_seconds must be positive")
        if not isinstance(resources, tuple):
            raise TypeError("resources must be a tuple[str, ...]")
        for item in resources:
            if not isinstance(item, str):
                raise TypeError("resources items must be str")
        stamp = time.time() if now is None else now
        token_id = secrets.token_urlsafe(16)
        expiry_unix = stamp + float(expiry_seconds)
        mac = self._mac(token_id, tool, resources, expiry_unix)
        return CapabilityToken(
            token_id=token_id,
            tool=tool,
            resources=resources,
            expiry_unix=expiry_unix,
            mac=mac,
        )

    def matches_secret(self, other: bytes) -> bool:
        """Constant-time compare of ``other`` to the minter HMAC secret."""
        if not isinstance(other, (bytes, bytearray)):
            return False
        return hmac.compare_digest(bytes(other), self._secret)

    def verify(
        self,
        token: CapabilityToken,
        *,
        tool: str,
        resources: tuple[str, ...] | None = None,
        now: float | None = None,
    ) -> None:
        """Verify and consume the token. Second use raises CapabilityError."""
        if not isinstance(token, CapabilityToken):
            raise CapabilityError("invalid token type")
        stamp = time.time() if now is None else now
        expected = self._mac(
            token.token_id, token.tool, token.resources, token.expiry_unix
        )
        if not hmac.compare_digest(token.mac, expected):
            raise CapabilityError("capability MAC invalid")
        if token.tool != tool:
            raise CapabilityError("capability tool mismatch")
        if resources is not None and token.resources != resources:
            raise CapabilityError("capability resources mismatch")
        if stamp > token.expiry_unix:
            raise CapabilityError("capability expired")
        if not self._store.try_consume(token.token_id, expiry_unix=token.expiry_unix):
            raise CapabilityError("capability already used")

    def _mac(
        self,
        token_id: str,
        tool: str,
        resources: tuple[str, ...],
        expiry_unix: float,
    ) -> str:
        # JSON-array encoding avoids comma-join delimiter collisions (L2).
        resources_enc = json.dumps(list(resources), separators=(",", ":"), ensure_ascii=False)
        payload = "|".join(
            [token_id, tool, resources_enc, f"{expiry_unix:.6f}"]
        ).encode("utf-8")
        digest = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return digest
