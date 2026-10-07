"""Egress provider: real proxy URL or pinned-client declaration."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class EgressProvider(Protocol):
    """Host-owned egress control surfaced to HostChecklist / HostGate."""

    @property
    def proxy_url(self) -> str | None:
        """Forward-proxy URL, or None when pin-only."""
        ...

    @property
    def mode(self) -> str:
        """Short mode label: ``proxy`` or ``pinned``."""
        ...


class ProxyEgressProvider:
    """Declare egress via an HTTP forward proxy (e.g. containment-egress-proxy)."""

    def __init__(self, url: str) -> None:
        cleaned = str(url).strip()
        if not cleaned:
            raise ValueError("proxy url must be a non-empty string")
        self._url = cleaned

    @property
    def proxy_url(self) -> str | None:
        return self._url

    @property
    def mode(self) -> str:
        return "proxy"


class PinnedEgressProvider:
    """Declare resolve-pin client egress (no forward proxy)."""

    @property
    def proxy_url(self) -> str | None:
        return None

    @property
    def mode(self) -> str:
        return "pinned"
