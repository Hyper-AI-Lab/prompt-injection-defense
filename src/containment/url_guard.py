"""SSRF / egress URL helpers (no DNS; literal checks only)."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Set
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


class UrlGuardError(ValueError):
    """URL failed an egress/SSRF guard check."""

    def __init__(self, reason: str, *, code: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


@dataclass(frozen=True, slots=True)
class ParsedEgressUrl:
    scheme: str
    host: str
    port: int | None
    path: str


_DECIMAL_HOST = re.compile(r"^\d{1,10}$")
_OCTAL_LIKE = re.compile(r"^0[0-7]+$")


def parse_egress_url(
    url: str,
    *,
    allowed_schemes: frozenset[str] = frozenset({"https"}),
) -> ParsedEgressUrl:
    if not isinstance(url, str) or not url.strip():
        raise UrlGuardError("empty url", code="empty_url")
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in allowed_schemes:
        raise UrlGuardError(f"bad scheme {scheme!r}", code="bad_scheme")
    if parsed.username is not None or parsed.password is not None:
        raise UrlGuardError("userinfo not allowed", code="userinfo")
    host = parsed.hostname
    if host is None or not str(host).strip():
        raise UrlGuardError("empty host", code="empty_host")
    host_norm = host.lower().rstrip(".")
    return ParsedEgressUrl(
        scheme=scheme,
        host=host_norm,
        port=parsed.port,
        path=parsed.path or "",
    )


def host_in_allowlist(host: str, allowlist: Set[str]) -> bool:
    return host.lower().rstrip(".") in allowlist


def _octet_int(part: str) -> int:
    if _OCTAL_LIKE.match(part) or (part.startswith("0") and len(part) > 1):
        return int(part, 8)
    return int(part, 10)


def _try_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse host as IP, including decimal / odd literal forms."""
    lowered = host.lower().rstrip(".")
    if lowered.startswith("[") and lowered.endswith("]"):
        lowered = lowered[1:-1]
    try:
        return ipaddress.ip_address(lowered)
    except ValueError:
        pass
    if _DECIMAL_HOST.match(lowered):
        try:
            return ipaddress.IPv4Address(int(lowered))
        except (ValueError, OverflowError):
            return None
    if _OCTAL_LIKE.match(lowered):
        try:
            return ipaddress.IPv4Address(int(lowered, 8))
        except (ValueError, OverflowError):
            return None
    parts = lowered.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            octets = [_octet_int(p) for p in parts]
            if all(0 <= o <= 255 for o in octets):
                return ipaddress.IPv4Address(".".join(str(o) for o in octets))
        except (ValueError, OverflowError):
            return None
    return None


def is_blocked_ip_literal(host: str) -> bool:
    """True for localhost aliases and non-public IP literals (incl. odd forms).

    IP deny checks (incl. CGNAT) go through ``egress_resolve.ip_is_denied``.
    """
    lowered = host.lower().rstrip(".")
    if lowered in {"localhost", "localhost.localdomain", "metadata.google.internal"}:
        return True
    ip = _try_ip(lowered)
    if ip is None:
        return False
    # Lazy import avoids circular import at module load
    # (egress_resolve imports parse helpers from this module).
    from containment.egress_resolve import ip_is_denied

    return ip_is_denied(ip)


def check_public_only(url: str) -> None:
    parsed = parse_egress_url(url, allowed_schemes=frozenset({"http", "https"}))
    if is_blocked_ip_literal(parsed.host):
        raise UrlGuardError(
            "network public_only: URL host is not a public address",
            code="not_public",
        )


def check_redirect_args(args: Mapping[str, Any], *, max_redirects: int) -> None:
    if max_redirects < 0:
        raise UrlGuardError("redirects must be >= 0", code="redirects_exceeded")
    for key in ("redirects", "max_redirects"):
        if key in args:
            raw = args[key]
            if isinstance(raw, (int, float)) and int(raw) > max_redirects:
                raise UrlGuardError(
                    f"argument {key!r} exceeds policy redirects {max_redirects}",
                    code="redirects_exceeded",
                )
    if "allow_redirects" in args and bool(args["allow_redirects"]):
        if max_redirects <= 0:
            raise UrlGuardError(
                "allow_redirects true violates redirects <= 0",
                code="redirects_exceeded",
            )


def check_url_for_tool(
    url: str,
    *,
    schemes: frozenset[str] = frozenset({"https"}),
    host_allowlist: Set[str] | None = None,
    network: str | None = None,
) -> ParsedEgressUrl:
    parsed = parse_egress_url(url, allowed_schemes=schemes)
    if host_allowlist is not None and not host_in_allowlist(parsed.host, host_allowlist):
        raise UrlGuardError(
            f"host {parsed.host!r} not in allowlist",
            code="host_not_allowlisted",
        )
    if network == "public_only" and is_blocked_ip_literal(parsed.host):
        raise UrlGuardError(
            "network public_only: URL host is not a public address",
            code="not_public",
        )
    if network is not None and network != "public_only":
        raise UrlGuardError(
            f"unsupported network limit {network!r}",
            code="unenforced_limit",
        )
    return parsed
