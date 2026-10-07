"""DNS resolve-then-pin helpers for SSRF-safe egress.

Literal ``url_guard`` checks alone cannot see hostname to private DNS answers.
This module resolves, denies if any answer is blocked (incl. CGNAT), and
returns a pin so callers connect to the IP only (Host/SNI keep the name).
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from collections.abc import Callable, Mapping, Sequence, Set
from dataclasses import dataclass

from containment.url_guard import (
    UrlGuardError,
    _try_ip,
    host_in_allowlist,
    parse_egress_url,
)

# Explicit deny table (do not rely on ipaddress.is_private alone: CGNAT is public).
_DENY_CIDRS: tuple[str, ...] = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",  # CGNAT (is_private is False)
    "192.0.0.0/24",
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
    "2001:db8::/32",
)

DENY_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(c, strict=False) for c in _DENY_CIDRS
)

ResolverFn = Callable[[str, int], Sequence[tuple[int, str]]]
ConnectorFn = Callable[[str, int, float], socket.socket]


class DenyNetworkError(UrlGuardError):
    """Resolved or literal address hit a deny network (or resolve failed closed)."""


@dataclass(frozen=True, slots=True)
class ResolvedPin:
    hostname: str
    scheme: str
    port: int
    pinned_ip: str
    all_ips: tuple[str, ...]
    family: int


def ip_is_denied(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if ``ip`` must not be contacted (explicit table + legacy flags)."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip_is_denied(ip.ipv4_mapped)
    for net in DENY_NETWORKS:
        if isinstance(ip, ipaddress.IPv4Address) and net.version != 4:
            continue
        if isinstance(ip, ipaddress.IPv6Address) and net.version != 6:
            continue
        if ip in net:
            return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
    )


def _default_port(scheme: str, port: int | None) -> int:
    if port is not None:
        return port
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    raise DenyNetworkError(f"no default port for scheme {scheme!r}", code="bad_scheme")


def _default_resolver(host: str, port: int) -> list[tuple[int, str]]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    out: list[tuple[int, str]] = []
    seen: set[str] = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        ip_s = sockaddr[0]
        if ip_s in seen:
            continue
        seen.add(ip_s)
        out.append((family, ip_s))
    return out


def resolve_and_pin(
    url: str,
    *,
    allowed_schemes: frozenset[str] = frozenset({"https"}),
    host_allowlist: Set[str] | None = None,
    resolver: ResolverFn | None = None,
) -> ResolvedPin:
    """Parse URL, resolve DNS, deny if any answer is blocked, return a pin.

    Never returns a connect-by-name success: callers must dial ``pinned_ip``.
    """
    parsed = parse_egress_url(url, allowed_schemes=allowed_schemes)
    if host_allowlist is not None and not host_in_allowlist(parsed.host, host_allowlist):
        raise UrlGuardError(
            f"host {parsed.host!r} not in allowlist",
            code="host_not_allowlisted",
        )
    port = _default_port(parsed.scheme, parsed.port)
    literal = _try_ip(parsed.host)
    if literal is not None:
        if ip_is_denied(literal):
            raise DenyNetworkError(
                f"denied network for literal {literal}",
                code="denied_network",
            )
        family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
        ip_s = str(literal)
        return ResolvedPin(
            hostname=parsed.host,
            scheme=parsed.scheme,
            port=port,
            pinned_ip=ip_s,
            all_ips=(ip_s,),
            family=family,
        )

    resolve = resolver if resolver is not None else _default_resolver
    try:
        answers = list(resolve(parsed.host, port))
    except OSError as exc:
        raise DenyNetworkError(
            f"DNS resolve failed for {parsed.host!r}: {exc}",
            code="resolve_failed",
        ) from exc

    if not answers:
        raise DenyNetworkError(
            f"empty DNS answers for {parsed.host!r}",
            code="empty_answers",
        )

    all_ips: list[str] = []
    allowed: list[tuple[int, str]] = []
    any_denied = False
    for family, ip_s in answers:
        all_ips.append(ip_s)
        try:
            ip_obj = ipaddress.ip_address(ip_s)
        except ValueError as exc:
            raise DenyNetworkError(
                f"invalid resolved address {ip_s!r}",
                code="resolve_failed",
            ) from exc
        if ip_is_denied(ip_obj):
            any_denied = True
        else:
            allowed.append((family, ip_s))

    if any_denied:
        raise DenyNetworkError(
            f"denied network in DNS answers for {parsed.host!r}: {all_ips}",
            code="denied_network",
        )
    if not allowed:
        raise DenyNetworkError(
            f"no allowable DNS answers for {parsed.host!r}",
            code="denied_network",
        )

    family, pinned_ip = allowed[0]
    return ResolvedPin(
        hostname=parsed.host,
        scheme=parsed.scheme,
        port=port,
        pinned_ip=pinned_ip,
        all_ips=tuple(all_ips),
        family=family,
    )


def pinned_socket_connect(
    pin: ResolvedPin,
    *,
    timeout: float = 30.0,
    connector: ConnectorFn | None = None,
) -> socket.socket:
    """Connect to ``(pinned_ip, port)`` only (no hostname DNS)."""
    if connector is not None:
        return connector(pin.pinned_ip, pin.port, timeout)
    sock = socket.socket(pin.family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((pin.pinned_ip, pin.port))
    except OSError:
        sock.close()
        raise
    return sock


def open_pinned_urllib(
    pin: ResolvedPin,
    *,
    path: str = "/",
    timeout: float = 30.0,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    connector: ConnectorFn | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> http.client.HTTPResponse:
    """HTTP(S) request over a pinned socket; sets Host; SNI uses hostname."""
    sock = pinned_socket_connect(pin, timeout=timeout, connector=connector)
    try:
        if pin.scheme == "https":
            ctx = ssl_context if ssl_context is not None else ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=pin.hostname)
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                pin.hostname,
                pin.port,
                timeout=timeout,
                context=ctx,
            )
        elif pin.scheme == "http":
            conn = http.client.HTTPConnection(pin.hostname, pin.port, timeout=timeout)
        else:
            sock.close()
            raise DenyNetworkError(
                f"unsupported scheme {pin.scheme!r}",
                code="bad_scheme",
            )
        conn.sock = sock
        hdrs = {"Host": pin.hostname}
        if headers:
            hdrs.update(headers)
        conn.request(method, path or "/", body=body, headers=hdrs)
        return conn.getresponse()
    except BaseException:
        try:
            sock.close()
        except OSError:
            pass
        raise


pinned_urlopen = open_pinned_urllib


def pinned_http_url(pin: ResolvedPin, path: str = "/") -> str:
    """Absolute URL using pinned IP (caller must still set Host / SNI)."""
    host = pin.pinned_ip
    if pin.family == socket.AF_INET6:
        host = f"[{pin.pinned_ip}]"
    return f"{pin.scheme}://{host}:{pin.port}{path}"


__all__ = [
    "DENY_NETWORKS",
    "DenyNetworkError",
    "ResolvedPin",
    "ip_is_denied",
    "open_pinned_urllib",
    "pinned_http_url",
    "pinned_socket_connect",
    "pinned_urlopen",
    "resolve_and_pin",
]
