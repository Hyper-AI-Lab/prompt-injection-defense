"""Hermetic tests for egress_resolve (injected resolver; no real IMDS)."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

import pytest

from containment.egress_resolve import (
    DENY_NETWORKS,
    DenyNetworkError,
    ip_is_denied,
    pinned_socket_connect,
    resolve_and_pin,
)
from containment.url_guard import UrlGuardError, check_public_only, is_blocked_ip_literal


def _resolver(answers: list[tuple[int, str]]):
    def _fn(host: str, port: int) -> list[tuple[int, str]]:
        return list(answers)

    return _fn


def test_deny_table_includes_cgnat() -> None:
    nets = {str(n) for n in DENY_NETWORKS}
    assert "100.64.0.0/10" in nets
    assert ip_is_denied(ipaddress.ip_address("100.64.1.1")) is True
    # Python is_private is False for CGNAT; our table must still deny.
    assert ipaddress.ip_address("100.64.1.1").is_private is False


def test_ip_is_denied_imds_rfc1918_loopback_ula() -> None:
    assert ip_is_denied(ipaddress.ip_address("169.254.169.254")) is True
    assert ip_is_denied(ipaddress.ip_address("10.0.0.1")) is True
    assert ip_is_denied(ipaddress.ip_address("192.168.1.1")) is True
    assert ip_is_denied(ipaddress.ip_address("172.16.5.5")) is True
    assert ip_is_denied(ipaddress.ip_address("127.0.0.1")) is True
    assert ip_is_denied(ipaddress.ip_address("::1")) is True
    assert ip_is_denied(ipaddress.ip_address("fc00::1")) is True
    assert ip_is_denied(ipaddress.ip_address("fe80::1")) is True
    assert ip_is_denied(ipaddress.ip_address("8.8.8.8")) is False


def test_ipv4_mapped_cgnat_denied() -> None:
    assert ip_is_denied(ipaddress.ip_address("::ffff:100.64.1.1")) is True
    assert ip_is_denied(ipaddress.ip_address("::ffff:169.254.169.254")) is True


def test_resolve_denies_imds() -> None:
    with pytest.raises(DenyNetworkError) as ei:
        resolve_and_pin(
            "https://evil.example/",
            resolver=_resolver([(socket.AF_INET, "169.254.169.254")]),
        )
    assert ei.value.code == "denied_network"


def test_resolve_denies_rfc1918() -> None:
    with pytest.raises(DenyNetworkError) as ei:
        resolve_and_pin(
            "https://evil.example/",
            resolver=_resolver([(socket.AF_INET, "10.1.2.3")]),
        )
    assert ei.value.code == "denied_network"


def test_resolve_denies_loopback() -> None:
    with pytest.raises(DenyNetworkError):
        resolve_and_pin(
            "https://evil.example/",
            resolver=_resolver([(socket.AF_INET, "127.0.0.1")]),
        )


def test_resolve_denies_ula() -> None:
    with pytest.raises(DenyNetworkError):
        resolve_and_pin(
            "https://evil.example/",
            allowed_schemes=frozenset({"https"}),
            resolver=_resolver([(socket.AF_INET6, "fc00::abcd")]),
        )


def test_resolve_denies_cgnat() -> None:
    with pytest.raises(DenyNetworkError) as ei:
        resolve_and_pin(
            "https://evil.example/",
            resolver=_resolver([(socket.AF_INET, "100.64.1.1")]),
        )
    assert ei.value.code == "denied_network"


def test_resolve_denies_mixed_public_and_private() -> None:
    with pytest.raises(DenyNetworkError) as ei:
        resolve_and_pin(
            "https://evil.example/",
            resolver=_resolver(
                [
                    (socket.AF_INET, "8.8.8.8"),
                    (socket.AF_INET, "10.0.0.1"),
                ]
            ),
        )
    assert ei.value.code == "denied_network"


def test_resolve_allows_single_public() -> None:
    pin = resolve_and_pin(
        "https://api.example.com/v1",
        resolver=_resolver([(socket.AF_INET, "1.1.1.1")]),
    )
    assert pin.hostname == "api.example.com"
    assert pin.pinned_ip == "1.1.1.1"
    assert pin.port == 443
    assert pin.scheme == "https"
    assert pin.all_ips == ("1.1.1.1",)
    assert pin.family == socket.AF_INET


def test_resolve_empty_answers_denied() -> None:
    with pytest.raises(DenyNetworkError) as ei:
        resolve_and_pin("https://evil.example/", resolver=_resolver([]))
    assert ei.value.code == "empty_answers"


def test_resolve_gaierror_denied() -> None:
    def boom(host: str, port: int) -> list[tuple[int, str]]:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    with pytest.raises(DenyNetworkError) as ei:
        resolve_and_pin("https://no.such.host/", resolver=boom)
    assert ei.value.code == "resolve_failed"


def test_literal_cgnat_denied_by_resolve() -> None:
    with pytest.raises(DenyNetworkError) as ei:
        resolve_and_pin("https://100.64.1.1/")
    assert ei.value.code == "denied_network"


def test_literal_public_pinned() -> None:
    pin = resolve_and_pin("https://1.1.1.1/dns")
    assert pin.pinned_ip == "1.1.1.1"
    assert pin.hostname == "1.1.1.1"


def test_pinned_connect_uses_ip_not_hostname() -> None:
    pin = resolve_and_pin(
        "https://api.example.com/",
        resolver=_resolver([(socket.AF_INET, "1.1.1.1")]),
    )
    recorded: dict[str, Any] = {}

    def fake_connector(ip: str, port: int, timeout: float) -> socket.socket:
        recorded["ip"] = ip
        recorded["port"] = port
        recorded["timeout"] = timeout
        # Do not open a real socket; return a closed unbound socket for type.
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock = pinned_socket_connect(pin, timeout=5.0, connector=fake_connector)
    try:
        assert recorded["ip"] == "1.1.1.1"
        assert recorded["ip"] != "api.example.com"
        assert recorded["port"] == 443
        assert recorded["timeout"] == 5.0
    finally:
        sock.close()


def test_url_guard_cgnat_literal_blocked() -> None:
    assert is_blocked_ip_literal("100.64.1.1") is True
    with pytest.raises(UrlGuardError) as ei:
        check_public_only("https://100.64.1.1/")
    assert ei.value.code == "not_public"


def test_host_allowlist_enforced() -> None:
    with pytest.raises(UrlGuardError) as ei:
        resolve_and_pin(
            "https://evil.example/",
            host_allowlist={"good.example"},
            resolver=_resolver([(socket.AF_INET, "1.1.1.1")]),
        )
    assert ei.value.code == "host_not_allowlisted"
