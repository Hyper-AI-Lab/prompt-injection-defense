"""Hermetic tests for egress_proxy (mock DNS + local connector; no real IMDS)."""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from containment.egress_proxy import EgressProxyServer, ProxyConfig, main


def _resolver(answers: list[tuple[int, str]]):
    def _fn(host: str, port: int) -> list[tuple[int, str]]:
        return list(answers)

    return _fn


def _redirect_connector(local_host: str, local_port: int):
    """Ignore pinned IP; dial a local echo/HTTP server instead."""

    def _fn(pinned_ip: str, port: int, timeout: float) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((local_host, local_port))
        return sock

    return _fn


class _EchoHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        body = f"ok:{self.path}:host={self.headers.get('Host', '')}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n) if n else b""
        body = b"echo:" + raw
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def origin_http():
    server = HTTPServer(("127.0.0.1", 0), _EchoHandler)
    port = server.server_address[1]
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()
    yield ("127.0.0.1", port)
    server.shutdown()


def _proxy_http_request(
    proxy_host: str,
    proxy_port: int,
    request: bytes,
    timeout: float = 5.0,
) -> bytes:
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.sendall(request)
        chunks: list[bytes] = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        sock.close()


def test_connect_denied_imds_via_mock_dns() -> None:
    proxy = EgressProxyServer(
        ProxyConfig(listen_host="127.0.0.1", listen_port=0),
        resolver=_resolver([(socket.AF_INET, "169.254.169.254")]),
    )
    proxy.serve_in_thread()
    try:
        host, port = "127.0.0.1", proxy.listen_port
        req = (
            b"CONNECT imds.evil:443 HTTP/1.1\r\n"
            b"Host: imds.evil:443\r\n"
            b"\r\n"
        )
        resp = _proxy_http_request(host, port, req)
        assert resp.startswith(b"HTTP/1.1 403")
        assert b"denied_network" in resp
    finally:
        proxy.shutdown()


def test_connect_denied_cgnat_via_mock_dns() -> None:
    proxy = EgressProxyServer(
        ProxyConfig(listen_host="127.0.0.1", listen_port=0),
        resolver=_resolver([(socket.AF_INET, "100.64.1.1")]),
    )
    proxy.serve_in_thread()
    try:
        req = (
            b"CONNECT cgnat.evil:443 HTTP/1.1\r\n"
            b"Host: cgnat.evil:443\r\n"
            b"\r\n"
        )
        resp = _proxy_http_request("127.0.0.1", proxy.listen_port, req)
        assert resp.startswith(b"HTTP/1.1 403")
        assert b"denied_network" in resp
    finally:
        proxy.shutdown()


def test_http_forward_denied_private() -> None:
    proxy = EgressProxyServer(
        ProxyConfig(listen_host="127.0.0.1", listen_port=0),
        resolver=_resolver([(socket.AF_INET, "10.1.2.3")]),
    )
    proxy.serve_in_thread()
    try:
        req = (
            b"GET http://private.evil/secret HTTP/1.1\r\n"
            b"Host: private.evil\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = _proxy_http_request("127.0.0.1", proxy.listen_port, req)
        assert resp.startswith(b"HTTP/1.1 403")
        assert b"denied_network" in resp
    finally:
        proxy.shutdown()


def test_http_forward_allow_mock_public(origin_http) -> None:
    local_host, local_port = origin_http
    public_ip = "93.184.216.34"
    proxy = EgressProxyServer(
        ProxyConfig(listen_host="127.0.0.1", listen_port=0, timeout=5.0),
        resolver=_resolver([(socket.AF_INET, public_ip)]),
        connector=_redirect_connector(local_host, local_port),
    )
    proxy.serve_in_thread()
    try:
        req = (
            b"GET http://example.com/hello HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = _proxy_http_request("127.0.0.1", proxy.listen_port, req)
        assert b"200" in resp.split(b"\r\n", 1)[0]
        assert b"ok:/hello:host=example.com" in resp
    finally:
        proxy.shutdown()


def test_http_forward_post_roundtrip(origin_http) -> None:
    local_host, local_port = origin_http
    proxy = EgressProxyServer(
        ProxyConfig(listen_host="127.0.0.1", listen_port=0, timeout=5.0),
        resolver=_resolver([(socket.AF_INET, "8.8.8.8")]),
        connector=_redirect_connector(local_host, local_port),
    )
    proxy.serve_in_thread()
    try:
        body = b"payload-bytes"
        req = (
            b"POST http://pub.example/echo HTTP/1.1\r\n"
            b"Host: pub.example\r\n"
            b"Content-Length: "
            + str(len(body)).encode()
            + b"\r\n"
            + b"Connection: close\r\n"
            + b"\r\n"
            + body
        )
        resp = _proxy_http_request("127.0.0.1", proxy.listen_port, req)
        assert b"200" in resp.split(b"\r\n", 1)[0]
        assert b"echo:payload-bytes" in resp
    finally:
        proxy.shutdown()


def test_connect_allow_then_tunnel_http(origin_http) -> None:
    """CONNECT succeeds for mock-public; tunnel carries plain HTTP to origin."""
    local_host, local_port = origin_http
    proxy = EgressProxyServer(
        ProxyConfig(listen_host="127.0.0.1", listen_port=0, timeout=5.0),
        resolver=_resolver([(socket.AF_INET, "1.1.1.1")]),
        connector=_redirect_connector(local_host, local_port),
    )
    proxy.serve_in_thread()
    try:
        sock = socket.create_connection(("127.0.0.1", proxy.listen_port), timeout=5.0)
        try:
            sock.sendall(
                b"CONNECT pub.example:443 HTTP/1.1\r\n"
                b"Host: pub.example:443\r\n"
                b"\r\n"
            )
            # Read 200 Connection Established
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                assert chunk, "proxy closed before CONNECT response"
                buf += chunk
            assert buf.startswith(b"HTTP/1.1 200")
            # Blind tunnel: send plain HTTP (hermetic; no TLS).
            sock.sendall(
                b"GET /via-connect HTTP/1.1\r\n"
                b"Host: pub.example\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            resp = b""
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                resp += data
            assert b"200" in resp.split(b"\r\n", 1)[0]
            assert b"ok:/via-connect:host=pub.example" in resp
        finally:
            sock.close()
    finally:
        proxy.shutdown()


def test_proxy_url_property() -> None:
    proxy = EgressProxyServer(ProxyConfig(listen_host="127.0.0.1", listen_port=0))
    with pytest.raises(RuntimeError):
        _ = proxy.proxy_url
    proxy.start()
    try:
        assert proxy.proxy_url.startswith("http://127.0.0.1:")
        assert proxy.listen_port > 0
    finally:
        proxy.shutdown()


def test_cli_help_exits_zero() -> None:
    with pytest.raises(SystemExit) as ei:
        main(["--help"])
    assert ei.value.code == 0


def test_cli_main_importable() -> None:
    assert callable(main)
