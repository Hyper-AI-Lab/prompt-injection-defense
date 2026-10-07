"""Hermetic tests for http_egress.fetch_url (pinned + proxy paths)."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from containment.egress_proxy import EgressProxyServer, ProxyConfig
from containment.http_egress import HttpEgressError, fetch_url


def _resolver(answers: list[tuple[int, str]]):
    def _fn(host: str, port: int) -> list[tuple[int, str]]:
        return list(answers)

    return _fn


def _redirect_connector(local_host: str, local_port: int):
    def _fn(pinned_ip: str, port: int, timeout: float) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((local_host, local_port))
        return sock

    return _fn


class _JsonHandler(BaseHTTPRequestHandler):
    payload: dict[str, Any] = {"ok": True, "posts": [{"id": "1"}]}

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        body = json.dumps(self.payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def origin_http():
    server = HTTPServer(("127.0.0.1", 0), _JsonHandler)
    port = server.server_address[1]
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()
    yield ("127.0.0.1", port)
    server.shutdown()


def test_fetch_url_pinned_local_server(origin_http) -> None:
    host, port = origin_http
    body = fetch_url(
        "http://api.example.com/posts?sort=new&limit=1",
        max_bytes=50_000,
        timeout=5.0,
        use_pinned=True,
        allowed_schemes=frozenset({"http", "https"}),
        resolver=_resolver([(socket.AF_INET, "1.1.1.1")]),
        connector=_redirect_connector(host, port),
        headers={"Accept": "application/json"},
    )
    data = json.loads(body.decode("utf-8"))
    assert data["ok"] is True
    assert data["posts"][0]["id"] == "1"


def test_fetch_url_pinned_denies_imds() -> None:
    with pytest.raises(HttpEgressError, match="egress denied"):
        fetch_url(
            "http://evil.example/",
            max_bytes=1000,
            use_pinned=True,
            allowed_schemes=frozenset({"http"}),
            resolver=_resolver([(socket.AF_INET, "169.254.169.254")]),
        )


def test_fetch_url_proxy_path(origin_http) -> None:
    host, port = origin_http
    proxy = EgressProxyServer(
        ProxyConfig(listen_host="127.0.0.1", listen_port=0),
        resolver=_resolver([(socket.AF_INET, "1.1.1.1")]),
        connector=_redirect_connector(host, port),
    )
    proxy.serve_in_thread()
    try:
        proxy_url = f"http://127.0.0.1:{proxy.listen_port}"
        body = fetch_url(
            "http://api.example.com/v1/posts",
            max_bytes=50_000,
            timeout=5.0,
            proxy_url=proxy_url,
            headers={"Accept": "application/json"},
        )
        data = json.loads(body.decode("utf-8"))
        assert data["posts"][0]["id"] == "1"
    finally:
        proxy.shutdown()


def test_fetch_url_opener_wins_over_pinned() -> None:
    calls: list[str] = []

    class Resp:
        status = 200

        def read(self, n: int = -1) -> bytes:
            return b'{"via":"opener"}'

        def getcode(self) -> int:
            return 200

        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

    def opener(req: Any, timeout: float = 20.0) -> Any:
        calls.append(req.full_url)
        return Resp()

    body = fetch_url(
        "https://www.moltbook.com/api/v1/posts",
        max_bytes=1000,
        use_pinned=True,
        opener=opener,
    )
    assert json.loads(body)["via"] == "opener"
    assert calls
