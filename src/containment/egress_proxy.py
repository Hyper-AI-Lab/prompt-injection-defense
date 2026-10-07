"""HTTP forward proxy: resolve-pin-forward (no TLS MITM).

CONNECT and absolute-URI HTTP are resolved via ``resolve_and_pin``, then
connected only to the pinned IP. On deny, clients get HTTP 403.
"""

from __future__ import annotations

import argparse
import select
import socket
import ssl
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from urllib.parse import urlparse

from containment.egress_resolve import (
    ConnectorFn,
    DenyNetworkError,
    ResolverFn,
    pinned_socket_connect,
    resolve_and_pin,
)
from containment.url_guard import UrlGuardError

_BUF = 65536
_HEADER_LIMIT = 65536


@dataclass
class ProxyConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    allowed_schemes: frozenset[str] = field(
        default_factory=lambda: frozenset({"http", "https"})
    )
    host_allowlist: frozenset[str] | None = None
    timeout: float = 10.0
    enable_connect: bool = True
    enable_http_forward: bool = True


def _recv_until_headers(sock: socket.socket, limit: int = _HEADER_LIMIT) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        if len(data) >= limit:
            raise OSError("headers too large")
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def _split_headers(raw: bytes) -> tuple[bytes, dict[str, str], bytes]:
    """Return (request_line, headers_lower, body_prefix)."""
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines or not lines[0]:
        raise OSError("empty request")
    req_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        k, _, v = line.partition(b":")
        headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return req_line, headers, rest


def _send_all(sock: socket.socket, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = sock.send(view)
        view = view[n:]


def _reply(sock: socket.socket, status: int, reason: str, body: bytes | None = None) -> None:
    phrase = {
        200: "Connection Established",
        400: "Bad Request",
        403: "Forbidden",
        405: "Method Not Allowed",
        502: "Bad Gateway",
    }.get(status, "Error")
    if status == 200:
        _send_all(sock, b"HTTP/1.1 200 Connection Established\r\n\r\n")
        return
    payload = body if body is not None else reason.encode("utf-8")
    msg = (
        f"HTTP/1.1 {status} {phrase}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("latin-1") + payload
    _send_all(sock, msg)


def _tunnel(a: socket.socket, b: socket.socket, timeout: float) -> None:
    a.settimeout(timeout)
    b.settimeout(timeout)
    sockets = [a, b]
    try:
        while True:
            readable, _, errored = select.select(sockets, [], sockets, timeout)
            if errored or not readable:
                break
            for src in readable:
                dst = b if src is a else a
                try:
                    data = src.recv(_BUF)
                except OSError:
                    return
                if not data:
                    return
                try:
                    _send_all(dst, data)
                except OSError:
                    return
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass



def _parse_connect_target(target: str) -> tuple[str, int]:
    """Parse CONNECT authority into (host, port).

    Bracketed IPv6 (``[::1]`` or ``[::1]:443``) is accepted; missing port
    defaults to 443. Unbracketed multi-colon IPv6 is rejected (fail closed).
    """
    host_port = target.strip()
    if not host_port:
        raise ValueError("empty CONNECT host")
    if host_port.startswith("["):
        end = host_port.find("]")
        if end < 0:
            raise ValueError("unclosed IPv6 bracket")
        host = host_port[1:end]
        if not host:
            raise ValueError("empty CONNECT host")
        rest = host_port[end + 1 :]
        if rest == "":
            return host, 443
        if not rest.startswith(":"):
            raise ValueError("bad CONNECT authority after IPv6")
        port_s = rest[1:]
        if not port_s:
            raise ValueError("bad CONNECT port")
        try:
            port = int(port_s)
        except ValueError as exc:
            raise ValueError("bad CONNECT port") from exc
        if port < 1 or port > 65535:
            raise ValueError("bad CONNECT port")
        return host, port
    # hostname or IPv4 — at most one colon for :port
    if host_port.count(":") > 1:
        raise ValueError("unbracketed IPv6 CONNECT authority")
    if ":" in host_port:
        host, _, port_s = host_port.rpartition(":")
        if not host:
            raise ValueError("empty CONNECT host")
        try:
            port = int(port_s)
        except ValueError as exc:
            raise ValueError("bad CONNECT port") from exc
        if port < 1 or port > 65535:
            raise ValueError("bad CONNECT port")
        return host, port
    return host_port, 443


class EgressProxyServer:
    """Resolve-pin-forward HTTP proxy (stdlib sockets)."""

    def __init__(
        self,
        config: ProxyConfig | None = None,
        *,
        resolver: ResolverFn | None = None,
        connector: ConnectorFn | None = None,
    ) -> None:
        self.config = config if config is not None else ProxyConfig()
        self._resolver = resolver
        self._connector = connector
        self._listen: socket.socket | None = None
        self._bound_host = self.config.listen_host
        self._bound_port = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def proxy_url(self) -> str:
        if self._bound_port == 0:
            raise RuntimeError("proxy not bound; call start() first")
        host = self._bound_host
        if host == "0.0.0.0":
            host = "127.0.0.1"
        return f"http://{host}:{self._bound_port}"

    @property
    def listen_port(self) -> int:
        return self._bound_port

    def start(self) -> None:
        """Bind listen_host:listen_port (port 0 picks an ephemeral port)."""
        with self._lock:
            if self._listen is not None:
                return
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.config.listen_host, self.config.listen_port))
            sock.listen(128)
            sock.settimeout(1.0)
            self._listen = sock
            self._bound_host, self._bound_port = sock.getsockname()[:2]
            self._stop.clear()

    def serve_forever(self) -> None:
        if self._listen is None:
            self.start()
        assert self._listen is not None
        while not self._stop.is_set():
            try:
                client, _addr = self._listen.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            threading.Thread(
                target=self._handle_client,
                args=(client,),
                daemon=True,
            ).start()

    def serve_in_thread(self) -> threading.Thread:
        self.start()
        th = threading.Thread(target=self.serve_forever, name="egress-proxy", daemon=True)
        th.start()
        self._thread = th
        return th

    def shutdown(self) -> None:
        self._stop.set()
        with self._lock:
            sock = self._listen
            self._listen = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None

    def _handle_client(self, client: socket.socket) -> None:
        client.settimeout(self.config.timeout)
        try:
            raw = _recv_until_headers(client)
            if not raw:
                client.close()
                return
            req_line, headers, body_prefix = _split_headers(raw)
            line = req_line.decode("latin-1")
            parts = line.split()
            if len(parts) < 2:
                _reply(client, 400, "bad request line")
                client.close()
                return
            method, target = parts[0].upper(), parts[1]
            version = parts[2] if len(parts) > 2 else "HTTP/1.1"
            if method == "CONNECT":
                self._handle_connect(client, target)
            else:
                self._handle_http_forward(
                    client, method, target, version, headers, body_prefix
                )
        except (OSError, ValueError) as exc:
            try:
                _reply(client, 502, f"proxy error: {exc}")
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass

    def _pin(self, url: str, *, schemes: frozenset[str] | None = None):
        return resolve_and_pin(
            url,
            allowed_schemes=schemes
            if schemes is not None
            else self.config.allowed_schemes,
            host_allowlist=self.config.host_allowlist,
            resolver=self._resolver,
        )

    def _connect_pin(self, pin):
        return pinned_socket_connect(
            pin,
            timeout=self.config.timeout,
            connector=self._connector,
        )

    def _handle_connect(self, client: socket.socket, target: str) -> None:
        if not self.config.enable_connect:
            _reply(client, 405, "CONNECT disabled")
            client.close()
            return
        try:
            host, port = _parse_connect_target(target)
        except ValueError as exc:
            _reply(client, 400, str(exc))
            client.close()
            return
        # Bracket IPv6 in the URL authority so urlparse stays unambiguous.
        if ":" in host:
            authority = f"[{host}]:{port}"
        else:
            authority = f"{host}:{port}"
        url = f"https://{authority}/"
        try:
            pin = self._pin(url, schemes=frozenset({"https"}))
            upstream = self._connect_pin(pin)
        except (DenyNetworkError, UrlGuardError) as exc:
            reason = getattr(exc, "reason", str(exc))
            code = getattr(exc, "code", "denied")
            msg = f"{code}: {reason}"
            _reply(client, 403, msg, body=msg.encode("utf-8"))
            client.close()
            return
        except OSError as exc:
            _reply(client, 502, f"connect failed: {exc}")
            client.close()
            return
        try:
            _reply(client, 200, "ok")
        except OSError:
            upstream.close()
            client.close()
            return
        _tunnel(client, upstream, self.config.timeout)

    def _handle_http_forward(
        self,
        client: socket.socket,
        method: str,
        target: str,
        version: str,
        headers: dict[str, str],
        body_prefix: bytes,
    ) -> None:
        if not self.config.enable_http_forward:
            _reply(client, 405, "HTTP forward disabled")
            client.close()
            return
        parsed = urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            _reply(client, 400, "absolute-form URI required")
            client.close()
            return
        scheme = parsed.scheme.lower()
        if scheme not in self.config.allowed_schemes:
            _reply(client, 403, f"bad_scheme: {scheme}")
            client.close()
            return
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        url = f"{scheme}://{parsed.netloc}{path}"
        try:
            pin = self._pin(url)
            upstream: socket.socket = self._connect_pin(pin)
        except (DenyNetworkError, UrlGuardError) as exc:
            reason = getattr(exc, "reason", str(exc))
            code = getattr(exc, "code", "denied")
            msg = f"{code}: {reason}"
            _reply(client, 403, msg, body=msg.encode("utf-8"))
            client.close()
            return
        except OSError as exc:
            _reply(client, 502, f"connect failed: {exc}")
            client.close()
            return

        if scheme == "https":
            ctx = ssl.create_default_context()
            try:
                upstream = ctx.wrap_socket(upstream, server_hostname=pin.hostname)
            except OSError as exc:
                try:
                    upstream.close()
                except OSError:
                    pass
                _reply(client, 502, f"tls failed: {exc}")
                client.close()
                return

        body = body_prefix
        cl = headers.get("content-length")
        if cl is not None:
            try:
                need = int(cl)
            except ValueError:
                upstream.close()
                _reply(client, 400, "bad Content-Length")
                client.close()
                return
            while len(body) < need:
                chunk = client.recv(min(_BUF, need - len(body)))
                if not chunk:
                    break
                body += chunk
            body = body[:need]

        # Host = original hostname (do not substitute pinned IP).
        host_hdr = pin.hostname
        out_lines = [f"{method} {path} {version}", f"Host: {host_hdr}"]
        for k, v in headers.items():
            if k in {"host", "proxy-connection", "proxy-authorization"}:
                continue
            if k == "connection":
                out_lines.append("Connection: close")
                continue
            out_lines.append(f"{k}: {v}")
        if not any(line.lower().startswith("connection:") for line in out_lines[1:]):
            out_lines.append("Connection: close")
        req = ("\r\n".join(out_lines) + "\r\n\r\n").encode("latin-1") + body
        try:
            _send_all(upstream, req)
            # Pipe response as-is; do not follow redirects.
            while True:
                data = upstream.recv(_BUF)
                if not data:
                    break
                _send_all(client, data)
        except OSError:
            pass
        finally:
            try:
                upstream.close()
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="containment-egress-proxy",
        description=(
            "Resolve-pin-forward HTTP proxy. Denies private/IMDS/CGNAT DNS answers."
        ),
    )
    parser.add_argument(
        "--listen",
        default="127.0.0.1:18080",
        help="HOST:PORT to bind (default 127.0.0.1:18080)",
    )
    parser.add_argument(
        "--allow-host",
        action="append",
        default=None,
        dest="allow_hosts",
        help="Optional host allowlist entry (repeatable)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Socket timeout seconds (default 10)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    listen = args.listen.strip()
    if ":" not in listen:
        parser.error("--listen must be HOST:PORT")
    host, _, port_s = listen.rpartition(":")
    try:
        port = int(port_s)
    except ValueError:
        parser.error("invalid --listen port")
    allow: frozenset[str] | None = None
    if args.allow_hosts:
        allow = frozenset(h.lower().rstrip(".") for h in args.allow_hosts)
    cfg = ProxyConfig(
        listen_host=host or "127.0.0.1",
        listen_port=port,
        host_allowlist=allow,
        timeout=float(args.timeout),
    )
    server = EgressProxyServer(cfg)
    server.start()
    print(f"containment-egress-proxy listening on {server.proxy_url}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
