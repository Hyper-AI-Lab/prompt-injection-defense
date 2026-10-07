"""HTTP fetch helpers with optional DNS pin or forward proxy.

Default path uses stdlib urllib (back-compat). Enterprise hosts set
``use_pinned=True`` and/or ``proxy_url`` (typically the in-repo
containment-egress-proxy) so DNS answers are checked before connect.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from collections.abc import Mapping, Set
from typing import Any
from urllib.parse import urlparse
from urllib.request import HTTPErrorProcessor, HTTPRedirectHandler, Request

from containment.egress_resolve import (
    ConnectorFn,
    DenyNetworkError,
    ResolverFn,
    open_pinned_urllib,
    resolve_and_pin,
)
from containment.url_guard import UrlGuardError


class HttpEgressError(RuntimeError):
    """Raised when a fetch fails (network, deny, size, or HTTP status)."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise HttpEgressError(f"HTTP redirect forbidden ({code} -> {newurl})")


def _request_path(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        return f"{path}?{parsed.query}"
    return path


def _read_capped(resp: Any, max_bytes: int) -> bytes:
    body = resp.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise HttpEgressError(f"response exceeds max_bytes {max_bytes}")
    return body


def _default_opener(*, proxy_url: str | None = None):
    handlers: list[Any] = [_NoRedirectHandler, HTTPErrorProcessor]
    if proxy_url:
        handlers.insert(
            0,
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
        )
    return urllib.request.build_opener(*handlers)


def fetch_url(
    url: str,
    *,
    max_bytes: int,
    timeout: float = 30.0,
    use_pinned: bool = False,
    proxy_url: str | None = None,
    resolver: ResolverFn | None = None,
    connector: ConnectorFn | None = None,
    opener: Any = None,
    headers: Mapping[str, str] | None = None,
    method: str = "GET",
    allowed_schemes: frozenset[str] = frozenset({"https"}),
    host_allowlist: Set[str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> bytes:
    """GET (or other method) ``url`` and return response body bytes.

    Priority:
    1. Explicit ``opener`` (DI / tests) — legacy urllib path, no pin.
    2. ``proxy_url`` — urllib via ProxyHandler (no redirects).
    3. ``use_pinned`` — ``resolve_and_pin`` + ``open_pinned_urllib`` (no redirects).
    4. Default urllib opener (no redirects).
    """
    if max_bytes < 1:
        raise ValueError("max_bytes must be >= 1")
    if not url or not str(url).strip():
        raise ValueError("url must be non-empty")

    hdrs = dict(headers) if headers else {}

    if opener is not None:
        return _fetch_via_opener(
            url,
            opener=opener,
            max_bytes=max_bytes,
            timeout=timeout,
            headers=hdrs,
            method=method,
        )

    if proxy_url:
        return _fetch_via_opener(
            url,
            opener=_default_opener(proxy_url=proxy_url).open,
            max_bytes=max_bytes,
            timeout=timeout,
            headers=hdrs,
            method=method,
        )

    if use_pinned:
        return _fetch_pinned(
            url,
            max_bytes=max_bytes,
            timeout=timeout,
            resolver=resolver,
            connector=connector,
            headers=hdrs,
            method=method,
            allowed_schemes=allowed_schemes,
            host_allowlist=host_allowlist,
            ssl_context=ssl_context,
        )

    return _fetch_via_opener(
        url,
        opener=_default_opener().open,
        max_bytes=max_bytes,
        timeout=timeout,
        headers=hdrs,
        method=method,
    )


def _fetch_pinned(
    url: str,
    *,
    max_bytes: int,
    timeout: float,
    resolver: ResolverFn | None,
    connector: ConnectorFn | None,
    headers: dict[str, str],
    method: str,
    allowed_schemes: frozenset[str],
    host_allowlist: Set[str] | None,
    ssl_context: ssl.SSLContext | None,
) -> bytes:
    try:
        pin = resolve_and_pin(
            url,
            allowed_schemes=allowed_schemes,
            host_allowlist=host_allowlist,
            resolver=resolver,
        )
    except DenyNetworkError as exc:
        raise HttpEgressError(f"egress denied: {exc}") from exc
    except UrlGuardError as exc:
        raise HttpEgressError(f"unsafe url: {exc.reason}") from exc

    path = _request_path(url)
    try:
        resp = open_pinned_urllib(
            pin,
            path=path,
            timeout=timeout,
            method=method,
            headers=headers,
            connector=connector,
            ssl_context=ssl_context,
        )
    except (OSError, ssl.SSLError) as exc:
        raise HttpEgressError(f"network error fetching {url}: {exc}") from exc

    try:
        status = int(getattr(resp, "status", None) or 0)
        body = _read_capped(resp, max_bytes)
    finally:
        try:
            resp.close()
        except OSError:
            pass

    if status >= 400:
        raise HttpEgressError(f"HTTP {status} fetching {url}")
    return body


def _fetch_via_opener(
    url: str,
    *,
    opener: Any,
    max_bytes: int,
    timeout: float,
    headers: dict[str, str],
    method: str,
) -> bytes:
    req = Request(url, headers=headers, method=method)
    try:
        with opener(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            body = _read_capped(resp, max_bytes)
    except HttpEgressError:
        raise
    except urllib.error.HTTPError as exc:
        raise HttpEgressError(f"HTTP {exc.code} fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise HttpEgressError(f"network error fetching {url}: {exc.reason}") from exc
    except OSError as exc:
        raise HttpEgressError(f"network error fetching {url}: {exc}") from exc

    if status and int(status) >= 400:
        raise HttpEgressError(f"HTTP {status} fetching {url}")
    return body


__all__ = [
    "HttpEgressError",
    "fetch_url",
]
