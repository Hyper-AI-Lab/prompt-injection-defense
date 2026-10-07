"""Moltbook public feed reader — untrusted ingest + fixed summary schema.

No account or auth. All posts are treated as untrusted. Network I/O uses
stdlib ``urllib`` by default. Set ``use_pinned_egress=True`` /
``CONTAINMENT_EGRESS_PINNED=1`` or ``proxy_url`` /
``CONTAINMENT_EGRESS_PROXY`` for enterprise resolve-pin or forward-proxy
egress. Live calls are optional; unit tests must mock HTTP.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.request import HTTPErrorProcessor, HTTPRedirectHandler, Request

from containment.detectors.cascade import DetectorCascade
from containment.egress_resolve import ConnectorFn, ResolverFn
from containment.http_egress import HttpEgressError, fetch_url
from containment.ingest import IngestResult, default_ingest_cascade, ingest
from containment.quarantine import closed_object_schema
from containment.url_guard import UrlGuardError, check_url_for_tool, parse_egress_url

DEFAULT_API_BASE = "https://www.moltbook.com/api/v1"
LIVE_ENV = "CONTAINMENT_LIVE_MOLTBOOK"
PINNED_ENV = "CONTAINMENT_EGRESS_PINNED"
PROXY_ENV = "CONTAINMENT_EGRESS_PROXY"
DEFAULT_MAX_BYTES = 2_000_000

MOLTBOOK_SUMMARY_SCHEMA: dict[str, Any] = closed_object_schema(
    {
        "title": {"type": "string", "maxLength": 200},
        "topic": {"type": "string", "maxLength": 80},
        "summary": {"type": "string", "maxLength": 500},
    },
    required=["title", "topic", "summary"],
    schema_id="moltbook_summary",
)

_DEFAULT_HOST = parse_egress_url(DEFAULT_API_BASE).host


class MoltbookError(RuntimeError):
    """Raised when the public API request or parse fails."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise MoltbookError(f"HTTP redirect forbidden ({code} → {newurl})")


def _default_opener():
    return urllib.request.build_opener(_NoRedirectHandler, HTTPErrorProcessor)


@dataclass(frozen=True, slots=True)
class MoltbookPostSummary:
    """One post after containment ingest (typed fields only when ok)."""

    post_id: str
    ingest: IngestResult

    @property
    def ok(self) -> bool:
        return self.ingest.ok

    @property
    def data(self) -> Mapping[str, Any] | None:
        if self.ingest.extract is None:
            return None
        return self.ingest.extract.data


def _truncate(text: str, max_len: int) -> str:
    text = text.replace("\r\n", "\n").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 1].rstrip() + "…"


def candidate_from_post(post: Mapping[str, Any]) -> dict[str, str]:
    """Map a raw API post dict to the fixed summary candidate (pre-quarantine)."""
    title = str(post.get("title") or "").strip() or "(untitled)"
    sub = post.get("submolt") if isinstance(post.get("submolt"), Mapping) else {}
    topic = str(sub.get("name") or sub.get("display_name") or "general").strip()
    content = str(post.get("content") or "")
    summary = _truncate(content, 500)
    return {
        "title": _truncate(title, 200),
        "topic": _truncate(topic, 80),
        "summary": summary if summary else "(empty)",
    }


def _validate_base_url(base_url: str) -> None:
    try:
        check_url_for_tool(
            base_url if "://" in base_url else f"{base_url}/",
            schemes=frozenset({"https"}),
            host_allowlist={_DEFAULT_HOST},
            network="public_only",
        )
    except UrlGuardError as exc:
        raise MoltbookError(f"unsafe base_url: {exc.reason}") from exc


def _resolve_egress_flags(
    *,
    use_pinned_egress: bool,
    proxy_url: str | None,
) -> tuple[bool, str | None]:
    """Kwargs win when truthy; otherwise honor env (PINNED / PROXY)."""
    pinned = use_pinned_egress or os.environ.get(PINNED_ENV, "").strip() == "1"
    proxy = proxy_url
    if proxy is None:
        env_proxy = os.environ.get(PROXY_ENV, "").strip()
        proxy = env_proxy or None
    return pinned, proxy


def fetch_posts(
    *,
    sort: str = "new",
    limit: int = 10,
    base_url: str = DEFAULT_API_BASE,
    timeout: float = 20.0,
    opener: Any = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    use_pinned_egress: bool = False,
    proxy_url: str | None = None,
    resolver: ResolverFn | None = None,
    connector: ConnectorFn | None = None,
) -> list[dict[str, Any]]:
    """GET public ``/posts`` with sort/limit. No auth headers.

    ``opener`` is an optional callable ``(Request, timeout=...) -> http response``
    for dependency injection / tests. Defaults to a no-redirect urllib opener.

    Enterprise egress (when ``opener`` is not set):
    - ``use_pinned_egress=True`` or env ``CONTAINMENT_EGRESS_PINNED=1``:
      DNS resolve-pin via ``containment.http_egress.fetch_url``.
    - ``proxy_url`` or env ``CONTAINMENT_EGRESS_PROXY`` (e.g.
      ``http://127.0.0.1:3128``): forward through that HTTP proxy
      (typically ``containment-egress-proxy``).
    Explicit ``opener`` always wins (test DI / back-compat).
    """
    if limit < 1 or limit > 100:
        raise ValueError("limit must be in 1..100")
    if not sort or not str(sort).strip():
        raise ValueError("sort must be a non-empty string")
    if max_bytes < 1:
        raise ValueError("max_bytes must be >= 1")

    _validate_base_url(base_url.rstrip("/") + "/")

    query = urllib.parse.urlencode({"sort": sort, "limit": str(limit)})
    url = f"{base_url.rstrip('/')}/posts?{query}"
    try:
        check_url_for_tool(
            url,
            schemes=frozenset({"https"}),
            host_allowlist={_DEFAULT_HOST},
            network="public_only",
        )
    except UrlGuardError as exc:
        raise MoltbookError(f"unsafe fetch url: {exc.reason}") from exc

    headers = {
        "Accept": "application/json",
        "User-Agent": "containment-moltbook-reader/0.1",
    }

    pinned, proxy = _resolve_egress_flags(
        use_pinned_egress=use_pinned_egress,
        proxy_url=proxy_url,
    )

    if opener is not None:
        body = _fetch_with_opener(
            url, opener=opener, timeout=timeout, max_bytes=max_bytes, headers=headers
        )
    elif pinned or proxy:
        try:
            body = fetch_url(
                url,
                max_bytes=max_bytes,
                timeout=timeout,
                use_pinned=bool(pinned) and not proxy,
                proxy_url=proxy,
                resolver=resolver,
                connector=connector,
                headers=headers,
                allowed_schemes=frozenset({"https"}),
                host_allowlist={_DEFAULT_HOST},
            )
        except HttpEgressError as exc:
            raise MoltbookError(str(exc)) from exc
    else:
        body = _fetch_with_opener(
            url,
            opener=_default_opener().open,
            timeout=timeout,
            max_bytes=max_bytes,
            headers=headers,
        )

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MoltbookError("response is not valid JSON") from exc

    if not isinstance(payload, dict):
        raise MoltbookError("response root must be an object")
    posts = payload.get("posts")
    if not isinstance(posts, list):
        raise MoltbookError("response missing posts list")
    out: list[dict[str, Any]] = []
    for item in posts:
        if isinstance(item, dict):
            out.append(item)
    return out


def _fetch_with_opener(
    url: str,
    *,
    opener: Any,
    timeout: float,
    max_bytes: int,
    headers: Mapping[str, str],
) -> bytes:
    req = Request(url, headers=dict(headers), method="GET")
    try:
        with opener(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            body = resp.read(max_bytes + 1)
    except MoltbookError:
        raise
    except urllib.error.HTTPError as exc:
        raise MoltbookError(f"HTTP {exc.code} fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise MoltbookError(f"network error fetching {url}: {exc.reason}") from exc

    if len(body) > max_bytes:
        raise MoltbookError(f"response exceeds max_bytes {max_bytes}")

    if status and int(status) >= 400:
        raise MoltbookError(f"HTTP {status} fetching {url}")
    return body


def ingest_post(
    post: Mapping[str, Any],
    *,
    task_id: str = "moltbook-read",
    cascade: DetectorCascade | None = None,
) -> MoltbookPostSummary:
    """Run one raw post through containment ingest (always untrusted)."""
    post_id = str(post.get("id") or "unknown")
    raw_parts = [
        str(post.get("title") or ""),
        str(post.get("content") or ""),
    ]
    raw_text = "\n\n".join(p for p in raw_parts if p)
    candidate = candidate_from_post(post)
    result = ingest(
        raw_text,
        source=f"moltbook:post:{post_id}",
        task_id=task_id,
        schema=MOLTBOOK_SUMMARY_SCHEMA,
        candidate=candidate,
        integrity="untrusted",
        confidentiality="public",
        cascade=cascade or default_ingest_cascade(),
        reject_instruction_text=True,
    )
    return MoltbookPostSummary(post_id=post_id, ingest=result)


def read_posts(
    *,
    sort: str = "new",
    limit: int = 10,
    task_id: str = "moltbook-read",
    cascade: DetectorCascade | None = None,
    base_url: str = DEFAULT_API_BASE,
    timeout: float = 20.0,
    opener: Any = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    use_pinned_egress: bool = False,
    proxy_url: str | None = None,
    resolver: ResolverFn | None = None,
    connector: ConnectorFn | None = None,
) -> list[MoltbookPostSummary]:
    """Fetch public posts and run each through containment ingest.

    Passes ``use_pinned_egress`` / ``proxy_url`` / env
    ``CONTAINMENT_EGRESS_PINNED`` and ``CONTAINMENT_EGRESS_PROXY`` through
    to :func:`fetch_posts` (see that docstring).
    """
    posts = fetch_posts(
        sort=sort,
        limit=limit,
        base_url=base_url,
        timeout=timeout,
        opener=opener,
        max_bytes=max_bytes,
        use_pinned_egress=use_pinned_egress,
        proxy_url=proxy_url,
        resolver=resolver,
        connector=connector,
    )
    return [
        ingest_post(p, task_id=task_id, cascade=cascade) for p in posts
    ]


def live_enabled() -> bool:
    """True when optional live smoke may hit the network."""
    return os.environ.get(LIVE_ENV, "").strip() == "1"


__all__ = [
    "DEFAULT_API_BASE",
    "DEFAULT_MAX_BYTES",
    "LIVE_ENV",
    "MOLTBOOK_SUMMARY_SCHEMA",
    "PINNED_ENV",
    "PROXY_ENV",
    "MoltbookError",
    "MoltbookPostSummary",
    "candidate_from_post",
    "fetch_posts",
    "ingest_post",
    "live_enabled",
    "read_posts",
]
