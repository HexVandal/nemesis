"""Async HTTP client with scope enforcement, rate limiting and evidence capture.

Design notes
------------
* Redirects are followed *manually* so that every hop is re-checked against
  the scope. Letting httpx follow redirects internally would let a target
  walk the scanner off-site in a single hop.
* Rate limiting is a token bucket per host plus a global concurrency cap, so
  a single slow host cannot starve the rest of the scan.
* Every request/response pair is recorded (with secrets redacted) so findings
  can be independently reproduced by a human.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from ..config import ScanConfig
from ..scope import Scope

#: Patterns for values that must never end up in a report.
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(authorization\s*:\s*)(bearer\s+)?\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[=:]\s*)"
                r"[\"']?([^\s\"'&,;]{3,})"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(sk-[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|"
                r"AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})"), "[REDACTED]"),
    (re.compile(r"(?i)([?&](?:token|key|secret|password|api_key)=)([^&\s]+)"), r"\1[REDACTED]"),
]


def redact(text: str, limit: int = 8000) -> str:
    """Remove credential-shaped values from *text*."""
    if not text:
        return ""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    if len(text) > limit:
        text = text[:limit] + f"\n... [truncated, {len(text)} bytes total]"
    return text


@dataclass
class Response:
    """A normalised HTTP response."""

    url: str
    status: int
    headers: dict[str, str]
    text: str
    content: bytes
    elapsed: float
    method: str = "GET"
    request_body: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400 and not self.error

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()

    @property
    def length(self) -> int:
        return len(self.content)

    def header(self, name: str, default: str = "") -> str:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default

    def summary(self) -> str:
        return f"{self.status} {self.method} {self.url} ({self.length}B, {self.elapsed:.2f}s)"


@dataclass
class Transaction:
    """A recorded request/response pair."""

    request_line: str
    request_headers: dict[str, str]
    request_body: str
    response: Response

    def evidence(self) -> tuple[str, str]:
        return (
            redact(self.request_line + "\n" + self.request_body),
            redact(self.response.text),
        )


class RateLimiter:
    """Token bucket, one instance per host."""

    def __init__(self, rate: float, burst: int | None = None) -> None:
        self.rate = max(0.1, rate)
        self.capacity = burst or max(1, int(self.rate))
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self.lock:
                now = time.monotonic()
                elapsed = now - self.updated
                self.updated = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                deficit = (1.0 - self.tokens) / self.rate
            await asyncio.sleep(min(deficit, 1.0))


class HttpClient:
    """The scanner's single egress point.

    Nothing in nemesis should call httpx directly; everything goes through
    here so that scope, rate limits and recording are never bypassed.
    """

    def __init__(self, config: ScanConfig, scope: Scope) -> None:
        self.config = config
        self.scope = scope
        self._client: httpx.AsyncClient | None = None
        self._limiters: dict[str, RateLimiter] = {}
        self._global_sem = asyncio.Semaphore(max(1, config.rate.global_concurrency))
        # Bounded: nothing reads this today, and an unbounded list of
        # response bodies is a memory leak on a long crawl.
        self.transactions: deque[Transaction] = deque(maxlen=2000)
        self.request_count = 0
        self.bytes_received = 0
        self._host_sems: dict[str, asyncio.Semaphore] = {}

    # -- lifecycle --------------------------------------------------------
    async def __aenter__(self) -> HttpClient:
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
        headers.update(self.config.auth.extra_headers)
        self._apply_auth_headers(headers)
        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(self.config.timeout),
            follow_redirects=False,
            verify=self.config.verify_tls,
            proxy=self.config.proxy,
            limits=httpx.Limits(
                max_connections=max(4, self.config.rate.global_concurrency * 2),
                max_keepalive_connections=max(2, self.config.rate.per_host_concurrency),
            ),
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client:
            await self._client.aclose()

    def _apply_auth_headers(self, headers: dict[str, str]) -> None:
        auth = self.config.auth
        if auth.mode == "header" and auth.header and auth.value:
            headers[auth.header] = auth.value
        elif auth.mode == "bearer" and auth.value:
            headers[auth.header or "Authorization"] = (
                auth.value if auth.value.lower().startswith("bearer ") else f"Bearer {auth.value}"
            )
        elif auth.mode == "basic" and auth.username:
            token = __import__("base64").b64encode(
                f"{auth.username}:{auth.password}".encode()
            ).decode()
            headers[auth.header or "Authorization"] = f"Basic {token}"
        elif auth.mode == "query" and auth.query_param and auth.value:
            # Query auth is applied per-request, not on the client.
            pass

    # -- internals --------------------------------------------------------
    def _limiter(self, host: str) -> RateLimiter:
        if host not in self._limiters:
            self._limiters[host] = RateLimiter(self.config.rate.requests_per_second)
        return self._limiters[host]

    def _host_sem(self, host: str) -> asyncio.Semaphore:
        if host not in self._host_sems:
            self._host_sems[host] = asyncio.Semaphore(
                max(1, self.config.rate.per_host_concurrency)
            )
        return self._host_sems[host]

    async def _raw_request(
        self, method: str, url: str, **kwargs: Any
    ) -> Response:
        if self._client is None:
            raise RuntimeError(
                "HttpClient used outside of its context manager: wrap the scan "
                "in 'async with HttpClient(config, scope)'"
            )
        host = (urlparse(url).hostname or "").lower()
        limiter = self._limiter(host)
        sem = self._host_sem(host)

        # Capture the body WITHOUT removing it from the request. An earlier
        # version used kwargs.pop(), which silently stripped every form body
        # and JSON payload before it was sent - so probes were recorded as if
        # they had been delivered when the server received nothing at all.
        data = kwargs.pop("data", None)
        content = kwargs.pop("content", None)
        json_body = kwargs.pop("json", None)
        request_body: Any = (
            data if data is not None
            else content if content is not None
            else json_body
        )
        if isinstance(request_body, (dict, list)):
            request_body = str(request_body)
        elif isinstance(request_body, bytes):
            request_body = request_body.decode("utf-8", "replace")
        request_body = request_body or ""

        headers = dict(kwargs.pop("headers", None) or {})
        if self.config.auth.mode == "query" and self.config.auth.query_param:
            parsed = urlparse(url)
            query = f"{parsed.query}&" if parsed.query else ""
            url = url.replace(
                parsed.query,
                f"{query}{self.config.auth.query_param}={self.config.auth.value}",
                1,
            ) if parsed.query else f"{url}?{self.config.auth.query_param}={self.config.auth.value}"

        async with self._global_sem, sem:
            await limiter.acquire()
            started = time.monotonic()
            try:
                send: dict[str, Any] = {}
                if data is not None:
                    send["data"] = data
                if content is not None:
                    send["content"] = content
                if json_body is not None:
                    send["json"] = json_body
                response = await self._client.request(
                    method, url, headers=headers, **send, **kwargs
                )
            except httpx.TimeoutException as exc:
                return Response(
                    url=url, status=0, headers={}, text="", content=b"",
                    elapsed=time.monotonic() - started, method=method,
                    request_body=request_body, error=f"timeout: {exc}",
                )
            except Exception as exc:  # network errors are normal, not fatal
                return Response(
                    url=url, status=0, headers={}, text="", content=b"",
                    elapsed=time.monotonic() - started, method=method,
                    request_body=request_body, error=f"{type(exc).__name__}: {exc}",
                )

        body = response.content
        max_bytes = self.config.crawl.max_body_bytes
        if len(body) > max_bytes:
            body = body[:max_bytes]

        return Response(
            url=str(response.url),
            status=response.status_code,
            headers=dict(response.headers),
            text=body.decode(response.encoding or "utf-8", errors="replace"),
            content=body,
            elapsed=time.monotonic() - started,
            method=method,
            request_body=request_body,
        )

    # -- public API -------------------------------------------------------
    async def request(
        self,
        method: str,
        url: str,
        *,
        follow_redirects: bool | None = None,
        max_redirects: int | None = None,
        **kwargs: Any,
    ) -> Response:
        """Perform a request, honouring scope and redirect policy.

        Returns a response with ``status == 0`` and ``error`` set when the
        request could not be made, or with ``status == 0`` and
        ``error == 'out_of_scope'`` when scope blocked it.
        """
        if not self.scope.allows(url):
            return Response(
                url=url, status=0, headers={}, text="", content=b"", elapsed=0.0,
                method=method, error="out_of_scope",
            )

        follow = self.config.follow_redirects if follow_redirects is None else follow_redirects
        max_hops = self.config.max_redirects if max_redirects is None else max_redirects

        chain: list[str] = []
        current = url
        for hop in range(max_hops + 1):
            response = await self._raw_request(method, current, **kwargs)
            response.redirect_chain = list(chain)
            self.request_count += 1
            self.bytes_received += response.length

            self.transactions.append(
                Transaction(
                    request_line=f"{method} {response.url}",
                    request_headers=dict(kwargs.get("headers") or {}),
                    request_body=response.request_body,
                    response=response,
                )
            )

            is_redirect = response.status in (301, 302, 303, 307, 308)
            if not follow or not is_redirect or hop >= max_hops:
                return response

            location = response.header("location")
            if not location:
                return response
            nxt = urljoin(response.url, location)
            if not self.scope.allows(nxt):
                blocked = Response(
                    url=response.url, status=response.status, headers=response.headers,
                    text=response.text, content=response.content, elapsed=response.elapsed,
                    method=method, request_body=response.request_body,
                    redirect_chain=chain, error="redirect_out_of_scope",
                )
                return blocked
            chain.append(nxt)
            current = nxt
            if response.status in (301, 302, 303) and method.upper() != "HEAD":
                # A 303 means "the work is done, fetch this instead": the
                # body must not be replayed onto the next hop.
                method = "GET"
                kwargs.pop("data", None)
                kwargs.pop("content", None)
                kwargs.pop("json", None)
        return response

    async def get(self, url: str, **kwargs: Any) -> Response:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Response:
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Response:
        return await self.request("POST", url, **kwargs)

    async def request_with_cookies(
        self, method: str, url: str, cookies: dict[str, str], **kwargs: Any
    ) -> Response:
        headers = dict(kwargs.pop("headers", None) or {})
        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        return await self.request(method, url, headers=headers, **kwargs)
