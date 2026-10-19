"""BFS web crawler.

The crawler is the attack-surface mapper. It follows links, submits nothing,
respects scope and robots.txt, and records every endpoint, form and
parameter it discovers so that later layers can attack them.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

from ..config import ScanConfig
from ..http.client import HttpClient, Response
from ..models import Endpoint, Form
from ..scope import Scope
from .parser import ParsedPage, parse_html

log = logging.getLogger("nemesis.crawler")


@dataclass
class CrawlStats:
    pages_fetched: int = 0
    pages_skipped_scope: int = 0
    pages_error: int = 0
    links_discovered: int = 0
    forms_discovered: int = 0
    parameters_discovered: int = 0
    duration: float = 0.0
    external_hosts: set[str] = field(default_factory=set)


def normalize_url(url: str) -> str:
    """Strip fragments and normalise a URL for deduplication.

    The empty path and "/" are the same resource, so they must collapse to a
    single key or the crawler fetches the home page twice and every finding
    derived from it is reported twice. A trailing slash on any *other* path
    is significant (``/admin`` and ``/admin/`` are different resources) and
    is left alone.
    """
    parsed = urlparse(url)
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, ""))


class Spider:
    """Breadth-first crawler with scope, robots and depth control."""

    def __init__(self, client: HttpClient, config: ScanConfig, scope: Scope) -> None:
        self.client = client
        self.config = config
        self.scope = scope
        self.stats = CrawlStats()
        self.endpoints: dict[str, Endpoint] = {}
        self.responses: dict[str, Response] = {}
        self.forms: list[Form] = []
        self._seen: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()
        self._robots: dict[str, RobotFileParser | None] = {}
        self._host_seen: set[str] = set()
        self._seen_forms: set[tuple] = set()

    # -- robots -----------------------------------------------------------
    async def _robots_for(self, base: str) -> RobotFileParser | None:
        parsed = urlparse(base)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in self._robots:
            return self._robots[origin]
        if not self.config.crawl.follow_robots:
            self._robots[origin] = None
            return None
        parser: RobotFileParser | None = RobotFileParser()
        try:
            response = await self.client.get(urljoin(origin, "/robots.txt"))
            if response.ok and response.status == 200:
                parser.parse(response.text.splitlines())
            else:
                parser = None
        except Exception:
            parser = None
        self._robots[origin] = parser
        return parser

    def _allowed_by_robots(self, parser: RobotFileParser | None, url: str) -> bool:
        if parser is None:
            return True
        try:
            return parser.can_fetch(self.config.user_agent, url)
        except Exception:
            return True

    # -- crawling ---------------------------------------------------------
    async def crawl(self, seeds: list[str]) -> tuple[list[Endpoint], list[Form], CrawlStats]:
        """Crawl from *seeds* and return discovered endpoints and forms."""
        started = time.monotonic()
        for seed in seeds:
            self._queue.append((seed, 0))

        while self._queue:
            url, depth = self._queue.popleft()
            key = normalize_url(url)
            if key in self._seen:
                continue
            if len(self._seen) >= self.config.crawl.max_pages:
                break
            if depth > self.config.crawl.max_depth:
                continue
            if not self.scope.allows(url):
                self.stats.pages_skipped_scope += 1
                continue

            parsed_url = urlparse(url)
            if self._is_skippable_extension(parsed_url.path):
                continue

            self._seen.add(key)
            robots = await self._robots_for(url)
            if not self._allowed_by_robots(robots, url):
                log.debug("robots.txt disallows %s", url)
                continue

            try:
                response = await self.client.get(url)
            except Exception as exc:  # pragma: no cover - defensive
                self.stats.pages_error += 1
                log.debug("crawl error %s: %s", url, exc)
                continue

            self.stats.pages_fetched += 1
            self._record_response(url, response, depth)

            if self.config.crawl.crawl_delay:
                await asyncio.sleep(self.config.crawl.crawl_delay)

            if not response.ok:
                continue
            if "html" not in response.content_type and "json" not in response.content_type:
                continue

            page = parse_html(url, response.text, response.content_type)
            self._enqueue(page, depth)

        self.stats.duration = time.monotonic() - started
        return list(self.endpoints.values()), self.forms, self.stats

    def _is_skippable_extension(self, path: str) -> bool:
        lowered = path.lower()
        for ext in self.config.crawl.skip_extensions:
            if lowered.endswith(ext):
                return True
        return False

    def _record_response(self, url: str, response: Response, depth: int) -> None:
        key = normalize_url(url)
        self.responses[key] = response
        if key in self.endpoints:
            return
        query_params = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        self.endpoints[key] = Endpoint(
            url=url,
            method="GET",
            status=response.status,
            title="",
            content_type=response.content_type,
            length=response.length,
            depth=depth,
            params=query_params,
        )

    def _enqueue(self, page: ParsedPage, depth: int) -> None:
        base = page.url

        for link in page.links:
            self.stats.links_discovered += 1
            if not self.scope.allows(link):
                host = urlparse(link).hostname or ""
                base_host = urlparse(base).hostname or ""
                if host and host != base_host:
                    self.stats.external_hosts.add(host)
                continue
            if normalize_url(link) not in self._seen:
                self._queue.append((link, depth + 1))

        for endpoint in page.endpoints:
            if self.scope.allows(endpoint) and normalize_url(endpoint) not in self._seen:
                self._queue.append((endpoint, depth + 1))

        for form in page.forms:
            self.stats.forms_discovered += 1
            self.stats.parameters_discovered += len(form.get("raw_fields", []))
            # The same form can be linked from several pages; only count it once.
            form_key = (
                form["method"],
                form["action"],
                tuple(sorted(form.get("raw_fields", []))),
            )
            if form_key in self._seen_forms:
                continue
            self._seen_forms.add(form_key)
            self.forms.append(
                Form(
                    action=form["action"],
                    method=form["method"],
                    fields=form.get("fields", {}),
                    raw_fields=form.get("raw_fields", []),
                    has_file_upload=form.get("has_file_upload", False),
                    source_url=form["source_url"],
                )
            )
            action = form["action"]
            if self.scope.allows(action) and normalize_url(action) not in self._seen:
                self._queue.append((action, depth + 1))
