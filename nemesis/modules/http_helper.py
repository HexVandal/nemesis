"""Shared helpers for active HTTP modules.

Active modules follow the same loop: pick a parameter, send a benign
baseline, send the same request with a payload, and diff the two. This module
centralises that loop so individual checks stay short and consistent.
"""

from __future__ import annotations

import asyncio
import random
import string
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..http.client import Response
from ..models import Capability
from ..verify.verifier import Delta, compare
from .base import Module, ScanContext


#: A random marker makes it possible to prove that *our* input caused an
#: effect, and to distinguish it from coincidental content.
def make_marker(prefix: str = "nms") -> str:
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}{token}"


def replace_param(url: str, param: str, value: str) -> str:
    """Return *url* with *param* set to *value* (added if absent)."""
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    out: list[tuple[str, str]] = []
    for key, val in pairs:
        if key == param:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, val))
    if not replaced:
        out.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(out)))


def build_form_body(fields: dict[str, str], override: tuple[str, str] | None = None) -> dict[str, str]:
    body = {k: (v if v else "nemesis") for k, v in fields.items()}
    if override:
        body[override[0]] = override[1]
    return body


@dataclass
class ParamTarget:
    """A concrete (url, parameter) pair to attack."""

    url: str
    param: str
    method: str = "GET"
    fields: dict[str, str] | None = None

    @property
    def key(self) -> str:
        return f"{self.method}:{self.url}:{self.param}"


class HttpModule(Module):
    """Base class for modules that send crafted HTTP requests."""

    abstract = True
    capability: Capability = Capability.HTTP

    #: Maximum number of parameters this module will test.
    max_params: int = 25
    #: Maximum number of payloads tried per parameter.
    max_payloads: int = 12
    #: Parameters skipped because they look like identifiers.
    skip_params: set[str] = set()

    def collect_targets(self, ctx: ScanContext) -> list[ParamTarget]:
        """Gather candidate parameters from crawled endpoints and forms."""
        targets: list[ParamTarget] = []
        seen: set[str] = set()

        for endpoint in ctx.endpoints:
            for param in endpoint.params:
                if param.lower() in self.skip_params:
                    continue
                key = f"GET:{endpoint.url}:{param}"
                if key in seen:
                    continue
                seen.add(key)
                targets.append(ParamTarget(url=endpoint.url, param=param, method="GET"))

        for form in ctx.forms:
            for param in form.raw_fields:
                if param.lower() in self.skip_params:
                    continue
                key = f"{form.method}:{form.action}:{param}"
                if key in seen:
                    continue
                seen.add(key)
                targets.append(
                    ParamTarget(
                        url=form.action,
                        param=param,
                        method=form.method,
                        fields=dict(form.fields),
                    )
                )

        # Prefer parameters that are historically interesting.
        from ..crawler.parser import INTERESTING_PARAMS

        targets.sort(
            key=lambda t: (
                0 if t.param.lower() in INTERESTING_PARAMS else 1,
                -len(t.param),
            )
        )
        return targets[: self.max_params]

    async def fetch(
        self,
        ctx: ScanContext,
        target: ParamTarget,
        value: str,
    ) -> Response:
        """Fetch *target* with one parameter overridden to *value*.

        Redirects are deliberately **not** followed. A baseline and a probe
        that take different code paths (one redirected, one did not) produce
        a meaningless diff and a false positive; keeping both responses at
        the first hop makes them comparable.
        """
        if target.method == "GET" or not target.fields:
            url = replace_param(target.url, target.param, value)
            return await ctx.client.get(url, follow_redirects=False)
        body = build_form_body(target.fields, (target.param, value))
        return await ctx.client.post(target.url, data=body, follow_redirects=False)

    async def baseline(self, ctx: ScanContext, target: ParamTarget) -> Response:
        """A benign request against the same parameter."""
        return await self.fetch(ctx, target, "nemesis_baseline_value")

    @staticmethod
    def benign_equivalent(payload: str) -> str:
        """A harmless value with the **same length** as *payload*.

        Length matching is essential. If the baseline were a long constant
        and the payload were a single quote, every response would differ in
        length simply because the echoed value was shorter - and the scanner
        would report an injection on every parameter. With a length-matched
        baseline, a length difference can only come from the server doing
        something different.
        """
        if not payload:
            return "A"
        if payload.isdigit():
            return "9" * len(payload)
        if payload.isalpha():
            return "A" * len(payload)
        # Keep the shape (so numeric-ish and URL-ish payloads stay valid)
        # but neutralise every character that could carry meaning.
        out: list[str] = []
        for char in payload:
            if char.isdigit():
                out.append("9")
            elif char.isalpha():
                out.append("A")
            else:
                out.append("x")
        return "".join(out)

    async def probe(
        self,
        ctx: ScanContext,
        target: ParamTarget,
        payload: str,
        signatures: list[tuple[str, str]] | None = None,
    ) -> Delta:
        """Send *payload* and diff it against a length-matched baseline."""
        base = await self.fetch(ctx, target, self.benign_equivalent(payload))
        probe = await self.fetch(ctx, target, payload)
        return compare(base, probe, payload=payload, signatures=signatures)

    async def iter_deltas(
        self,
        ctx: ScanContext,
        target: ParamTarget,
        payloads: Iterable[str],
        signatures: list[tuple[str, str]] | None = None,
        stop_on_hit: bool = True,
    ) -> AsyncIterator[tuple[str, Delta]]:
        """Yield ``(payload, delta)`` for each payload, optionally stopping early."""
        for payload in list(payloads)[: self.max_payloads]:
            delta = await self.probe(ctx, target, payload, signatures)
            yield payload, delta
            if stop_on_hit and delta.new_signatures:
                return

    async def limited_gather(self, coros: list) -> list:
        """Run coroutines with a small concurrency window."""
        semaphore = asyncio.Semaphore(6)

        async def _run(coro):
            async with semaphore:
                return await coro

        return await asyncio.gather(*(_run(c) for c in coros), return_exceptions=True)
