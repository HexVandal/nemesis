"""Abuse of the things that make a server work: cost, order, and cache keys."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

_PRIVATE_MARKERS = re.compile(r"(logout|sign out|my account|dashboard|email|order history)", re.I)


class GraphqlDepthModule(Module):
    """How much work will the server accept in one request?"""

    group = "api"
    id = "graphql_depth_abuse"
    name = "GraphQL Depth and Cost Unbounded"
    description = (
        "Sends a deeply nested introspection query and reports endpoints that "
        "answer it in full."
    )
    severity = Severity.LOW
    confidence = Confidence.CONFIRMED
    category = Category.DOS
    capability = Capability.HTTP
    cwe = "CWE-770"
    owasp = "A04"
    remediation = "Cap query depth and cost, and disable introspection in production."
    references = ["https://owasp.org/www-project-api-security/"]
    tags = ["graphql", "dos", "active"]

    query = (
        "{__schema{types{fields{type{fields{type{fields{type{fields{"
        "type{name}}}}}}}}}}"
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint in ctx.endpoints[:4]:
            if "graphql" not in endpoint.url.lower():
                continue
            response = await ctx.client.post(
                endpoint.url,
                json={"query": self.query},
                headers={"Content-Type": "application/json"},
                follow_redirects=False,
            )
            if response.status != 200 or '"data"' not in (response.text or ""):
                continue
            findings.append(
                self.finding(
                    title=f"Deep GraphQL query accepted on {endpoint.url}",
                    target=endpoint.url,
                    description=(
                        "A six-level nested introspection query returned data. "
                        "Depth like this multiplies the work per request, and the "
                        "same shape can be used with aliases to exhaust a worker."
                    ),
                    evidence_text=f"POST {endpoint.url}\n  depth: 6\n  status: {response.status}",
                    matched="deep query answered",
                )
            )
        return findings


class RateLimitBypassModule(Module):
    """A limit keyed on a header the client controls is not a limit."""

    group = "config"
    id = "rate_limit_bypass"
    name = "Rate Limit Keyed on a Spoofable Header"
    description = (
        "Trips the limit, then repeats the same traffic with rotating "
        "X-Forwarded-For values and reports the endpoints that stop resisting."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-307"
    owasp = "A04"
    remediation = "Key throttling on the authenticated principal or the socket address, never on X-Forwarded-For."
    references = ["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"]
    tags = ["ratelimit", "bypass", "active"]

    burst: int = 12

    async def run(self, ctx: ScanContext) -> list[Finding]:
        url = ctx.target_url
        hit_limit = False
        for _ in range(self.burst):
            response = await ctx.client.get(url, follow_redirects=False)
            if response.status == 429:
                hit_limit = True
                break
        if not hit_limit:
            return []

        for index in range(self.burst):
            response = await ctx.client.get(
                url, headers={"X-Forwarded-For": f"198.51.100.{index + 1}"},
                follow_redirects=False,
            )
            if response.status == 429:
                return []
        return [
            self.finding(
                title="Rate limit bypassed by rotating X-Forwarded-For",
                target=url,
                description=(
                    f"The endpoint returned 429 after repeated requests, then "
                    f"answered all {self.burst} requests once each carried a "
                    f"different X-Forwarded-For value. The limiter trusts a header "
                    f"the client writes."
                ),
                evidence_text=(
                    f"GET {url} x{self.burst}                    -> 429\n"
                    f"GET {url} x{self.burst} with rotated XFF -> 200"
                ),
                matched="X-Forwarded-For bypass",
            )
        ]


class CacheDeceptionModule(Module):
    """Ask for a private page with a static extension and see who wins."""

    group = "cache"
    id = "cache_deception"
    name = "Web Cache Deception"
    description = (
        "Appends a static extension to discovered paths and reports the ones "
        "that still return the private page."
    )
    severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-525"
    owasp = "A05"
    remediation = "Cache on the full path and the session, and never treat an extension as a cache key."
    references = ["https://portswigger.net/web-security/web-cache-deception"]
    tags = ["cache", "deception", "active"]

    suffixes = ["/x.css", "/x.js", "/x.png"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for endpoint in ctx.endpoints[:6]:
            path = urlparse(endpoint.url).path.rstrip("/")
            if not path or path in seen:
                continue
            seen.add(path)
            original = await ctx.client.get(endpoint.url, follow_redirects=False)
            if original.status != 200 or not _PRIVATE_MARKERS.search(original.text or ""):
                continue
            root = ctx.target_url.rstrip("/")
            for suffix in self.suffixes:
                probe = await ctx.client.get(f"{root}{path}{suffix}", follow_redirects=False)
                if probe.status != 200 or not probe.text:
                    continue
                if _PRIVATE_MARKERS.search(probe.text) and len(probe.text) > 0.8 * len(original.text):
                    findings.append(
                        self.finding(
                            title=f"Private page served with a static extension: {path}{suffix}",
                            target=f"{root}{path}{suffix}",
                            description=(
                                "The account page answered at a path ending in a "
                                "static extension. A CDN caches by extension, so the "
                                "authenticated response lands in a cache shared with "
                                "everyone else."
                            ),
                            evidence_text=(
                                f"GET {endpoint.url}      -> 200, {len(original.text)} bytes\n"
                                f"GET {root}{path}{suffix} -> 200, {len(probe.text)} bytes"
                            ),
                            matched=suffix,
                        )
                    )
                    break
        return findings


class CacheControlModule(Module):
    """Authenticated responses that a shared cache is allowed to keep."""

    group = "headers"
    id = "cache_control_misconfig"
    name = "Cacheable Authenticated Response"
    description = (
        "Reports responses that set a session cookie or show account chrome "
        "without a no-store directive."
    )
    severity = Severity.LOW
    confidence: Confidence = Confidence.CONFIRMED
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-525"
    owasp = "A05"
    remediation = "Send Cache-Control: no-store on every authenticated response."
    references = ["https://cwe.mitre.org/data/definitions/525.html"]
    tags = ["cache", "headers", "passive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for response in ctx.responses:
            headers = {k.lower(): v for k, v in getattr(response, "headers", {}).items()}
            if "set-cookie" not in headers:
                continue
            control = headers.get("cache-control", "")
            if "no-store" in control or "private" in control:
                continue
            if not _PRIVATE_MARKERS.search(getattr(response, "text", "") or ""):
                continue
            findings.append(
                self.finding(
                    title="Account response is cacheable",
                    target=getattr(response, "url", ctx.target_url),
                    description=(
                        "The response issues a session cookie and shows account "
                        f"content, but its Cache-Control is "
                        f"'{control or 'absent'}'. A shared cache may keep it."
                    ),
                    evidence_text=(
                        f"GET {getattr(response, 'url', '')}\n"
                        f"  Cache-Control: {control or '(absent)'}\n"
                        "  Set-Cookie: present"
                    ),
                    matched=control or "(absent)",
                )
            )
        return findings[:5]


class RaceConditionModule(Module):
    """Fire the same state change at once and count how many land."""

    group = "logic"
    id = "race_condition"
    name = "Race Condition in State Change"
    description = (
        "Sends six identical state-changing requests concurrently and reports "
        "when more than one succeeds."
    )
    severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    category = Category.BUG
    capability = Capability.DESTRUCTIVE
    cwe = "CWE-362"
    owasp = "A04"
    remediation = "Make the state transition atomic: one row lock, one conditional update."
    references = ["https://cwe.mitre.org/data/definitions/362.html"]
    tags = ["race", "concurrency", "destructive"]

    attempts: int = 6
    skip = re.compile(r"(login|signin|sign-in|register|logout)", re.I)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for form in ctx.forms[:3]:
            if form.method.lower() != "post" or self.skip.search(form.action):
                continue
            body = {k: (v or "nemesis") for k, v in form.fields.items()}
            responses = await asyncio.gather(
                *(
                    ctx.client.post(form.action, data=dict(body), follow_redirects=False)
                    for _ in range(self.attempts)
                ),
                return_exceptions=True,
            )
            ok = [r for r in responses if not isinstance(r, Exception) and 200 <= r.status < 300]
            if len(ok) < 2:
                continue
            bodies = {r.text for r in ok}
            if len(bodies) == 1:
                # Identical answers are usually an idempotent read; not a race.
                continue
            findings.append(
                self.finding(
                    title=f"{len(ok)} concurrent submissions all succeeded on {form.action}",
                    target=form.action,
                    description=(
                        f"{self.attempts} identical requests were sent at once and "
                        f"{len(ok)} of them returned success with different bodies. "
                        f"Whatever this action changes - stock, balance, a claim - "
                        f"was changed more than once."
                    ),
                    evidence_text=(
                        f"POST {form.action} x{self.attempts} concurrently\n"
                        f"  successes: {len(ok)}\n"
                        f"  distinct response bodies: {len(bodies)}"
                    ),
                    matched=f"{len(ok)} successes",
                )
            )
        return findings
