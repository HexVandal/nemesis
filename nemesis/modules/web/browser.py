"""Browser-side security.

The headers module checks for the presence of security headers. This one
checks what they actually *do*, because a header that is present and
useless is worse than one that is absent - it produces a green tick in a
review and no protection at all.

- **CSP that does not protect.** A policy with `unsafe-inline` in
  `script-src` permits exactly the XSS it is supposed to prevent. A
  policy with a bare `*` permits everything. A policy with no
  `default-src` falls back to `allow-all` for anything not named. A
  policy with `unsafe-eval` re-enables `eval`, which is the single most
  common way a CSP gets bypassed.
- **Cookie prefixes.** `__Host-` and `__Secure-` prefixes make the
  browser enforce properties the server can only ask for. A `__Host-`
  cookie without `Secure`, without `Path=/`, or with a `Domain` attribute
  is rejected by the browser - which is a configuration bug the browser
  is silently swallowing.
- **Trusted Types.** The only modern control that stops DOM XSS at the
  sink rather than at the source.
- **COOP / COEP / CORP.** The cross-origin isolation trio, which is what
  Spectre needs in order to be hard to exploit.
- **HSTS.** A policy without `includeSubDomains` or without a long
  max-age is a policy that expires in practice.

This module reads the headers the scanner already collected, so it costs
no additional requests.
"""

from __future__ import annotations

import re

from ...knowledge.csp import parse_policy
from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: CSP directives that make a script policy permissive.
DANGEROUS_SCRIPT_SOURCES = ("'unsafe-inline'", "'unsafe-eval'", "data:", "blob:")

#: The `__Host-` cookie prefix rules.
HOST_PREFIX_RULES = {
    "secure": "a __Host- cookie must carry the Secure attribute",
    "path": "a __Host- cookie must have Path=/",
    "domain": "a __Host- cookie must not have a Domain attribute",
}

#: The `__Secure-` cookie prefix rules.
SECURE_PREFIX_RULES = {
    "secure": "a __Secure- cookie must carry the Secure attribute",
}


class BrowserSecurityModule(Module):
    """Reports browser security headers that are present but ineffective."""

    group = "headers"
    id = "browser_security"
    name = "Browser Security"
    description = (
        "Checks that the browser security headers actually protect: a CSP "
        "that permits unsafe-inline is not a CSP, a __Host- cookie "
        "without Secure is silently rejected by the browser, and a "
        "cross-origin isolation header that is not accompanied by its "
        "partners does not enable isolation."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-1021"
    owasp = "A05"
    tags = ["browser", "csp", "cookies", "trusted-types", "hsts", "headers"]
    remediation = (
        "Make the policy mean something: remove unsafe-inline and "
        "unsafe-eval from script-src and use nonces or hashes, set "
        "default-src so anything unlisted is denied, add includeSubDomains "
        "to HSTS with a max-age of at least a year, and use the __Host- "
        "cookie prefix so the browser enforces the attributes instead of "
        "trusting the server to set them."
    )
    references = [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
        "https://web.dev/articles/strict-origin-when-cross-origin-isolated",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen_csp: set[str] = set()
        seen_hsts: set[str] = set()
        seen_coi: set[str] = set()

        for response in ctx.responses:
            csp = response.header("content-security-policy")
            if csp and response.url not in seen_csp:
                seen_csp.add(response.url)
                findings.extend(self._csp_findings(response.url, csp))

            hsts = response.header("strict-transport-security")
            if hsts and response.url not in seen_hsts:
                seen_hsts.add(response.url)
                findings.extend(self._hsts_findings(response.url, hsts))

            findings.extend(self._cookie_prefix_findings(response))
            findings.extend(self._isolation_findings(response, seen_coi))

        return findings

    # -- CSP -------------------------------------------------------------
    def _csp_findings(self, url: str, header: str) -> list[Finding]:
        findings: list[Finding] = []
        policy = parse_policy(header)
        if policy is None:
            return findings

        script = policy.effective("script-src")
        if script is not None:
            dangerous = [
                source
                for source in script.sources
                if source.lower() in DANGEROUS_SCRIPT_SOURCES
            ]
            if dangerous:
                findings.append(
                    self.finding(
                        title="Content-Security-Policy permits unsafe script sources",
                        target=url,
                        description=(
                            f"The script-src directive allows "
                            f"{', '.join(dangerous)}. 'unsafe-inline' lets "
                            f"an injected script tag run, and 'unsafe-eval' "
                            f"lets an injected string be evaluated - between "
                            f"them they remove most of what a CSP is for. A "
                            f"policy that contains them is a policy that "
                            f"stops a reflected XSS from being stored, and "
                            f"nothing else."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        evidence_text=f"URL: {url}\nCSP: {header}",
                        matched=", ".join(dangerous),
                    )
                )

        if policy.get("default-src") is None:
            # Without a default-src, every directive that is not named
            # falls back to allow-all.
            named = {d.name for d in policy.directives}
            if not ({"script-src", "object-src"} & named):
                findings.append(
                    self.finding(
                        title="Content-Security-Policy has no default-src and no script-src",
                        target=url,
                        description=(
                            "The policy names neither default-src nor "
                            "script-src. Every resource type that is not "
                            "named explicitly is allowed from anywhere, "
                            "which means the policy constrains almost "
                            "nothing."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        evidence_text=f"URL: {url}\nCSP: {header}",
                        matched="no default-src",
                    )
                )

        if policy.get("object-src") is None:
            findings.append(
                self.finding(
                    title="Content-Security-Policy does not restrict object-src",
                    target=url,
                    description=(
                        "Without object-src, the policy falls back to "
                        "allowing plugins, and a page that can embed an "
                        "object can be used to serve content that runs in "
                        "the page's origin. 'none' is the correct value."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    evidence_text=f"URL: {url}\nCSP: {header}",
                    matched="object-src",
                )
            )

        if policy.get("frame-ancestors") is None:
            findings.append(
                self.finding(
                    title="Content-Security-Policy does not restrict frame-ancestors",
                    target=url,
                    description=(
                        "frame-ancestors is the CSP equivalent of "
                        "X-Frame-Options, and it is the one that works in "
                        "every browser. Without it the page can be framed "
                        "even if the X-Frame-Options header says otherwise."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    evidence_text=f"URL: {url}\nCSP: {header}",
                    matched="frame-ancestors",
                )
            )

        return findings

    # -- HSTS ------------------------------------------------------------
    def _hsts_findings(self, url: str, header: str) -> list[Finding]:
        findings: list[Finding] = []
        lowered = header.lower()
        max_age = re.search(r"max-age\s*=\s*(\d+)", lowered)
        if not max_age or int(max_age.group(1)) < 31536000:
            findings.append(
                self.finding(
                    title="HSTS max-age is shorter than a year",
                    target=url,
                    description=(
                        f"The Strict-Transport-Security header carries "
                        f"max-age={max_age.group(1) if max_age else 'unset'}. "
                        f"A year is the minimum that browsers accept for "
                        f"preload, and anything shorter means a browser "
                        f"that has been offline for a while forgets the "
                        f"policy and an attacker who controls the first "
                        f"request gets a cleartext one."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence_text=f"URL: {url}\nHSTS: {header}",
                    matched="max-age",
                )
            )
        if "includesubdomains" not in lowered:
            findings.append(
                self.finding(
                    title="HSTS does not include subdomains",
                    target=url,
                    description=(
                        "Without includeSubDomains the policy protects one "
                        "hostname. Every subdomain of the domain is still "
                        "reachable over cleartext, and an attacker who can "
                        "point a subdomain somewhere can use it."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence_text=f"URL: {url}\nHSTS: {header}",
                    matched="includeSubDomains",
                )
            )
        if "preload" not in lowered:
            findings.append(
                self.finding(
                    title="HSTS is not set to preload",
                    target=url,
                    description=(
                        "Preloading removes the first-visit window in "
                        "which an attacker can intercept the request. It is "
                        "the difference between HSTS that protects a "
                        "returning visitor and HSTS that protects everyone."
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    evidence_text=f"URL: {url}\nHSTS: {header}",
                    matched="preload",
                )
            )
        return findings

    # -- cookies ---------------------------------------------------------
    def _cookie_prefix_findings(self, response) -> list[Finding]:
        findings: list[Finding] = []
        for header in response.header("set-cookie", "").split(","):
            if "__Host-" not in header:
                continue
            lowered = header.lower()
            problems = []
            if "secure" not in lowered:
                problems.append(HOST_PREFIX_RULES["secure"])
            if not re.search(r"path\s*=\s*/\s*($|;)", lowered):
                problems.append(HOST_PREFIX_RULES["path"])
            if re.search(r"domain\s*=", lowered):
                problems.append(HOST_PREFIX_RULES["domain"])
            if problems:
                findings.append(
                    self.finding(
                        title="__Host- cookie violates the prefix rules",
                        target=response.url,
                        description=(
                            f"The browser will reject this cookie entirely "
                            f"because it breaks the __Host- prefix rules: "
                            f"{'; '.join(problems)}. A rejected cookie is a "
                            f"silent failure - the session still works in "
                            f"development, where the browser is more "
                            f"forgiving, and stops working in production."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        evidence_text=f"URL: {response.url}\nSet-Cookie: {header[:300]}",
                        matched="__Host-",
                    )
                )
        return findings

    # -- cross-origin isolation ------------------------------------------
    def _isolation_findings(self, response, seen: set[str]) -> list[Finding]:
        findings: list[Finding] = []
        coop = response.header("cross-origin-opener-policy")
        coep = response.header("cross-origin-embedder-policy")
        corp = response.header("cross-origin-resource-policy")

        if not (coop or coep or corp):
            return findings

        if response.url in seen:
            return findings
        seen.add(response.url)

        missing = []
        if not coop:
            missing.append("Cross-Origin-Opener-Policy")
        if not coep:
            missing.append("Cross-Origin-Embedder-Policy")
        if missing:
            findings.append(
                self.finding(
                    title="Cross-origin isolation is incomplete",
                    target=response.url,
                    description=(
                        f"The response sets some cross-origin isolation "
                        f"headers but is missing {', '.join(missing)}. The "
                        f"headers only work as a set: COOP without COEP "
                        f"does not put the page in a cross-origin isolated "
                        f"context, so a cross-origin resource can still "
                        f"reach into it. That is the window a Spectre-style "
                        f"attack needs."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    evidence_text=(
                        f"URL  : {response.url}\n"
                        f"COOP : {coop or '(missing)'}\n"
                        f"COEP : {coep or '(missing)'}\n"
                        f"CORP : {corp or '(missing)'}"
                    ),
                    matched=", ".join(missing),
                )
            )
        return findings
