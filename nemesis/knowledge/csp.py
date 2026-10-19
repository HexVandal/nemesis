"""Content Security Policy parsing and analysis.

A CSP is a small language that people get wrong in a small number of
predictable ways. The parser here resolves directives, expands the
wildcard and scheme-source forms, and reports the gaps that actually
matter rather than every deviation from the spec.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: The CSP directives nemesis understands, and what each one controls.
DIRECTIVE_PURPOSE = {
    "default-src": "fallback for every fetch directive",
    "script-src": "script execution",
    "style-src": "stylesheets and inline style attributes",
    "img-src": "images",
    "font-src": "fonts",
    "connect-src": "XHR, fetch and WebSocket connections",
    "frame-src": "frames",
    "child-src": "frames and workers",
    "object-src": "plugins and <object>/<embed>",
    "media-src": "audio and video",
    "manifest-src": "web app manifests",
    "worker-src": "web workers",
    "frame-ancestors": "who may frame this page",
    "form-action": "where forms may submit",
    "base-uri": "the <base> element",
    "report-uri": "where violation reports are sent",
    "report-to": "where violation reports are sent",
    "sandbox": "sandboxing applied to the page",
    "upgrade-insecure-requests": "upgrades http subresources",
    "block-all-mixed-content": "blocks mixed content",
    "require-trusted-types-for": "Trusted Types enforcement",
    "trusted-types": "allowlisted Trusted Types policies",
    "script-src-elem": "script elements specifically",
    "script-src-attr": "inline event handlers specifically",
    "style-src-elem": "style elements specifically",
    "style-src-attr": "style attributes specifically",
    "plugin-types": "plugin types",
}


@dataclass
class Directive:
    """One CSP directive and the sources it allows."""

    name: str
    sources: list[str] = field(default_factory=list)

    @property
    def purpose(self) -> str:
        return DIRECTIVE_PURPOSE.get(self.name, "")

    @property
    def allows_wildcard(self) -> bool:
        return "*" in self.sources

    @property
    def allows_unsafe_inline(self) -> bool:
        return "'unsafe-inline'" in self.sources

    @property
    def allows_unsafe_eval(self) -> bool:
        return "'unsafe-eval'" in self.sources

    @property
    def allows_data(self) -> bool:
        return "data:" in self.sources

    @property
    def allows_http(self) -> bool:
        return "http:" in self.sources

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "sources": list(self.sources),
            "purpose": self.purpose,
        }


@dataclass
class CspPolicy:
    """A parsed Content-Security-Policy."""

    directives: list[Directive] = field(default_factory=list)
    raw: str = ""

    def get(self, name: str) -> Directive | None:
        for directive in self.directives:
            if directive.name == name:
                return directive
        return None

    def effective(self, name: str) -> Directive | None:
        """The directive that actually governs *name*.

        ``script-src`` covers everything except inline handlers, which are
        governed by ``script-src-attr``; ``default-src`` is the fallback
        for anything not otherwise specified.
        """
        directive = self.get(name)
        if directive is not None:
            return directive
        if name == "script-src":
            return self.get("script-src-elem") or self.get("default-src")
        if name == "style-src":
            return self.get("style-src-elem") or self.get("default-src")
        return self.get("default-src")

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "directives": [d.to_dict() for d in self.directives],
        }


def parse_policy(header: str) -> CspPolicy:
    """Parse a Content-Security-Policy header value.

    Multiple policies separated by commas are handled by treating a
    repeated directive as a second, independent directive - the browser
    enforces all of them, so the effective rule is the intersection.
    """
    policy = CspPolicy(raw=header or "")
    if not header:
        return policy

    for chunk in _split_directives(header):
        parts = chunk.split()
        if not parts:
            continue
        name = parts[0].lower()
        sources = [source.lower() for source in parts[1:]]
        policy.directives.append(Directive(name=name, sources=sources))
    return policy


def _split_directives(header: str) -> list[str]:
    """Split a header into individual directives.

    A Content-Security-Policy is a list of directives separated by
    semicolons, and a header may carry several policies separated by
    commas - the browser enforces all of them, so the effective rule is
    the intersection. Neither separator counts when it is inside a
    quoted nonce or hash.
    """
    directives: list[str] = []
    for policy in _split_outside_quotes(header, ","):
        for directive in _split_outside_quotes(policy, ";"):
            directive = directive.strip()
            if directive:
                directives.append(directive)
    return directives


def _split_outside_quotes(text: str, separator: str) -> list[str]:
    """Split *text* on *separator*, ignoring separators inside quotes."""
    chunks: list[str] = []
    current: list[str] = []
    in_quotes = False
    for char in text:
        if char == "'":
            in_quotes = not in_quotes
            current.append(char)
            continue
        if char == separator and not in_quotes:
            chunks.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    chunks.append("".join(current).strip())
    return [chunk for chunk in chunks if chunk]


@dataclass
class CspGap:
    """One weakness in a policy."""

    directive: str
    kind: str
    severity: str
    title: str
    detail: str
    remediation: str


#: Gaps that are always worth reporting.
_BASE_GAPS = {
    "unsafe-inline": (
        "medium",
        "'unsafe-inline' allows inline script to run",
        "Inline script and event handlers are allowed, which removes most of "
        "the protection a CSP provides against XSS.",
        "Remove 'unsafe-inline' and use a nonce or a hash for the scripts "
        "that genuinely need to run.",
    ),
    "unsafe-eval": (
        "high",
        "'unsafe-eval' allows string-to-code evaluation",
        "eval() and the Function constructor are allowed, so any injection "
        "point becomes code execution even with a strict CSP.",
        "Remove 'unsafe-eval'. Rewrite the code that needs it.",
    ),
    "wildcard": (
        "high",
        "a wildcard source allows any origin",
        "A bare '*' allows the directive's resource type to be loaded from "
        "any origin, which is close to no policy at all.",
        "Replace the wildcard with an explicit allowlist.",
    ),
    "data": (
        "medium",
        "data: URIs are allowed",
        "data: URIs bypass origin restrictions and are a common way to "
        "smuggle a payload past a policy.",
        "Remove data: unless a specific feature needs it, and use "
        "'strict-dynamic' with nonces where it is required.",
    ),
    "http": (
        "low",
        "plain http is allowed",
        "Resources can be loaded over an unencrypted connection, so a "
        "network attacker can modify them.",
        "Use https: sources, or add upgrade-insecure-requests.",
    ),
}


def analyse(policy: CspPolicy) -> list[CspGap]:
    """Report the weaknesses in a parsed policy."""
    gaps: list[CspGap] = []
    if not policy.directives:
        return gaps

    for directive in policy.directives:
        if directive.name not in ("script-src", "style-src", "default-src"):
            continue

        for source in directive.sources:
            if source == "*":
                kind = "wildcard"
            elif source == "'unsafe-inline'":
                kind = "unsafe-inline"
            elif source == "'unsafe-eval'":
                kind = "unsafe-eval"
            elif source == "data:":
                kind = "data"
            elif source == "http:":
                kind = "http"
            else:
                continue

            severity, title, detail, remediation = _BASE_GAPS[kind]
            # 'unsafe-inline' in a style directive is far less serious than
            # in a script directive.
            if kind == "unsafe-inline" and directive.name == "style-src":
                severity = "low"
            # A wildcard in default-src is less bad than in script-src.
            if kind == "wildcard" and directive.name == "default-src":
                severity = "medium"
            gaps.append(
                CspGap(
                    directive=directive.name,
                    kind=kind,
                    severity=severity,
                    title=f"Content Security Policy: {title}",
                    detail=(
                        f"The {directive} directive "
                        f"({directive.purpose or 'fetch directive'}) contains "
                        f"{source}. {detail}"
                    ),
                    remediation=remediation,
                )
            )

    # A missing script-src means default-src governs scripts.
    if policy.get("script-src") is None and policy.get("default-src") is None:
        gaps.append(
            CspGap(
                directive="-",
                kind="missing",
                severity="medium",
                title="Content Security Policy has no script-src or default-src",
                detail=(
                    "Without script-src or default-src the browser applies "
                    "no restriction on script sources at all."
                ),
                remediation=(
                    "Add a script-src directive with an explicit allowlist "
                    "or nonces."
                ),
            )
        )

    # frame-ancestors is the directive that actually stops clickjacking.
    if policy.get("frame-ancestors") is None:
        gaps.append(
            CspGap(
                directive="frame-ancestors",
                kind="missing",
                severity="low",
                title="Content Security Policy has no frame-ancestors directive",
                detail=(
                    "frame-ancestors is the modern way to prevent framing. "
                    "Without it the page relies on X-Frame-Options alone."
                ),
                remediation=(
                    "Add frame-ancestors 'none' or an explicit allowlist."
                ),
            )
        )

    # object-src 'none' stops plugin content.
    obj = policy.get("object-src")
    if obj is None or (obj.sources and "none" not in obj.sources and "*" not in obj.sources):
        gaps.append(
            CspGap(
                directive="object-src",
                kind="missing",
                severity="low",
                title="Content Security Policy does not restrict object-src",
                detail=(
                    "Plugins and <object>/<embed> content is not restricted, "
                    "which is a path to content sniffing and to some XSS "
                    "filter bypasses."
                ),
                remediation="Add object-src 'none'.",
            )
        )

    return gaps
