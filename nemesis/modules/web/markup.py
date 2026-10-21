"""What the HTML itself gives away, once it is parsed rather than grepped."""

from __future__ import annotations

from urllib.parse import urlparse

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _attr(tag: str, name: str) -> str | None:
    lowered = tag.lower()
    marker = f"{name}="
    index = lowered.find(marker)
    if index == -1:
        return None
    rest = tag[index + len(marker) :].lstrip()
    if not rest or rest[0] not in "\"'":
        return rest.split(">")[0].split()[0] if rest else ""
    quote = rest[0]
    end = rest.find(quote, 1)
    return rest[1:end] if end != -1 else None


def _tags(text: str, name: str) -> list[str]:
    lowered = text.lower()
    out: list[str] = []
    start = 0
    needle = f"<{name}"
    while True:
        index = lowered.find(needle, start)
        if index == -1:
            return out
        end = lowered.find(">", index)
        if end == -1:
            return out
        out.append(text[index : end + 1])
        start = end + 1


class SriModule(Module):
    """A third-party script without an integrity hash can change under you.

    The CDN, its DNS, its TLS or the account that owns the bucket all become
    part of your trust boundary - silently.
    """

    group = "browser"

    id = "sri_missing"
    name = "Missing Subresource Integrity"
    description = (
        "Reports third-party scripts and stylesheets loaded without an "
        "integrity attribute."
    )
    severity = Severity.LOW
    confidence = Confidence.CONFIRMED
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-353"
    owasp = "A08"
    remediation = (
        "Add integrity and crossorigin attributes to every cross-origin "
        "script and stylesheet, or self-host the asset."
    )
    references = ["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"]
    tags = ["browser", "supply-chain", "passive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        reported: set[str] = set()
        for response in ctx.responses:
            text = getattr(response, "text", "") or ""
            if "<script" not in text and "<link" not in text:
                continue
            page_origin = _origin(getattr(response, "url", ctx.target_url))
            for tag in _tags(text, "script") + _tags(text, "link"):
                src = _attr(tag, "src") or _attr(tag, "href")
                if not src or not src.startswith(("http://", "https://")):
                    continue
                if _origin(src) == page_origin or src in reported:
                    continue
                if _attr(tag, "integrity"):
                    continue
                reported.add(src)
                findings.append(
                    self.finding(
                        title=f"Third-party asset without integrity: {src}",
                        target=src,
                        description=(
                            f"{getattr(response, 'url', ctx.target_url)} loads {src} "
                            f"from another origin with no integrity hash. Whatever "
                            f"that host serves next will execute in this origin."
                        ),
                        evidence_text=f"<script src=\"{src}\"> on {getattr(response, 'url', '')}",
                        matched=src,
                    )
                )
        return findings


class ReverseTabnabbingModule(Module):
    """target=_blank without noopener lets the new tab rewrite this one."""

    group = "browser"

    id = "reverse_tabnabbing"
    name = "Reverse Tabnabbing"
    description = (
        "Reports links that open a new tab with target=_blank but no "
        "rel=noopener or noreferrer."
    )
    severity = Severity.LOW
    confidence = Confidence.CONFIRMED
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-1022"
    owasp = "A05"
    remediation = "Add rel=\"noopener noreferrer\" to every target=\"_blank\" link."
    references = ["https://cwe.mitre.org/data/definitions/1022.html"]
    tags = ["browser", "passive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for response in ctx.responses:
            text = getattr(response, "text", "") or ""
            page_url = getattr(response, "url", ctx.target_url)
            for tag in _tags(text, "a"):
                target = (_attr(tag, "target") or "").lower()
                if target != "_blank":
                    continue
                rel = (_attr(tag, "rel") or "").lower()
                if "noopener" in rel or "noreferrer" in rel:
                    continue
                href = _attr(tag, "href") or "(no href)"
                findings.append(
                    self.finding(
                        title=f"target=_blank without rel=noopener on {page_url}",
                        target=page_url,
                        description=(
                            f"The link to {href} opens in a new tab that keeps a "
                            f"handle on this window. The linked page can replace "
                            f"this tab with a phishing form."
                        ),
                        evidence_text=tag,
                        matched=href,
                    )
                )
        return findings
