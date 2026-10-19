"""DNS posture checks."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: Hosting providers whose dangling CNAME usually means a claimable subdomain.
_CLAIMABLE = {
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "elastic-cloud.com": "Elastic Cloud",
    "s3.amazonaws.com": "Amazon S3",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure App Service",
    "web.app": "Firebase",
    "firebaseapp.com": "Firebase",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "pages.dev": "Cloudflare Pages",
    "readthedocs.io": "Read the Docs",
    "blogspot.com": "Blogspot",
    "myshopify.com": "Shopify",
    "zendesk.com": "Zendesk",
    "hubspot.com": "HubSpot",
    "fastly.net": "Fastly",
    "cloudfront": "AWS CloudFront",
    "s3-website": "Amazon S3",
    "azureedge.net": "Azure CDN",
    "linodeobjects.com": "Linode",
    "digitaloceanspaces.com": "DigitalOcean",
}


def _is_ip_literal(host: str) -> bool:
    """True when *host* is an IPv4/IPv6 literal rather than a domain name."""
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class DnsPostureModule(Module):
    """Check SPF, DMARC, CAA and dangling CNAME records."""
    group = "host"

    id = "dns_posture"
    name = "DNS Posture"
    description = (
        "Checks that SPF, DMARC and CAA records exist and are not permissive, "
        "and looks for CNAMEs pointing at claimable hosting providers."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.HOST
    cwe = "CWE-284"
    owasp = "A05"
    tags = ["dns", "spf", "dmarc", "host"]
    remediation = (
        "Publish a restrictive SPF record, a DMARC policy of `p=quarantine` or "
        "stricter, and a CAA record listing the intended certificate authorities."
    )
    references = [
        "https://owasp.org/www-project-cheat-sheets/",
        "https://www.owasp.org/www-project-email-security/",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        host = (urlparse(ctx.target_url).hostname or ctx.host or "").lower()
        if not host:
            return []

        # SPF/DMARC/CAA are domain-level controls. Running them against a bare
        # IP address or localhost produces meaningless noise.
        if _is_ip_literal(host) or host in ("localhost", "127.0.0.1", "::1"):
            return []

        try:
            import dns.resolver
        except ImportError:
            return []

        findings: list[Finding] = []
        loop = asyncio.get_running_loop()

        spf = await self._query(loop, dns.resolver, host, "TXT")
        dmarc = await self._query(loop, dns.resolver, f"_dmarc.{host}", "TXT")
        caa = await self._query(loop, dns.resolver, host, "CAA")
        cname = await self._query(loop, dns.resolver, host, "CNAME")

        # -- SPF ------------------------------------------------------------
        spf_records = [r for r in spf if r.lower().startswith("v=spf1")]
        if not spf_records:
            findings.append(
                self.finding(
                    title="No SPF record published",
                    target=host,
                    description=(
                        f"{host} publishes no SPF record, so any host may send email "
                        "that appears to come from this domain. This enables "
                        "phishing and reputation abuse."
                    ),
                    confidence=Confidence.MEDIUM,
                    evidence_text=f"TXT query for {host} returned: {spf or '(empty)'}",
                    matched=host,
                )
            )
        else:
            record = spf_records[0]
            if "+all" in record.lower():
                findings.append(
                    self.finding(
                        title="SPF record ends with +all (permissive)",
                        target=host,
                        description=(
                            f"The SPF record for {host} ends with `+all`, authorising "
                            "every host in the world to send mail as this domain. Use "
                            "`~all` or `-all` instead."
                        ),
                        severity=Severity.MEDIUM,
                        evidence_text=record,
                        matched="+all",
                    )
                )

        # -- DMARC ----------------------------------------------------------
        dmarc_records = [r for r in dmarc if r.lower().startswith("v=dmarc1")]
        if not dmarc_records:
            findings.append(
                self.finding(
                    title="No DMARC record published",
                    target=host,
                    description=(
                        f"{host} publishes no DMARC record, so spoofed email is not "
                        "reported and receivers have no instruction on what to do "
                        "with it."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    evidence_text=f"TXT query for _dmarc.{host} returned: {dmarc or '(empty)'}",
                    matched=host,
                )
            )
        else:
            record = dmarc_records[0]
            policy = re.search(r"p=(\w+)", record.lower())
            if policy and policy.group(1) == "none":
                findings.append(
                    self.finding(
                        title="DMARC policy is p=none (monitoring only)",
                        target=host,
                        description=(
                            f"The DMARC record for {host} is set to `p=none`, which only "
                            "collects reports and takes no action against spoofed "
                            "email. Move to `p=quarantine` and then `p=reject`."
                        ),
                        severity=Severity.LOW,
                        evidence_text=record,
                        matched="p=none",
                    )
                )

        # -- CAA ------------------------------------------------------------
        if not caa:
            findings.append(
                self.finding(
                    title="No CAA record published",
                    target=host,
                    description=(
                        f"{host} publishes no CAA record, so any public certificate "
                        "authority may issue a certificate for it. A CAA record "
                        "restricts issuance to the intended CAs."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    evidence_text=f"CAA query for {host} returned: '(empty)'",
                    matched=host,
                )
            )

        # -- Dangling CNAME -------------------------------------------------
        if cname:
            target = cname[0].lower().rstrip(".")
            for suffix, provider in _CLAIMABLE.items():
                if target.endswith(suffix):
                    findings.append(
                        self.finding(
                            title=f"CNAME points at a {provider} target - verify it is claimed",
                            target=host,
                            description=(
                                f"{host} is a CNAME for {target}, a {provider} endpoint. "
                                "If the corresponding resource has been removed but the "
                                "DNS record remains, the subdomain can be claimed by "
                                "an attacker and used for cookie or trust attacks."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            evidence_text=f"CNAME {host} -> {target}",
                            matched=target,
                        )
                    )
                    break

        return findings

    async def _query(self, loop, resolver, name: str, record_type: str) -> list[str]:
        def _do() -> list[str]:
            try:
                answers = resolver.resolve(name, record_type)
                return [str(r).strip('"') for r in answers]
            except Exception:
                return []

        try:
            return await loop.run_in_executor(None, _do)
        except Exception:
            return []
