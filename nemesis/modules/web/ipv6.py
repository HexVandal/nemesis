"""IPv6-specific security issues.

IPv6 breaks a lot of assumptions that IPv4 made safe, and most of the
breakage is in *parsing*, not in the protocol. The recurring bugs are:

- **IPv4-mapped address confusion** - ``::ffff:127.0.0.1`` is an IPv4
  address wearing an IPv6 hat. A check that string-matches for
  ``127.0.0.1`` misses it; a check that only understands IPv6 misses it
  in the other direction. An allow-list that handles only one of the two
  forms is bypassable.
- **Zone identifiers** - ``fe80::1%25eth0`` names a link-local address on
  a specific interface. Two URLs that differ only by zone can reach
  different hosts, and a naive comparison treats them as one.
- **Unbracketed literals** - ``http://[::1]:8080`` and ``http://::1:8080``
  are parsed completely differently. The second one is what a broken
  parser mis-handles.
- **Abbreviated forms** - ``::1``, ``0:0:0:0:0:0:0:1`` and
  ``0000:0000:0000:0000:0000:0000:0000:0001`` are the same address. A
  denylist that only matches the short form is bypassed by the long one.
- **DNS responses with AAAA records** - a hostname that resolves to both
  families is two different servers from the application's point of view.

This module resolves the target's address family and then tests the
application's address handling against the forms that confuse it.
"""

from __future__ import annotations

import ipaddress
import re
import socket

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import ScanContext
from ..http_helper import HttpModule

#: The IPv4-mapped IPv6 prefix.
V4_MAPPED = "::ffff:"

#: A literal IPv6 address in a URL or a header.
IPV6_LITERAL = re.compile(
    r"\[?((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})\]?(?:%[0-9a-zA-Z._-]+)?"
)

#: Header and parameter names that carry a client address.
ADDRESS_PARAMS = ("ip", "addr", "address", "client", "clientip", "remote_addr", "forwarded")

#: The address each confusing form is equivalent to. Comparing the
#: literal against a neutralised string proves nothing - both would be
#: rejected. Comparing it against the address it *means* is the
#: question that matters: a filter that accepts one and rejects the
#: other is treating the two families differently.
EQUIVALENT_FORM = {
    "::ffff:127.0.0.1": "127.0.0.1",
    "0000:0000:0000:0000:0000:0000:0000:0001": "::1",
    "fe80::1%25eth0": "fe80::1",
}


class Ipv6SecurityModule(HttpModule):
    """Tests the application's handling of IPv6 address forms."""

    group = "headers"
    id = "ipv6_security"
    name = "IPv6 Security"
    description = (
        "Tests whether the application's address handling survives the "
        "forms of IPv6 that look like something else: IPv4-mapped "
        "addresses, zone identifiers, unbracketed literals and long-form "
        "abbreviations."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.BUG
    capability = Capability.HTTP
    cwe = "CWE-1389"
    owasp = "A07"
    tags = ["ipv6", "ip", "address", "ssrf", "allowlist", "bypass"]
    remediation = (
        "Parse addresses with a library that understands both families "
        "rather than with string matching. Normalise an address with "
        "ipaddress.ip_address() before comparing it, treat the "
        "IPv4-mapped form as the IPv4 address it is, and strip the zone "
        "identifier before an address is used in a comparison or a log."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/1389.html",
        "https://www.rfc-editor.org/rfc/rfc4291",
    ]

    max_params = 8
    max_payloads = 3

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # 1. The target itself: which family does it resolve to?
        addresses = self._resolve(ctx.host)
        ipv6 = [a for a in addresses if ":" in a]
        findings.extend(self._dns_findings(ctx, addresses, ipv6))

        # 2. Do the address-shaped parameters survive the confusing forms?
        for target in self.collect_targets(ctx):
            if target.param.lower() not in ADDRESS_PARAMS:
                continue
            for payload in self._payloads():
                delta = await self.probe(ctx, target, payload)
                if not delta.has_behaviour_change:
                    continue
                if delta.status_delta == 0 and abs(delta.length_ratio - 1.0) < 0.4:
                    continue
                findings.append(
                    self.finding(
                        title=(
                            f"Address parameter '{target.param}' behaves "
                            f"differently for an IPv6 literal"
                        ),
                        target=target.url,
                        description=(
                            f"The parameter '{target.param}' changed the "
                            f"response when it was given the IPv6 literal "
                            f"{payload!r} instead of an ordinary address. "
                            f"An address filter that does not parse both "
                            f"families can be bypassed with the other one - "
                            f"and the address is usually the thing the "
                            f"filter is there to check."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        evidence_text=delta.describe(payload),
                        matched=payload,
                        parameter=target.param,
                    )
                )
                break

        return findings

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def benign_equivalent(payload: str) -> str:
        """The address the payload is really asking about.

        The generic baseline replaces every character with a
        placeholder, which for an address parameter produces a value no
        filter would accept - so the comparison is between two
        rejections and says nothing at all.
        """
        return EQUIVALENT_FORM.get(payload, HttpModule.benign_equivalent(payload))

    @staticmethod
    def _resolve(host: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, None)
        except (socket.gaierror, UnicodeError, OSError):
            return []
        seen: list[str] = []
        for info in infos:
            address = info[4][0]
            if address not in seen:
                seen.append(address)
        return seen

    def _dns_findings(
        self, ctx: ScanContext, addresses: list[str], ipv6: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not addresses:
            return findings
        if ipv6 and len(ipv6) < len(addresses):
            findings.append(
                self.finding(
                    title="Host resolves to both IPv4 and IPv6 addresses",
                    target=ctx.host,
                    description=(
                        f"{ctx.host} resolves to {len(addresses)} addresses "
                        f"across both address families. The two families are "
                        f"different servers with different configurations, "
                        f"and a control applied to one of them is not applied "
                        f"to the other. An allow-list, a firewall rule or a "
                        f"patch level that was verified on the IPv4 address "
                        f"does not apply to the IPv6 one."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence_text=(
                        f"Host    : {ctx.host}\n"
                        f"Addresses: {', '.join(addresses)}"
                    ),
                    matched=ctx.host,
                )
            )
        return findings

    @staticmethod
    def _payloads() -> list[str]:
        """Address forms that a naive filter gets wrong."""
        return [
            # IPv4-mapped loopback: 127.0.0.1 wearing an IPv6 hat.
            "::ffff:127.0.0.1",
            # The long form of the loopback address.
            "0000:0000:0000:0000:0000:0000:0000:0001",
            # A link-local address with a zone identifier.
            "fe80::1%25eth0",
        ]

    def _is_confusable(self, literal: str) -> bool:
        """Does this literal look like a loopback in some other form?"""
        try:
            address = ipaddress.ip_address(literal.split("%")[0])
        except ValueError:
            return False
        if address.is_loopback:
            return True
        # An IPv4-mapped address that maps onto a loopback.
        mapped = getattr(address, "ipv4_mapped", None)
        return bool(mapped and mapped.is_loopback)
