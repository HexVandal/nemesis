"""LDAP filter injection, proved by the error the directory server returns.

A reflected payload proves nothing - LDAP filters are strings, and strings get
echoed. What proves the payload reached a directory is a backend error the
baseline never produced.
"""

from __future__ import annotations

import re

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import ScanContext
from ..http_helper import HttpModule

#: Filter syntax that only means something to an LDAP parser.
PAYLOADS = [
    "*)(uid=*",
    "*)(|(uid=*))",
    "*)(objectClass=*",
    "admin)(&(1=1",
]

#: Strings that appear when a filter is handed to a directory server.
SIGNATURES = re.compile(
    r"(javax\.naming|com\.sun\.jndi|LDAPException|LDAPSearchException|"
    r"invalid (?:dn|search filter|syntax)|supplied distinguished name|"
    r"LDAP: error code \d+|DSID-\w+|0x0202|"
    r"ldap_search|Bad search filter|Protocol error occurred)",
    re.IGNORECASE,
)


class LdapInjectionModule(HttpModule):
    group = "injection"

    id = "ldap_injection"
    name = "LDAP Injection"
    description = (
        "Sends LDAP filter metacharacters and reports the parameters that "
        "produce a directory-server error the baseline did not."
    )
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.INJECTION
    capability = Capability.HTTP
    cwe = "CWE-90"
    owasp = "A03"
    remediation = (
        "Escape RFC 4515 metacharacters (\\ * ( ) NUL) before building a "
        "filter, and use a parameterised directory API where one exists."
    )
    references = [
        "https://owasp.org/www-community/attacks/LDAP_Injection",
        "https://datatracker.ietf.org/doc/html/rfc4515",
    ]
    tags = ["ldap", "injection", "active"]

    max_params: int = 12
    max_payloads: int = 4
    skip_params = {"password", "pass", "csrf", "token", "_token"}

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target in self.collect_targets(ctx):
            for payload in PAYLOADS[: self.max_payloads]:
                baseline = await self.fetch(ctx, target, self.benign_equivalent(payload))
                probe = await self.fetch(ctx, target, payload)
                if not probe.text:
                    continue
                match = SIGNATURES.search(probe.text)
                if not match:
                    continue
                if baseline.text and SIGNATURES.search(baseline.text):
                    continue
                findings.append(
                    self.finding(
                        title=f"LDAP injection in '{target.param}'",
                        target=target.url,
                        description=(
                            f"The '{target.param}' parameter reached an LDAP "
                            f"directory: the filter metacharacters produced "
                            f"'{match.group(0)}', which the benign baseline did "
                            f"not. An attacker can rewrite the filter and read "
                            f"records the query was never meant to match."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        evidence_text=(
                            f"{target.method} {target.url}\n"
                            f"  {target.param} = {payload}\n"
                            f"  signature    : {match.group(0)}\n"
                            f"  context      : {probe.text[max(0, match.start() - 80):match.end() + 80]}"
                        ),
                        matched=match.group(0),
                        param=target.param,
                    )
                )
                break
        return findings
