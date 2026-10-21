"""Public write-up generation.

A write-up is a different artefact from a disclosure report. A disclosure
report is addressed to one company and explains one bug. A write-up is
address to the world, and it has to teach something.

The generator produces a write-up that:

- leads with the class of bug, not with a tool,
- shows the request and the response that prove it,
- explains *why* the payload worked, in terms a reader can apply elsewhere,
- and states the limits - what was tested, what was not.

It is generated from a finding set, so the technical facts come from the
scanner and the narrative is assembled around them. The generated draft
says clearly that it is a draft: the narrative is a scaffold, and the
person publishing it has to say what they actually learned.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ..models import Finding
from .proof import proof_lines, request_evidence

#: How the write-up is grouped when several findings are present.
#: These are the names as :class:`nemesis.models.Severity` spells them.
GROUP_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass
class Writeup:
    """A generated public write-up."""

    title: str
    subtitle: str
    body_markdown: str
    findings: list[Finding]
    tags: list[str]
    generated_at: str

    def to_markdown(self) -> str:
        return self.body_markdown


class WriteupBuilder:
    """Assembles a publishable write-up from a set of findings."""

    def __init__(self, *, author: str = "", target: str = "") -> None:
        self.author = author
        self.target = target

    # -- public API ------------------------------------------------------
    def build(self, findings: list[Finding], *, title: str = "") -> Writeup:
        findings = list(findings)
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        headline = title or self._default_title(findings)
        body = self._body(findings, headline, generated_at)
        return Writeup(
            title=headline,
            subtitle=self._subtitle(findings),
            body_markdown=body,
            findings=findings,
            tags=self._tags(findings),
            generated_at=generated_at,
        )

    # -- assembly --------------------------------------------------------
    def _default_title(self, findings: list[Finding]) -> str:
        if not findings:
            return "Security Research Notes"
        top = max(findings, key=lambda f: f.severity)
        weakness = top.cwe or top.category.value
        if len(findings) == 1:
            return f"{top.title} - A {weakness} Analysis"
        return f"{len(findings)} Findings Against {self.target or 'the Target'}"

    def _subtitle(self, findings: list[Finding]) -> str:
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity.name] = counts.get(finding.severity.name, 0) + 1
        parts = [
            f"{counts[severity]} {severity.lower()}"
            for severity in GROUP_ORDER
            if counts.get(severity)
        ]
        return ", ".join(parts) if parts else "No findings"

    def _tags(self, findings: list[Finding]) -> list[str]:
        tags: list[str] = []
        for finding in findings:
            for tag in finding.tags:
                if tag not in tags:
                    tags.append(tag)
        return tags[:12]

    def _body(self, findings: list[Finding], headline: str, generated_at: str) -> str:
        parts: list[str] = []

        parts.append(f"# {headline}\n\n_{self._subtitle(findings)} - {generated_at}_")

        if self.author:
            parts.append(f"**Author:** {self.author}")

        parts.append(self._intro(findings))
        parts.append(self._methodology(findings))
        parts.append(self._findings_section(findings))
        parts.append(self._limitations(findings))
        parts.append(self._conclusion(findings))

        return "\n\n".join(parts)

    def _intro(self, findings: list[Finding]) -> str:
        if not findings:
            return (
                "This note records a security review that produced no "
                "findings. The absence of findings is a statement about "
                "the scope and the time, not about the target."
            )
        classes = sorted({f.cwe or f.category.value for f in findings})
        worst = max(findings, key=lambda f: f.severity)
        return (
            f"This write-up covers {len(findings)} finding"
            f"{'s' if len(findings) != 1 else ''} raised against "
            f"`{self.target or 'the target'}`.\n\n"
            f"The findings span {len(classes)} weakness "
            f"{'class' if len(classes) == 1 else 'classes'}: "
            f"{', '.join(classes)}. The most serious is rated "
            f"**{worst.severity.name}**.\n\n"
            f"What follows is the evidence, what the evidence means, and "
            f"where the limits of the review are. The point of the write-up "
            f"is not the individual bug - it is the class of mistake and "
            f"how to recognise it."
        )

    def _methodology(self, findings: list[Finding]) -> str:
        modules = sorted({f.module for f in findings})
        return (
            "## Methodology\n\n"
            "Findings were produced with a differential scanner. Every "
            "active check sends a benign baseline request and the same "
            "request carrying a payload, and then compares the two "
            "responses: status, body length, error signatures, and where "
            "the payload was reflected.\n\n"
            "That distinction matters. A scanner that reports a page "
            "because it *looks* different produces a report full of "
            "findings that are not there. A scanner that reports only "
            "when the response provably changed because of the payload "
            "produces fewer findings, and the ones it produces are worth "
            "reading.\n\n"
            "The checks that contributed to these findings were:\n\n"
            + "\n".join(f"- `{module}`" for module in modules)
        )

    def _findings_section(self, findings: list[Finding]) -> str:
        if not findings:
            return "## Findings\n\nNo findings."

        parts = ["## Findings"]
        by_severity: dict[str, list[Finding]] = {}
        for finding in findings:
            by_severity.setdefault(finding.severity.name, []).append(finding)

        for severity in GROUP_ORDER:
            group = by_severity.get(severity, [])
            if not group:
                continue
            for index, finding in enumerate(group, start=1):
                parts.append(self._one_finding(finding, index))
        return "\n\n".join(parts)

    def _one_finding(self, finding: Finding, index: int) -> str:
        lines = [f"### {index}. {finding.title}"]
        lines.append("")
        lines.append(
            f"**Severity:** {finding.severity.name} · "
            f"**Confidence:** {finding.confidence.value} · "
            f"**CWE:** {finding.cwe or 'n/a'} · "
            f"**OWASP:** {finding.owasp or 'n/a'}"
        )
        lines.append("")
        lines.append(finding.description)
        lines.append("")

        proof = proof_lines(finding)
        if finding.evidence.request or proof or finding.evidence.response:
            lines.append("**Evidence**")
            lines.append("")
            lines.append("```http")
            lines.append(request_evidence(finding).strip())
            lines.append("```")
            lines.append("")
            if proof:
                lines.append("```")
                lines.extend(proof[:12])
                lines.append("```")
                lines.append("")

        lines.append("**Why it works**")
        lines.append("")
        lines.append(self._explanation(finding))
        lines.append("")

        if finding.remediation:
            lines.append("**Fix**")
            lines.append("")
            lines.append(finding.remediation)
            lines.append("")

        if finding.references:
            lines.append("**References**")
            lines.append("")
            lines.extend(f"- {ref}" for ref in finding.references[:5])
            lines.append("")

        return "\n".join(lines)

    def _explanation(self, finding: Finding) -> str:
        """Explain the mechanism, generically but truthfully."""
        category = finding.category.value
        explanations = {
            "injection": (
                "The value under test is concatenated into a command that "
                "the backend interprets - a database query, a shell "
                "command, a template. The payload was chosen to change the "
                "*structure* of that command rather than its data, and the "
                "response changed as a result. The fix is to keep data and "
                "code apart: parameterised queries, argument arrays, and "
                "no string-built interpreters."
            ),
            "auth": (
                "The server decided what to do based on a request that the "
                "client fully controls. The check either was not applied on "
                "this path, or was applied to something the client can also "
                "change. The fix is to make the authorisation decision on "
                "the server, from server-side state, on every path that "
                "changes state."
            ),
            "traversal": (
                "A path component from the request reached the filesystem "
                "without being normalised. A `..` sequence walks out of the "
                "directory the server meant to confine the request to. The "
                "fix is to resolve the path and then check that the "
                "resolved path is still inside the permitted root."
            ),
            "xss": (
                "User-controlled data was written into the page without "
                "being escaped for the context it landed in. The payload "
                "survived into the response, which means the escaping step "
                "either does not exist or does not cover this context. The "
                "fix is context-sensitive output encoding plus a "
                "Content-Security-Policy that limits what the page can do."
            ),
            "ssrf": (
                "The server made a network request to an address the "
                "request controlled. The server is inside the network and "
                "the requester is not, so the request carries the server's "
                "trust - which is exactly what an attacker wants to borrow. "
                "The fix is an allow-list of destinations, resolved and "
                "re-checked after DNS resolution so a rebind cannot get "
                "around it."
            ),
            "disclosure": (
                "The server returned data that its own routing was not "
                "meant to expose. Whether the cause is a permissive path "
                "match, a default that is too generous, or a missing "
                "authorisation check, the result is the same: a public URL "
                "returned a private thing."
            ),
            "supply-chain": (
                "The build resolves something the project's maintainers did "
                "not intend to control. The attacker does not need a "
                "vulnerability in the application; they need a name to "
                "publish under, or a version to publish, or a pipeline "
                "step to influence."
            ),
            "config": (
                "The deployment is more permissive than the application "
                "requires. Configuration mistakes are not bugs in the "
                "application logic, which is why they survive code review "
                "and are caught by nobody until they are exploited."
            ),
            "crypto": (
                "The construction used is not one that provides the "
                "property the code assumes. A hash without a salt, a "
                "cipher without a mode, a comparison that is not constant "
                "time - each of these looks like a solution and is not."
            ),
        }
        return explanations.get(
            category,
            "The behaviour changed when the payload was introduced, which "
            "means the payload reached a decision point the request was "
            "not supposed to influence.",
        )

    def _limitations(self, findings: list[Finding]) -> str:
        endpoints = len({f.target for f in findings})
        return (
            "## Limitations\n\n"
            f"This review looked at {endpoints} distinct "
            f"{'target' if endpoints == 1 else 'targets'} and produced "
            f"{len(findings)} finding{'s' if len(findings) != 1 else ''}. "
            "That is a sample, not a census. Specifically:\n\n"
            "- Only the checks that ran are covered. A scanner is a set of "
            "hypotheses about what can go wrong, and the ones it does not "
            "hold are the ones it cannot find.\n"
            "- Authentication and authorisation paths were exercised only "
            "as far as the scan was able to authenticate.\n"
            "- The absence of a finding for a given class of bug is not "
            "evidence that the class is absent.\n\n"
            "A report that claims completeness is making a claim the "
            "method does not support."
        )

    def _conclusion(self, findings: list[Finding]) -> str:
        if not findings:
            return (
                "## Conclusion\n\n"
                "Nothing was found within the scope described above. That "
                "is the honest result, and it is worth publishing only if "
                "it narrows somebody else's search."
            )
        worst = max(findings, key=lambda f: f.severity)
        modules = {f.module for f in findings}
        return (
            "## Conclusion\n\n"
            f"The most serious issue here is rated **{worst.severity.name}** "
            f"and is a {worst.category.value} problem. The rest of the "
            f"findings are variations on the same theme: the code trusts "
            f"something it should have checked.\n\n"
            f"Across {len(modules)} distinct checks, the pattern is "
            f"consistent enough to be worth stating as a rule: **every "
            f"one of these bugs would have been caught by asking what the "
            f"server would do if the client sent something the client "
            f"should never send.**\n\n"
            f"Tools find these; the fix is in the review. The draft above "
            f"is generated from a scan and is a starting point - the "
            f"narrative about what you learned belongs to the person who "
            f"learned it."
        )


