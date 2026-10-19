"""Disclosure report generation.

Every bug bounty programme has its own report shape, and every one of them
rejects a report that does not follow the shape. What they all require is
the same set of facts, in a predictable order:

1. A title that says what the bug is, not where it is.
2. A severity with a justification, not a number.
3. Steps to reproduce that someone else can follow without asking you
   anything.
4. The impact, stated in terms of what the attacker gains.
5. A remediation, specific enough to be actionable.
6. The request: how it was found, and a disclosure deadline.

This module renders a nemesis finding set into that shape for HackerOne,
Bugcrowd and Intigriti, each in the format that programme actually asks
for. The differences are real: HackerOne wants a severity rating, Bugcrowd
wants a priority and a vector string, Intigriti wants a rating and an
asset.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..models import Finding, Severity
from .proof import request_evidence

#: The three programmes nemesis can write for.
PROGRAMMES = ("hackerone", "bugcrowd", "intigriti")

#: Severity label per programme, keyed by nemesis severity.
SEVERITY_LABELS = {
    "hackerone": {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Informative",
    },
    "bugcrowd": {
        Severity.CRITICAL: "P1",
        Severity.HIGH: "P2",
        Severity.MEDIUM: "P3",
        Severity.LOW: "P4",
        Severity.INFO: "P5",
    },
    "intigriti": {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Informative",
    },
}

#: Default disclosure window, in days.
DEFAULT_DISCLOSURE_DAYS = 90



@dataclass
class DisclosureReport:
    """A rendered disclosure report."""

    programme: str
    title: str
    severity_label: str
    severity: Severity
    body_markdown: str
    fields: dict[str, str] = field(default_factory=dict)
    assets: list[str] = field(default_factory=list)
    cvss: str | None = None
    cwe: str | None = None
    references: list[str] = field(default_factory=list)
    disclosure_deadline: str = ""

    def to_markdown(self) -> str:
        return self.body_markdown

    def to_dict(self) -> dict:
        return {
            "programme": self.programme,
            "title": self.title,
            "severity": self.severity_label,
            "severity_raw": self.severity.name,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "assets": list(self.assets),
            "fields": dict(self.fields),
            "references": list(self.references),
            "disclosure_deadline": self.disclosure_deadline,
            "body_markdown": self.body_markdown,
        }

    def to_html(self) -> str:
        """A minimal HTML rendering, for programmes that want to paste it."""
        import html as html_mod

        body = html_mod.escape(self.body_markdown)
        paragraphs = body.split("\n\n")
        rendered = "\n".join(
            f"    <p>{block.replace(chr(10), '<br/>')}</p>" for block in paragraphs
        )
        return (
            "<!doctype html>\n<html>\n  <head>\n"
            '    <meta charset="utf-8"/>\n'
            f"    <title>{html_mod.escape(self.title)}</title>\n"
            "  </head>\n  <body>\n"
            f"    <h1>{html_mod.escape(self.title)}</h1>\n"
            f"    <p><strong>Severity:</strong> {html_mod.escape(self.severity_label)}</p>\n"
            f"{rendered}\n"
            "  </body>\n</html>\n"
        )


class DisclosureReportBuilder:
    """Renders findings into programme-shaped disclosure reports."""

    def __init__(
        self,
        programme: str = "hackerone",
        *,
        asset: str = "",
        researcher: str = "",
        disclosure_days: int = DEFAULT_DISCLOSURE_DAYS,
    ) -> None:
        programme = programme.lower()
        if programme not in PROGRAMMES:
            raise ValueError(
                f"unknown programme {programme!r}; expected one of {', '.join(PROGRAMMES)}"
            )
        self.programme = programme
        self.asset = asset
        self.researcher = researcher
        self.disclosure_days = disclosure_days

    # -- public API ------------------------------------------------------
    def build(self, finding: Finding) -> DisclosureReport:
        severity_label = SEVERITY_LABELS[self.programme][finding.severity]
        deadline = (
            datetime.now(timezone.utc) + timedelta(days=self.disclosure_days)
        ).strftime("%Y-%m-%d")

        assets = [self.asset] if self.asset else [finding.target]
        body = self._body(finding, severity_label, deadline, assets)
        return DisclosureReport(
            programme=self.programme,
            title=self._title(finding),
            severity_label=severity_label,
            severity=finding.severity,
            body_markdown=body,
            fields=self._fields(finding, assets),
            assets=assets,
            cvss=finding.cvss,
            cwe=finding.cwe,
            references=list(finding.references),
            disclosure_deadline=deadline,
        )

    def build_all(self, findings: list[Finding]) -> list[DisclosureReport]:
        return [self.build(finding) for finding in findings]

    # -- per-programme shape ---------------------------------------------
    def _fields(self, finding: Finding, assets: list[str]) -> dict[str, str]:
        base = {
            "Asset": ", ".join(assets),
            "Severity": SEVERITY_LABELS[self.programme][finding.severity],
        }
        if finding.cwe:
            base["CWE"] = finding.cwe
        if finding.cvss:
            base["CVSS"] = finding.cvss
        if self.programme == "bugcrowd":
            base["Priority"] = SEVERITY_LABELS[self.programme][finding.severity]
            base["Category"] = finding.category.value
        elif self.programme == "intigriti":
            base["Rating"] = SEVERITY_LABELS[self.programme][finding.severity]
            base["Asset type"] = "Web Application"
        else:
            base["Weakness"] = finding.cwe or "Unspecified"
            base["Category"] = finding.category.value
        return base

    def _title(self, finding: Finding) -> str:
        # A good title names the weakness and the impact, not the URL.
        clean = finding.title
        if clean.lower().startswith(("possible ", "potential ")):
            clean = clean.split(" ", 1)[1]
        return clean[:150]

    def _body(
        self, finding: Finding, severity_label: str, deadline: str, assets: list[str]
    ) -> str:
        parts: list[str] = []

        parts.append(f"## Summary\n\n{finding.description}")

        parts.append(
            "## Severity\n\n"
            f"**{severity_label}**"
            + (f" (CVSS {finding.cvss})" if finding.cvss else "")
            + f" - confidence: {finding.confidence.value}."
        )

        parts.append(
            "## Steps to reproduce\n\n"
            f"1. Target: `{finding.target}`\n"
            f"2. Send the request below.\n"
            f"3. Observe the response.\n\n"
            f"```http\n{request_evidence(finding)}\n```"
        )

        if finding.evidence.response:
            parts.append(
                "### Observed response\n\n"
                f"```\n{finding.evidence.response[:1200]}\n```"
            )

        parts.append(
            "## Impact\n\n"
            f"This is a **{severity_label}** issue in the "
            f"`{finding.category.value}` category. "
            f"{_impact_paragraph(finding)}"
        )

        if finding.remediation:
            parts.append(f"## Remediation\n\n{finding.remediation}")

        if finding.references:
            parts.append(
                "## References\n\n"
                + "\n".join(f"- {ref}" for ref in finding.references[:5])
            )

        parts.append(
            "## Disclosure\n\n"
            f"This report was produced by an automated scan that "
            f"differentiates a real behavioural change from a page that "
            f"merely looks different. The finding carries a confidence of "
            f"**{finding.confidence.value}**, and the evidence above is the "
            f"proof that the response changed because of the payload.\n\n"
            f"I am willing to coordinate a fix. My proposed disclosure "
            f"deadline is **{deadline}**, and I will not publish before "
            f"that date without your agreement."
        )

        if self.researcher:
            parts.append(f"\n---\n\nReported by {self.researcher}.")

        return "\n\n".join(parts)


def _impact_paragraph(finding: Finding) -> str:
    """Turn the category into a sentence about what the attacker gains."""
    category = finding.category.value
    mapping = {
        "injection": (
            "An attacker who can control the affected input can change the "
            "meaning of the request the server makes, and read or write "
            "data that the request should never have been able to touch."
        ),
        "auth": (
            "An attacker can act as a different user, or reach a function "
            "that was supposed to require a session or a role they do not "
            "have."
        ),
        "traversal": (
            "An attacker can read files the web server can read, and the "
            "web server usually runs with more access than the application "
            "logic needs."
        ),
        "xss": (
            "An attacker can run script in the browser of any user who "
            "visits the affected page, in that user's session, with that "
            "user's cookies."
        ),
        "ssrf": (
            "An attacker can make the server issue requests to addresses "
            "the attacker cannot reach, including services on the internal "
            "network that trust the request because it came from inside."
        ),
        "disclosure": (
            "Information that the application did not intend to publish is "
            "readable by anyone who asks."
        ),
        "supply-chain": (
            "The build or the dependency resolution can be influenced by "
            "someone other than the project's own maintainers."
        ),
        "config": (
            "The deployment is configured in a way that gives more access "
            "than the application needs."
        ),
        "crypto": (
            "The protection the application relies on is weaker than it "
            "appears to be, and the data it protects is exposed."
        ),
        "dos": (
            "A small amount of traffic is enough to make the service "
            "unavailable for its users."
        ),
        "bug": (
            "The application does not behave the way its own specification "
            "says it should, and the difference can be relied on to cause "
            "harm."
        ),
    }
    return mapping.get(
        category,
        "The issue lets an attacker do something the application did not "
        "intend to allow.",
    )
