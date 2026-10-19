"""Triage: deciding what to work on first.

A scanner that produces forty findings has not done triage, it has done
inventory. The job of triage is to answer a different question: given
everything found, what do I do next, and in what order?

nemesis's answer is deliberately not "sort by severity". Severity says how
bad it is; it does not say how likely it is, and it says nothing about how
much work it takes to prove. A critical finding that was only observed as
a status-code change is not the same as a critical finding with a
reflected, executable payload - and a report that flattens them into one
list has thrown away the most useful information the scanner had.

The score here is therefore built from three independent axes:

``impact``
    What the attacker gains. This is the severity.

``evidence``
    How well the exploit was proven. This is the confidence, refined by
    the *kind* of evidence: a reflected payload in a script block is
    stronger than a length change.

``effort``
    What it will take to confirm and fix. Deduplicated findings that all
    point at one root cause collapse into one item.

The output is a worklist, not a severity list.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Confidence, Finding, Severity

#: Evidence quality per confidence, before refinement.
_CONFIDENCE_BASE = {
    Confidence.CONFIRMED: 1.00,
    Confidence.HIGH: 0.85,
    Confidence.MEDIUM: 0.60,
    Confidence.LOW: 0.35,
    Confidence.INFO: 0.10,
}

#: Severity to impact weight.
_SEVERITY_IMPACT = {
    Severity.CRITICAL: 1.00,
    Severity.HIGH: 0.80,
    Severity.MEDIUM: 0.55,
    Severity.LOW: 0.30,
    Severity.INFO: 0.10,
}

#: Extra credit for evidence that proves execution rather than suspicion.
_STRONG_EVIDENCE = (
    "stack trace",
    "traceback",
    "sql syntax",
    "syntax error",
    "command not found",
    "exception",
    "unhandled",
)

#: Evidence that is weak even when the confidence is high.
_WEAK_EVIDENCE = (
    "not found",
    "404",
    "403",
    "forbidden",
)


@dataclass
class TriageItem:
    """One item on the worklist."""

    finding: Finding
    priority: float
    impact: float
    evidence: float
    effort: float
    reasons: list[str] = field(default_factory=list)
    duplicates: list[Finding] = field(default_factory=list)

    @property
    def title(self) -> str:
        return self.finding.title

    @property
    def band(self) -> str:
        """A named band, so the worklist reads as a plan."""
        if self.priority >= 0.70:
            return "act-now"
        if self.priority >= 0.45:
            return "schedule"
        if self.priority >= 0.25:
            return "backlog"
        return "note"

    def to_dict(self) -> dict:
        return {
            "title": self.finding.title,
            "target": self.finding.target,
            "severity": self.finding.severity.name,
            "confidence": self.finding.confidence.value,
            "priority": round(self.priority, 3),
            "band": self.band,
            "impact": round(self.impact, 3),
            "evidence": round(self.evidence, 3),
            "effort": round(self.effort, 3),
            "reasons": list(self.reasons),
            "duplicates": [d.title for d in self.duplicates],
            "fingerprint": self.finding.fingerprint,
        }


class TriageEngine:
    """Ranks findings into a worklist."""

    def __init__(self, *, root_cause_groups: bool = True) -> None:
        self.root_cause_groups = root_cause_groups

    def triage(self, findings: list[Finding]) -> list[TriageItem]:
        """Rank *findings* into a worklist, highest priority first."""
        items = [self._score(finding) for finding in findings]

        if self.root_cause_groups:
            items = self._collapse(items)

        items.sort(key=lambda item: item.priority, reverse=True)
        return items

    def plan(self, findings: list[Finding]) -> dict:
        """The full triage plan, grouped into bands."""
        items = self.triage(findings)
        bands: dict[str, list[TriageItem]] = {
            "act-now": [],
            "schedule": [],
            "backlog": [],
            "note": [],
        }
        for item in items:
            bands[item.band].append(item)
        return {
            "total_findings": len(findings),
            "worklist_size": len(items),
            "collapsed": len(findings) - len(items),
            "bands": dict(bands),
            "items": [item.to_dict() for item in items],
        }

    # -- scoring ---------------------------------------------------------
    def _score(self, finding: Finding) -> TriageItem:
        reasons: list[str] = []

        impact = _SEVERITY_IMPACT.get(finding.severity, 0.1)
        reasons.append(f"impact {impact:.2f} from severity {finding.severity.name}")

        evidence = self._evidence_score(finding, reasons)

        # Priority is impact weighted by how well the evidence supports it.
        # A low-confidence critical finding outranks a high-confidence
        # medium one, but not by much - confidence modulates, it does not
        # dominate.
        priority = impact * (0.55 + 0.45 * evidence)

        # Effort: code findings are usually cheaper to fix than findings
        # that need a live exploitation session.
        effort = self._effort(finding)
        priority *= 1.0 - 0.12 * effort

        return TriageItem(
            finding=finding,
            priority=round(priority, 4),
            impact=impact,
            evidence=evidence,
            effort=effort,
            reasons=reasons,
        )

    def _evidence_score(self, finding: Finding, reasons: list[str]) -> float:
        score = _CONFIDENCE_BASE.get(finding.confidence, 0.3)
        reasons.append(f"confidence {finding.confidence.value} contributes {score:.2f}")

        text = (finding.evidence.response or "").lower()
        matched = (finding.evidence.matched or "").lower()
        haystack = f"{text} {matched}"

        if any(marker in haystack for marker in _STRONG_EVIDENCE):
            score = min(1.0, score + 0.15)
            reasons.append("evidence contains an explicit error signature")
        elif any(marker in haystack for marker in _WEAK_EVIDENCE):
            score = max(0.05, score - 0.15)
            reasons.append("evidence is only a 403/404, which proves little")

        if finding.evidence.extra.get("status_delta"):
            reasons.append("the response status changed because of the payload")
        if finding.evidence.extra.get("length_delta"):
            reasons.append("the response length changed because of the payload")

        return min(1.0, score)

    @staticmethod
    def _effort(finding: Finding) -> float:
        """A 0..1 estimate of how much work confirmation and fixing will take."""
        if finding.file or finding.line:
            return 0.2  # a code finding has a location to look at
        if finding.module in ("sqli", "xss", "command_injection", "ssrf"):
            return 0.6  # needs a live exploitation session
        if finding.module in ("headers_security", "cookie_flags", "csp_analyzer"):
            return 0.1  # a configuration change
        return 0.4

    # -- root-cause grouping ---------------------------------------------
    def _collapse(self, items: list[TriageItem]) -> list[TriageItem]:
        """Fold findings that are the same bug seen from different angles."""
        groups: dict[str, list[TriageItem]] = {}
        order: list[str] = []
        for item in items:
            key = self._group_key(item.finding)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(item)

        collapsed: list[TriageItem] = []
        for key in order:
            group = groups[key]
            primary = max(group, key=lambda i: i.priority)
            primary.duplicates = [i.finding for i in group if i is not primary]
            if primary.duplicates:
                primary.reasons.append(
                    f"collapses {len(primary.duplicates)} duplicate finding(s) "
                    f"of the same weakness"
                )
                # One root cause, several observations: the priority does
                # not grow, because the work is the same work.
            collapsed.append(primary)
        return collapsed

    @staticmethod
    def _group_key(finding: Finding) -> str:
        """Findings that share a root cause share a key."""
        category = finding.category.value
        if category == "headers":
            return "headers"
        if finding.module in ("sqli", "nosql_injection"):
            return "injection:sql"
        if finding.module in ("xss", "template_injection"):
            return "injection:script"
        if finding.module in ("ssrf",):
            return "ssrf"
        if finding.module in ("secrets",):
            return "secrets"
        if finding.module in ("dependency_vulnerabilities", "typosquatting", "dependency_confusion"):
            return "supply-chain"
        return f"{category}:{finding.module}"


def render_triage(items: list[TriageItem], *, width: int = 100) -> str:
    """Render a worklist as plain text."""
    lines: list[str] = []
    band_titles = {
        "act-now": "ACT NOW",
        "schedule": "SCHEDULE",
        "backlog": "BACKLOG",
        "note": "NOTE",
    }
    current = ""
    for item in items:
        if item.band != current:
            current = item.band
            lines.append("")
            lines.append(f"== {band_titles.get(current, current.upper())} ==")
        confidence = item.finding.confidence.value
        lines.append(
            f"  [{item.priority:4.2f}] {item.finding.severity.name:<8} "
            f"({confidence:<9}) {item.title}"
        )
        lines.append(f"          target: {item.finding.target}")
        for reason in item.reasons:
            lines.append(f"          - {reason}")
        if item.duplicates:
            lines.append(
                f"          - {len(item.duplicates)} duplicate(s) folded in"
            )
    return "\n".join(lines)
