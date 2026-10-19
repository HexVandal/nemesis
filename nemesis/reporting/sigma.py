"""Sigma rule generation.

Sigma is the lingua franca of detection engineering: a YAML rule that says
"when these fields match, this is bad". A Sigma rule is data, so it can be
translated into a SIEM query, a Splunk SPL, an Elastic query or a
Microsoft Sentinel KQL without being rewritten.

nemesis generates Sigma rules from findings, which is the step most people
skip: the vulnerability is found, and then nobody ever writes the detection
for it. The generated rules are deliberately *detection* rules rather than
*exploit* rules - they look for the shape of an attack in a log, which is
what a SIEM can actually see.

Each rule records where it came from, so an analyst can judge it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Finding

#: The log source a module's attacks would appear in.
LOGSOURCE_BY_MODULE = {
    "sqli": "webserver",
    "nosql_injection": "webserver",
    "xss": "webserver",
    "command_injection": "webserver",
    "template_injection": "webserver",
    "insecure_deserialization": "webserver",
    "xml_external_entity": "webserver",
    "ssrf": "webserver",
    "path_traversal": "webserver",
    "open_redirect": "webserver",
    "file_upload": "webserver",
    "request_smuggling": "webserver",
    "web_cache_poisoning": "webserver",
    "host_header_injection": "webserver",
    "idor": "webserver",
    "csrf_missing": "webserver",
    "exposed_files": "webserver",
    "graphql_introspection": "webserver",
    "business_logic": "webserver",
    "websocket_security": "webserver",
}

#: A Sigma level derived from the finding severity.
LEVEL_BY_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "informational",
}

#: Payload markers that identify an injection attempt in a request line.
INJECTION_MARKERS = {
    "sqli": ["'", '"', "union select", "sleep(", "or 1=1", "--", "/*"],
    "nosql_injection": ["$ne", "$gt", "$where", "{\"$"],
    "xss": ["<script", "javascript:", "onerror=", "<img src=x", "onload="],
    "command_injection": [";", "|", "&&", "$(", "`", "cat /etc/passwd", "whoami"],
    "template_injection": ["{{", "{%", "${", "#{7*7}"],
    "insecure_deserialization": ["rO0AB", "O:8:", "base64"],
    "xml_external_entity": ["<!DOCTYPE", "<!ENTITY", "SYSTEM", "file://"],
    "path_traversal": ["../", "..%2f", "..%5c", "/etc/passwd", "%2e%2e%2f"],
    "ssrf": ["169.254.169.254", "localhost", "127.0.0.1", "metadata.google"],
    "open_redirect": ["http://", "https://", "//evil", "%2f%2f"],
}

#: The Sigma logsource per product. The tuple is
#: ``(category, product, service)``.
LOGSOURCE_PRODUCTS = {
    "webserver": ("webserver", "nginx", "nginx"),
    "proxy": ("proxy", "nginx", "nginx"),
}


@dataclass
class SigmaRule:
    """One generated Sigma rule."""

    title: str
    id: str
    status: str = "experimental"
    description: str = ""
    level: str = "medium"
    logsource: dict[str, str] = field(default_factory=dict)
    detection: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_yaml(self) -> str:
        """Render the rule as YAML, without needing a YAML dependency."""
        lines: list[str] = []
        lines.append(f"title: {_yaml_scalar(self.title)}")
        lines.append(f"id: {self.id}")
        lines.append(f"status: {self.status}")
        lines.append(f"description: {_yaml_scalar(self.description)}")
        lines.append("author: nemesis")
        lines.append(f"level: {self.level}")
        if self.tags:
            lines.append("tags:")
            for tag in self.tags:
                lines.append(f"    - {tag}")
        if self.logsource:
            lines.append("logsource:")
            for key, value in self.logsource.items():
                lines.append(f"    {key}: {value}")
        if self.detection:
            lines.append("detection:")
            for key, value in self.detection.items():
                if isinstance(value, dict):
                    lines.append(f"    {key}:")
                    for sub_key, sub_value in value.items():
                        if isinstance(sub_value, list):
                            lines.append(f"        {sub_key}:")
                            for item in sub_value:
                                lines.append(f"            - {_yaml_scalar(str(item))}")
                        else:
                            lines.append(f"        {sub_key}: {_yaml_scalar(str(sub_value))}")
                elif isinstance(value, list):
                    lines.append(f"    {key}:")
                    for item in value:
                        lines.append(f"        - {_yaml_scalar(str(item))}")
                else:
                    lines.append(f"    {key}: {_yaml_scalar(str(value))}")
        if self.fields:
            lines.append("fields:")
            for field_name in self.fields:
                lines.append(f"    - {field_name}")
        if self.falsepositives:
            lines.append("falsepositives:")
            for fp in self.falsepositives:
                lines.append(f"    - {_yaml_scalar(fp)}")
        if self.references:
            lines.append("references:")
            for ref in self.references:
                lines.append(f"    - {ref}")
        return "\n".join(lines) + "\n"

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "id": self.id,
            "status": self.status,
            "description": self.description,
            "level": self.level,
            "logsource": dict(self.logsource),
            "detection": self.detection,
            "tags": list(self.tags),
            "fields": list(self.fields),
            "falsepositives": list(self.falsepositives),
            "references": list(self.references),
        }


def _yaml_scalar(value: str) -> str:
    """Quote a YAML scalar when it needs quoting."""
    if value == "":
        return '""'
    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_ ./@:-]*", value) and ":" not in value:
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    return f'"{escaped}"'


class SigmaRuleBuilder:
    """Turns findings into Sigma detection rules."""

    def __init__(self) -> None:
        self.skipped: list[tuple[str, str]] = []

    # -- public API ------------------------------------------------------
    def build(self, findings: list[Finding]) -> list[SigmaRule]:
        rules: list[SigmaRule] = []
        for finding in findings:
            rule = self.rule_for(finding)
            if rule is not None:
                rules.append(rule)
        return rules

    def to_text(self, rules: list[SigmaRule]) -> str:
        header = (
            "# Generated by nemesis - Sigma detection rules derived from "
            "observed findings.\n"
            "# Rules are 'experimental' until an analyst has tuned them "
            "against production data.\n\n"
        )
        return header + "\n---\n\n".join(rule.to_yaml() for rule in rules)

    # -- per-finding -----------------------------------------------------
    def rule_for(self, finding: Finding) -> SigmaRule | None:
        product = LOGSOURCE_BY_MODULE.get(finding.module)
        markers = INJECTION_MARKERS.get(finding.module)
        if product is None and not markers:
            self.skipped.append(
                (finding.title, "no log source is known for this check")
            )
            return None

        category, product_name, service = LOGSOURCE_PRODUCTS["webserver"]
        logsource = {"category": category, "product": product_name, "service": service}

        detection: dict = {}
        selection: dict = {}
        if markers:
            selection["c-uri|contains"] = list(markers)
        else:
            # Fall back to the specific thing that was observed.
            literal = self._literal(finding)
            if not literal:
                self.skipped.append(
                    (finding.title, "no observable indicator to match on")
                )
                return None
            selection["c-uri|contains"] = [literal]
        detection["selection"] = selection
        detection["condition"] = "selection"

        title = f"{finding.title} attempt against {finding.target}"
        description = (
            f"{finding.description}\n\n"
            f"Derived from a nemesis finding with confidence "
            f"'{finding.confidence.value}'. The rule matches the request "
            f"shape of the attack, not the response, so it fires on both "
            f"successful and failed attempts."
        )

        return SigmaRule(
            title=title[:250],
            id=_sigma_id(finding),
            description=description,
            level=LEVEL_BY_SEVERITY.get(finding.severity.name, "medium"),
            logsource=logsource,
            detection=detection,
            tags=[
                "attack.t1110" if "injection" in finding.module else "attack.t1190",
                f"nemesis.{finding.module}",
                f"severity.{finding.severity.name.lower()}",
            ],
            fields=["c-uri", "c-method", "c-ip", "cs-User-Agent"],
            falsepositives=[
                "Legitimate traffic that happens to contain the same characters",
                "Security scanners and crawlers",
            ],
            references=list(finding.references)[:3],
        )

    @staticmethod
    def _literal(finding: Finding) -> str:
        extra = finding.evidence.extra or {}
        for key in ("payload", "matched", "path", "value"):
            value = extra.get(key)
            if isinstance(value, str) and len(value.strip()) >= 4:
                return value.strip()[:120]
        matched = finding.evidence.matched
        return matched.strip()[:120] if matched else ""


def _sigma_id(finding: Finding) -> str:
    """A UUID-shaped identifier, as the Sigma specification wants.

    Python's ``hash()`` is randomised per process, so it cannot be used
    here - the same finding must always produce the same rule id, or a
    ruleset that is regenerated on every run is impossible to review.
    """
    import hashlib

    raw = f"{finding.module}{finding.fingerprint}{finding.title}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"
