"""SARIF 2.1.0 report writer.

SARIF is the format GitHub code scanning ingests, so this output drops
straight into a repository's Security tab.
"""

from __future__ import annotations

from pathlib import Path

from ..models import ScanResult, Severity

#: SARIF severity strings.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

#: SARIF rule metadata.
_RULES = {
    "CWE-22": ("Path Traversal", "https://cwe.mitre.org/data/definitions/22.html"),
    "CWE-79": ("Cross-Site Scripting", "https://cwe.mitre.org/data/definitions/79.html"),
    "CWE-89": ("SQL Injection", "https://cwe.mitre.org/data/definitions/89.html"),
    "CWE-78": ("OS Command Injection", "https://cwe.mitre.org/data/definitions/78.html"),
    "CWE-91": ("XML Injection", "https://cwe.mitre.org/data/definitions/91.html"),
    "CWE-200": ("Information Exposure", "https://cwe.mitre.org/data/definitions/200.html"),
    "CWE-209": ("Error Message Exposure", "https://cwe.mitre.org/data/definitions/209.html"),
    "CWE-352": ("Cross-Site Request Forgery", "https://cwe.mitre.org/data/definitions/352.html"),
    "CWE-502": ("Deserialization of Untrusted Data", "https://cwe.mitre.org/data/definitions/502.html"),
    "CWE-538": ("Insertion of Sensitive Information", "https://cwe.mitre.org/data/definitions/538.html"),
    "CWE-548": ("Exposure of Information Through Directory Listing", "https://cwe.mitre.org/data/definitions/548.html"),
    "CWE-601": ("Open Redirect", "https://cwe.mitre.org/data/definitions/601.html"),
    "CWE-611": ("XXE", "https://cwe.mitre.org/data/definitions/611.html"),
    "CWE-639": ("Authorization Bypass Through User-Controlled Key", "https://cwe.mitre.org/data/definitions/639.html"),
    "CWE-644": ("Improper Neutralization of HTTP Headers", "https://cwe.mitre.org/data/definitions/644.html"),
    "CWE-693": ("Protection Mechanism Failure", "https://cwe.mitre.org/data/definitions/693.html"),
    "CWE-798": ("Use of Hard-coded Credentials", "https://cwe.mitre.org/data/definitions/798.html"),
    "CWE-918": ("Server-Side Request Forgery", "https://cwe.mitre.org/data/definitions/918.html"),
    "CWE-942": ("Permissive Cross-domain Policy", "https://cwe.mitre.org/data/definitions/942.html"),
    "CWE-1021": ("Improper Restriction of Rendered UI Layers", "https://cwe.mitre.org/data/definitions/1021.html"),
    "CWE-1104": ("Use of Unmaintained Third Party Components", "https://cwe.mitre.org/data/definitions/1104.html"),
}


def _rule_for(finding) -> dict:
    cwe = finding.cwe or ""
    name, url = _RULES.get(cwe, (cwe or "Unclassified", "https://cwe.mitre.org/"))
    return {
        "id": cwe or finding.module,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {"text": finding.description[:1000]},
        "helpUri": url,
        "properties": {
            "category": finding.category.value,
            "tags": [t for t in finding.tags if t] + ([cwe] if cwe else []),
            # GitHub code scanning ranks alerts by this string.
            "security-severity": f"{finding.cvss_score or 0.0:.1f}",
        },
    }


def write_sarif(result: ScanResult, path: str | Path) -> Path:
    """Write a SARIF 2.1.0 log."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    rules: dict[str, dict] = {}
    results: list[dict] = []

    for finding in result.findings:
        rule = _rule_for(finding)
        rules[rule["id"]] = rule

        physical = {
            "artifactLocation": {"uri": finding.file or finding.target},
        }
        if finding.line:
            physical["region"] = {"startLine": finding.line}

        results.append(
            {
                "ruleId": rule["id"],
                "level": _SARIF_LEVEL.get(finding.severity, "note"),
                "message": {"text": finding.description},
                "locations": [{"physicalLocation": physical}],
                "properties": {
                    "severity": finding.severity.name,
                    "confidence": finding.confidence.value,
                    "module": finding.module,
                    "tags": finding.tags,
                    "remediation": finding.remediation,
                    "evidence": finding.evidence.response[:2000],
                },
                "partialFingerprints": {"nemesis/v1": finding.fingerprint},
            }
        )

    document = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "nemesis",
                        "informationUri": "https://github.com/HexVandal/nemesis",
                        "version": "0.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": result.finished_at,
                    }
                ],
            }
        ],
    }

    import json

    target.write_text(json.dumps(document, indent=2, default=str), encoding="utf-8")
    return target
