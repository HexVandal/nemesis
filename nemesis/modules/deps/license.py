"""Dependency licence risk analysis."""

from __future__ import annotations

import re
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from .manifest import collect_dependencies

#: Licences that require source disclosure when used in a distributed product.
_STRONG_COPYLEFT = {"agpl-3.0", "agpl-2.0", "gpl-3.0", "gpl-2.0", "gpl-3.0+", "gpl-2.0+"}
#: Licences that require source disclosure for modifications.
_WEAK_COPYLEFT = {"lgpl-3.0", "lgpl-2.1", "lgpl-2.0", "mpl-2.0", "eupl-1.2", "cddl-1.0", "epl-2.0"}

#: Licences that are incompatible with proprietary distribution.
_PROHIBITIVE = {"sspl-1.0", "busl-1.1", "elastic-license-2.0", "fair-source", "proprietary"}


class LicenseRiskModule(Module):
    """Flag copyleft and source-available dependencies."""
    group = "deps"

    id = "license_risk"
    name = "Licence Risk"
    description = (
        "Identifies dependencies under strong copyleft, file-level copyleft and "
        "source-available licences that may conflict with a proprietary or "
        "closed-source distribution."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.SUPPLY_CHAIN
    capability = Capability.DEPS
    cwe = "CWE-1357"
    owasp = "A06"
    tags = ["deps", "licence", "legal"]
    remediation = (
        "Have counsel confirm the licence obligations, and consider a permissively "
        "licensed alternative or an explicit commercial licence."
    )
    references = ["https://choosealicense.com/"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        dependencies = collect_dependencies(ctx.code_path)
        if not dependencies:
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        for dep in dependencies:
            licence = self._licence_for(ctx.code_path, dep)
            if not licence:
                continue
            normalised = licence.lower().replace(" ", "-")
            key = (dep.name, normalised)
            if key in seen:
                continue
            seen.add(key)

            severity: Severity | None = None
            explanation = ""
            if normalised in _PROHIBITIVE:
                severity = Severity.HIGH
                explanation = (
                    f"{licence} is source-available and restricts how the software "
                    "may be distributed or offered as a service."
                )
            elif normalised in _STRONG_COPYLEFT:
                severity = Severity.MEDIUM
                explanation = (
                    f"{licence} is a strong copyleft licence: distributing the "
                    "product requires releasing the corresponding source code."
                )
            elif normalised in _WEAK_COPYLEFT:
                severity = Severity.LOW
                explanation = (
                    f"{licence} requires source disclosure for modifications to the "
                    "library itself, though linking is generally permitted."
                )

            if severity is None:
                continue

            findings.append(
                self.finding(
                    title=f"{dep.name} is licensed under {licence}",
                    target=dep.source_file,
                    description=(
                        f"Dependency {dep.name} {dep.version} is distributed under "
                        f"{licence}. {explanation}"
                    ),
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    evidence_text=(
                        f"Package  : {dep.name} {dep.version} ({dep.ecosystem})\n"
                        f"Licence  : {licence}\nManifest : {dep.source_file}\n"
                        f"Note     : {explanation}"
                    ),
                    matched=licence,
                    package=dep.name,
                    version=dep.version,
                    licence=licence,
                    file=dep.source_file,
                )
            )
        return findings

    def _licence_for(self, root: str, dep) -> str | None:
        """Best-effort licence extraction for a dependency."""
        root_path = Path(root)
        if dep.ecosystem == "npm":
            package_json = root_path / "node_modules" / dep.name / "package.json"
            if package_json.is_file():
                try:
                    import json

                    data = json.loads(package_json.read_text(encoding="utf-8", errors="replace"))
                    licence = data.get("license")
                    if isinstance(licence, dict):
                        licence = licence.get("type")
                    if licence:
                        return str(licence)
                except Exception:
                    return None
            return None

        # Look for a LICENSE file next to the manifest.
        for candidate in root_path.rglob(f"{dep.name}*"):
            if candidate.is_file() and candidate.name.upper().startswith("LICEN"):
                try:
                    head = candidate.read_text(encoding="utf-8", errors="replace")[:4000]
                except OSError:
                    continue
                for line in head.splitlines():
                    match = re.match(
                        r"(?i)\s*(?:MIT|Apache|GPL|LGPL|MPL|BSD|ISC|AGPL)\b[\w\-\. ]*",
                        line,
                    )
                    if match:
                        return match.group(0).strip().split()[0]
        return None
