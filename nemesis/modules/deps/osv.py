"""Software composition analysis backed by the OSV.dev database.

OSV.dev is the free, open vulnerability database that covers PyPI, npm,
crates.io, Go, Maven, RubyGems, Packagist, NuGet and more. Using it means
nemesis gets a maintained advisory feed without shipping a stale snapshot.
"""

from __future__ import annotations

import asyncio

import httpx

from ...knowledge.cvss import score_of
from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from .manifest import collect_dependencies

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

#: How many individual advisories to look up for severity data, and how many
#: of those lookups to run at once.
MAX_DETAIL_LOOKUPS = 250
DETAIL_CONCURRENCY = 12

#: OSV severity strings mapped onto our scale.
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class OsvVulnerabilityModule(Module):
    """Look up known vulnerabilities in declared dependencies."""
    group = "deps"

    id = "dependency_vulnerabilities"
    name = "Vulnerable Dependencies"
    description = (
        "Resolves dependencies from lockfiles and manifests, then checks each "
        "against the OSV.dev advisory database."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.SUPPLY_CHAIN
    capability = Capability.DEPS
    cwe = "CWE-1104"
    owasp = "A06"
    tags = ["deps", "sca", "supply-chain"]
    remediation = (
        "Upgrade the affected package to a patched release. If no fix exists, "
        "evaluate mitigations or replace the dependency."
    )
    references = ["https://osv.dev/", "https://owasp.org/www-project-dependency-check/"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        dependencies = collect_dependencies(ctx.code_path)
        if not dependencies:
            return []

        advisories = await self._query(ctx, dependencies)
        if not advisories:
            return []
        await self._enrich(ctx, advisories)

        findings: list[Finding] = []
        by_key = {dep.key: dep for dep in dependencies}
        for key, vulns in advisories.items():
            dep = by_key.get(key)
            if dep is None:
                continue
            finding = self._to_finding(dep, vulns, ctx)
            if finding:
                findings.append(finding)
        findings.sort(key=lambda f: -f.severity.value)
        return findings[:200]

    # -- OSV ---------------------------------------------------------------
    async def _query(self, ctx, dependencies) -> dict[str, list[dict]]:
        """Look up advisories for *dependencies*.

        The result is keyed by :attr:`Dependency.key` (a string) because the
        Dependency dataclass itself is mutable and therefore unhashable.
        """
        results: dict[str, list[dict]] = {}
        batch = dependencies[:200]
        queries = [
            {
                "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                "version": dep.version,
            }
            for dep in batch
        ]
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    OSV_BATCH_URL, json={"queries": queries}
                )
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            ctx.stats.setdefault("osv_errors", []).append(str(exc))
            return results

        for dep, result in zip(batch, data.get("results", []), strict=False):
            vulns = result.get("vulns") or []
            if vulns:
                results[dep.key] = vulns
        return results

    async def _enrich(self, ctx, advisories: dict[str, list[dict]]) -> None:
        """Fill in the severity of each advisory, in place.

        The ``querybatch`` endpoint returns advisory identifiers and titles
        but no severity - severity only appears on the individual advisory
        record. Without this step every dependency would be reported as
        "medium" and the output would be useless for triage.
        """
        wanted: list[str] = []
        for vulns in advisories.values():
            for vuln in vulns:
                advisory_id = vuln.get("id")
                if advisory_id and advisory_id not in wanted:
                    wanted.append(advisory_id)
        if not wanted:
            return

        limit = min(len(wanted), MAX_DETAIL_LOOKUPS)
        semaphore = asyncio.Semaphore(DETAIL_CONCURRENCY)

        async with httpx.AsyncClient(timeout=30.0) as client:

            async def fetch(advisory_id: str) -> tuple[str, dict | None]:
                async with semaphore:
                    try:
                        response = await client.get(f"{OSV_VULN_URL}{advisory_id}")
                        response.raise_for_status()
                        return advisory_id, response.json()
                    except Exception as exc:
                        ctx.stats.setdefault("osv_errors", []).append(
                            f"{advisory_id}: {exc}"
                        )
                        return advisory_id, None

            details = await asyncio.gather(*(fetch(a) for a in wanted[:limit]))

        table = {advisory_id: payload for advisory_id, payload in details if payload}
        for vulns in advisories.values():
            for vuln in vulns:
                advisory_id = vuln.get("id")
                payload = table.get(advisory_id or "")
                if not payload:
                    continue
                vuln["severity"] = payload.get("severity") or vuln.get("severity")
                vuln["database_specific"] = payload.get("database_specific") or {}
                vuln["summary"] = payload.get("summary") or vuln.get("summary")
                vuln["details"] = payload.get("details") or vuln.get("details")
                vuln["affected"] = payload.get("affected") or vuln.get("affected")
                vuln["aliases"] = payload.get("aliases") or vuln.get("aliases")

    def _to_finding(self, dep, vulns: list[dict], ctx: ScanContext) -> Finding | None:
        """Build **one** finding for a package, covering all of its advisories.

        A single outdated Django release can carry a dozen advisories.
        Reporting each one separately is how a scanner drowns a human in
        noise; the useful statement is "this package is affected by N known
        vulnerabilities, the worst of which is critical".
        """
        advisories: list[dict] = []
        for vuln in vulns:
            identifiers = vuln.get("aliases") or []
            cve = next((i for i in identifiers if i.startswith("CVE-")), None)
            advisory_id = vuln.get("id") or (identifiers[0] if identifiers else "UNKNOWN")
            summary = vuln.get("summary") or ""
            details = (vuln.get("details") or "").strip()
            if not summary and details:
                summary = details[:200]
            advisories.append(
                {
                    "id": advisory_id,
                    "cve": cve,
                    "severity": self._severity_of(vuln),
                    "summary": summary,
                    "fixed": self._fixed_version(vuln),
                }
            )

        if not advisories:
            return None

        worst = max(advisories, key=lambda a: a["severity"])
        count = len(advisories)
        ids = ", ".join(a["id"] for a in advisories[:12])
        if count > 12:
            ids += f", +{count - 12} more"

        fixed_versions = [a["fixed"] for a in advisories if a["fixed"]]
        fix_text = (
            f"Upgrade {dep.name} to {fixed_versions[0]} or later."
            if fixed_versions
            else f"No fixed release is recorded for {dep.name} {dep.version}."
        )

        cve_ids = [a["cve"] for a in advisories if a["cve"]]
        noun = "vulnerability" if count == 1 else "vulnerabilities"
        cve_suffix = ""
        if worst["cve"] and worst["cve"] != worst["id"]:
            cve_suffix = " ({})".format(worst["cve"])
        return self.finding(
            title=(
                f"{dep.name} {dep.version} is affected by {count} known {noun}"
            ),
            target=dep.source_file,
            description=(
                f"{dep.name} {dep.version} ({dep.ecosystem}) is affected by {count} "
                f"known {noun}. The most severe is {worst['id']}{cve_suffix}, "
                f"rated {worst['severity'].name}. "
                f"{worst['summary']} {fix_text}"
            ),
            severity=worst["severity"],
            confidence=Confidence.HIGH,
            evidence_text=(
                f"Package  : {dep.name} {dep.version}\n"
                f"Ecosystem: {dep.ecosystem}\n"
                f"Manifest : {dep.source_file}\n"
                f"Count    : {count}\n"
                f"Advisories: {ids}\n"
                f"CVEs     : {', '.join(cve_ids[:12]) if cve_ids else 'n/a'}\n"
                f"Worst    : {worst['id']} ({worst['severity'].name})\n"
                f"Summary  : {worst['summary'][:300]}\n"
                f"Fix      : {fix_text}"
            ),
            matched=worst["id"],
            package=dep.name,
            version=dep.version,
            advisory=worst["id"],
            cve=worst["cve"],
            file=dep.source_file,
            fix=fix_text,
            references=[f"https://osv.dev/vulnerability/{a['id']}" for a in advisories[:25]],
        )

    @staticmethod
    def _severity_of(vuln: dict) -> Severity:
        database_specific = vuln.get("database_specific") or {}
        raw = (database_specific.get("severity") or "").upper()
        if raw in _SEVERITY_MAP:
            return _SEVERITY_MAP[raw]

        for affected in vuln.get("affected", []) or []:
            for value in (affected.get("database_specific") or {}).values():
                text = str(value).upper()
                if text in _SEVERITY_MAP:
                    return _SEVERITY_MAP[text]

        # OSV usually publishes a CVSS *vector* rather than a number, so the
        # vector has to be evaluated to get a base score.
        for severity_entry in vuln.get("severity", []) or []:
            score = severity_entry.get("score", "")
            try:
                numeric = float(score)
            except (TypeError, ValueError):
                numeric = score_of(score)
            if numeric is None:
                continue
            if numeric >= 9.0:
                return Severity.CRITICAL
            if numeric >= 7.0:
                return Severity.HIGH
            if numeric >= 4.0:
                return Severity.MEDIUM
            if numeric > 0:
                return Severity.LOW
        return Severity.MEDIUM

    @staticmethod
    def _fixed_version(vuln: dict) -> str | None:
        for affected in vuln.get("affected", []) or []:
            for rng in affected.get("ranges", []) or []:
                for event in rng.get("events", []) or []:
                    if event.get("fixed"):
                        return event["fixed"]
        return None
