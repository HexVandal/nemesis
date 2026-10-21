"""What a release should carry with it: a lock, a bill of materials, a signature."""

from __future__ import annotations

from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

LOCKFILES = (
    "poetry.lock", "Pipfile.lock", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "go.sum", "Cargo.lock", "composer.lock", "Gemfile.lock",
)
SBOMS = ("sbom.json", "sbom.xml", "bom.json", "cyclonedx.json", "bom.xml")
MANIFESTS = ("pyproject.toml", "requirements.txt", "package.json", "go.mod", "Cargo.toml")


def _root(ctx: ScanContext) -> Path | None:
    if not ctx.code_path:
        return None
    root = Path(ctx.code_path)
    return root if root.exists() else None


def _find(root: Path, names: tuple[str, ...], depth: int = 2) -> list[Path]:
    found: list[Path] = []
    for name in names:
        for path in root.glob(name):
            found.append(path)
        for path in root.glob(f"*/{name}"):
            found.append(path)
        if depth > 2:
            for path in root.glob(f"*/*/{name}"):
                found.append(path)
    return found


class LockfileModule(Module):
    """A manifest without a lock is a build nobody can reproduce."""

    group = "supplychain"
    id = "lockfile_integrity"
    name = "Missing or Incomplete Lockfile"
    description = (
        "Reports a dependency manifest with no lock beside it, or a lock that "
        "does not pin resolved hashes."
    )
    severity = Severity.MEDIUM
    confidence: Confidence = Confidence.HIGH
    category = Category.SUPPLY_CHAIN
    capability = Capability.CODE
    cwe = "CWE-1104"
    owasp = "A08"
    remediation = "Commit the lockfile, and install with the locked resolver in CI."
    references = ["https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities"]
    tags = ["supply-chain", "reproducibility"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = _root(ctx)
        if root is None:
            return []
        manifests = _find(root, MANIFESTS)
        locks = _find(root, LOCKFILES)
        if not manifests or locks:
            return []
        return [
            self.finding(
                title=f"{manifests[0].name} has no lockfile",
                target=str(manifests[0]),
                description=(
                    "The project declares dependencies but commits no lock. Every "
                    "install resolves again, so two builds of the same commit can "
                    "contain different code."
                ),
                evidence_text=f"found: {', '.join(str(m.name) for m in manifests)}\nlocks: none",
                matched="no lockfile",
                file=str(manifests[0]),
            )
        ]


class SbomModule(Module):
    """Without a bill of materials, an advisory takes days to triage."""

    group = "supplychain"
    id = "sbom_presence"
    name = "No Software Bill of Materials"
    description = "Reports a repository that ships no SBOM in any common format."
    severity = Severity.LOW
    confidence: Confidence.CONFIRMED
    category = Category.SUPPLY_CHAIN
    capability = Capability.CODE
    cwe = "CWE-1104"
    owasp = "A08"
    remediation = "Generate CycloneDX or SPDX in CI and attach it to the release."
    references = ["https://cyclonedx.org/docs/1.5/"]
    tags = ["supply-chain", "sbom"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = _root(ctx)
        if root is None:
            return []
        if not _find(root, MANIFESTS) or _find(root, SBOMS):
            return []
        return [
            self.finding(
                title="No SBOM in the tree",
                target=str(root),
                description=(
                    "There is no CycloneDX or SPDX document. When the next "
                    "library advisory lands, answering 'are we affected' starts "
                    "with rebuilding the dependency list by hand."
                ),
                evidence_text=f"{root}: no sbom.json, bom.json or CycloneDX document",
                matched="no SBOM",
                file=str(root),
            )
        ]


class ProvenanceModule(Module):
    """Nothing in the tree says who built this or from what."""

    group = "supplychain"
    id = "artifact_provenance"
    name = "No Build Provenance"
    description = (
        "Reports a release with no signature, checksum file or provenance "
        "attestation beside it."
    )
    severity = Severity.LOW
    confidence: Confidence.MEDIUM
    category = Category.SUPPLY_CHAIN
    capability = Capability.CODE
    cwe = "CWE-345"
    owasp = "A08"
    remediation = "Sign releases (sigstore/cosign) and publish an attestation."
    references = ["https://slsa.dev/provenance/v1"]
    tags = ["supply-chain", "provenance"]

    markers = ("*.sig", "*.asc", "*.intoto.jsonl", "provenance.json", "SHA256SUMS", "checksums.txt")

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = _root(ctx)
        if root is None:
            return []
        if not _find(root, MANIFESTS) or _find(root, self.markers):
            return []
        return [
            self.finding(
                title="No signature or provenance beside the build",
                target=str(root),
                description=(
                    "No .sig, .asc, checksum file or in-toto statement was found. "
                    "A consumer downloading this artifact cannot tell whether it "
                    "came from this repository."
                ),
                evidence_text=f"{root}: no signature, checksum or attestation",
                matched="no provenance",
                file=str(root),
            )
        ]
