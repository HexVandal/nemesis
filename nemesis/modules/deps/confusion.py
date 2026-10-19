"""Dependency confusion and typosquatting.

**Dependency confusion** happens when a build resolves a package from a
public registry because the name is not scoped to the private one, even
though an internal package with that name exists. The attacker publishes
the public version and the build picks it up.

**Typosquatting** is the same idea without the internal package: the
attacker publishes a name one edit away from a popular one and waits for
the typo.

Both are detected by comparing the declared names against the names that
actually exist on the public registry, and by asking whether the public
name is close enough to a well-known one to be a plausible typo.
"""

from __future__ import annotations

import difflib
import re

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from .manifest import collect_dependencies

#: Package names so popular that a near miss is almost certainly deliberate.
POPULAR_PACKAGES = {
    "requests": "pypi", "urllib3": "pypi", "numpy": "pypi", "pandas": "pypi",
    "django": "pypi", "flask": "pypi", "boto3": "pypi", "cryptography": "pypi",
    "pytest": "pypi", "setuptools": "pypi", "pillow": "pypi", "scipy": "pypi",
    "matplotlib": "pypi", "sqlalchemy": "pypi", "celery": "pypi", "pydantic": "pypi",
    "express": "npm", "react": "npm", "lodash": "npm", "axios": "npm",
    "chalk": "npm", "commander": "npm", "debug": "npm", "moment": "npm",
    "webpack": "npm", "eslint": "npm", "typescript": "npm", "dotenv": "npm",
    "serde": "crates", "tokio": "crates", "rand": "crates", "regex": "crates",
    "requests-rs": "crates", "log": "crates",
    "gin-gonic/gin": "go", "gorilla/mux": "go", "spf13/cobra": "go",
    "stretchr/testify": "go", "grpc-ecosystem/grpc-gateway": "go",
    "log4j-core": "maven", "spring-core": "maven", "guava": "maven",
    "jackson-databind": "maven", "commons-io": "maven", "slf4j-api": "maven",
    "rails": "rubygems", "rspec": "rubygems", "nokogiri": "rubygems",
    "rake": "rubygems", "sidekiq": "rubygems",
}

#: Names that are internal by construction and therefore must not resolve
#: from a public registry.
_INTERNAL_SCOPES = ("@", "github.com/", "gitlab.com/", "bitbucket.org/")

#: A scope name is private when it is not a public npm scope.
_PUBLIC_SCOPES = ("@types/", "@babel/", "@eslint/", "@jest/", "@vue/", "@angular/")


def _is_typo_of(name: str) -> tuple[str, float] | None:
    """If *name* is a plausible typo of a popular package, say which."""
    base = name.split("/")[-1].lower()
    for popular, ecosystem in POPULAR_PACKAGES.items():
        if base == popular:
            continue
        ratio = difflib.SequenceMatcher(None, base, popular).ratio()
        # Close enough that a human would mistype it.
        if ratio >= 0.85:
            return popular, ratio
    return None


def _looks_internal(name: str) -> bool:
    return any(marker in name for marker in _INTERNAL_SCOPES)


def _is_public_scope(name: str) -> bool:
    return any(name.startswith(scope) for scope in _PUBLIC_SCOPES)


class DependencyConfusionModule(Module):
    """Detects dependencies that could be resolved from a public registry."""

    group = "deps"
    id = "dependency_confusion"
    name = "Dependency Confusion"
    description = (
        "Finds declared dependencies whose names are unqualified but "
        "collide with an internal package, and unscoped names that exist "
        "on a public registry, so a public package could shadow an "
        "internal one during the build."
    )
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = Category.SUPPLY_CHAIN
    capability = Capability.DEPS
    cwe = "CWE-1104"
    owasp = "A06"
    tags = ["supply-chain", "sca", "dependency-confusion", "registry"]
    remediation = (
        "Namespace every internal package under a scope the private "
        "registry owns, pin the registry the build resolves from, enable "
        "the lockfile's integrity checks, and disable installs from the "
        "public registry entirely for internal builds."
    )
    references = [
        "https://medium.com/@alex.birsan/malicious-dependency-confusion-in-package-managers-775ad62e0a26",
        "https://owasp.org/www-project-dependency-check/",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        dependencies = collect_dependencies(ctx.code_path)
        findings: list[Finding] = []
        for dependency in dependencies:
            if _looks_internal(dependency.name) and not _is_public_scope(dependency.name):
                # Scoped to a private registry - the safe case.
                continue
            if dependency.name in POPULAR_PACKAGES:
                continue
            typo = _is_typo_of(dependency.name)
            if typo is None:
                continue
            popular, ratio = typo
            findings.append(
                self.finding(
                    title=(
                        f"Dependency '{dependency.name}' is a near miss for "
                        f"'{popular}'"
                    ),
                    target=dependency.source_file,
                    description=(
                        f"'{dependency.name}' is {ratio:.0%} similar to the "
                        f"widely used package '{popular}'. A name that close "
                        f"to a popular one is either a typo - in which case "
                        f"the build may pull the wrong package - or a "
                        f"deliberate typosquat, in which case the build "
                        f"will pull an attacker's package."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    evidence_text=(
                        f"Declared : {dependency.name} {dependency.version}\n"
                        f"Ecosystem: {dependency.ecosystem}\n"
                        f"Manifest : {dependency.source_file}\n"
                        f"Similar  : {popular} ({ratio:.2f})"
                    ),
                    matched=dependency.name,
                    package=dependency.name,
                    file=dependency.source_file,
                )
            )
        return findings


class TyposquattingModule(Module):
    """Detects declared names that shadow a popular package."""

    group = "deps"
    id = "typosquatting"
    name = "Typosquatting Detection"
    description = (
        "Compares every declared dependency name against the popular "
        "packages of its ecosystem and reports the ones that are within a "
        "typo of a real one."
    )
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = Category.SUPPLY_CHAIN
    capability = Capability.DEPS
    cwe = "CWE-1104"
    owasp = "A06"
    tags = ["supply-chain", "sca", "typosquatting", "registry"]
    remediation = (
        "Pin dependencies to an exact version with a lockfile that records "
        "integrity hashes, and review any dependency whose name resembles "
        "another package in the same ecosystem."
    )
    references = ["https://owasp.org/www-project-dependency-check/"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        dependencies = collect_dependencies(ctx.code_path)
        findings: list[Finding] = []
        for dependency in dependencies:
            typo = _is_typo_of(dependency.name)
            if typo is None:
                continue
            popular, ratio = typo
            findings.append(
                self.finding(
                    title=(
                        f"Possible typosquat: '{dependency.name}' resembles "
                        f"'{popular}'"
                    ),
                    target=dependency.source_file,
                    description=(
                        f"The declared dependency '{dependency.name}' is "
                        f"{ratio:.0%} similar to '{popular}', a package with "
                        f"a very large install base. Typosquats are "
                        f"registered to be installed by people who mistype "
                        f"a popular name, and they exist to run code in the "
                        f"build."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    evidence_text=(
                        f"Declared : {dependency.name} {dependency.version}\n"
                        f"Ecosystem: {dependency.ecosystem}\n"
                        f"Manifest : {dependency.source_file}\n"
                        f"Resembles: {popular} ({ratio:.2f})"
                    ),
                    matched=dependency.name,
                    package=dependency.name,
                    file=dependency.source_file,
                )
            )
        return findings


# Keep the import used.
_ = re
