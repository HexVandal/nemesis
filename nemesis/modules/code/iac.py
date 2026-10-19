"""Infrastructure as Code misconfiguration scanning.

Cloud misconfiguration is the most common source of breaches there is, and
most of it is committed to a repository in a file that is trivially
machine-readable. Terraform HCL, Kubernetes YAML, Dockerfiles and
CloudFormation all describe the security posture of a deployment in plain
text, and all of them are parsed here.

The checks are the ones that map directly to real incidents: a storage
bucket that is public, a security group that opens everything, a container
that runs as root with the host's namespaces, and a credential in a
configuration file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from .common import read_lines

#: Terraform resource types that expose data publicly.
_PUBLIC_STORAGE_TYPES = (
    "aws_s3_bucket",
    "aws_s3_bucket_policy",
    "aws_s3_bucket_acl",
    "google_storage_bucket",
    "azurerm_storage_container",
    "azurerm_storage_account",
)

#: Terraform resources that open a network.
_NETWORK_TYPES = (
    "aws_security_group",
    "aws_security_group_rule",
    "google_compute_firewall",
    "azurerm_network_security_group",
    "azurerm_network_security_rule",
)

#: Terraform resources that carry an identity policy.
_IDENTITY_TYPES = (
    "aws_iam_role",
    "aws_iam_role_policy",
    "aws_iam_policy",
    "aws_iam_user_policy",
    "google_project_iam_policy",
    "azurerm_role_assignment",
)

#: The wildcard that makes an ACL or a policy public.
_PUBLIC_MARKERS = (
    '"*"',
    '"0.0.0.0/0"',
    '"::/0"',
    "public-read",
    "public-read-write",
    "AllUsers",
    "AuthenticatedUsers",
    "allUsers",
    "allAuthenticatedUsers",
)

#: Kubernetes pod-security settings that matter.
_K8S_PRIVILEGED = (
    "privileged: true",
    "allowprivilegeescalation: true",
    "hostnetwork: true",
    "hostpid: true",
    "hostipc: true",
    "runasuser: 0",
)

#: The same settings, with the original spelling, for exact-case matching.
_K8S_PRIVILEGED_EXACT = (
    "privileged: true",
    "allowPrivilegeEscalation: true",
    "hostNetwork: true",
    "hostPID: true",
    "hostIPC: true",
    "runAsUser: 0",
)


class IacMisconfigurationModule(Module):
    """Scans infrastructure as code for dangerous configuration."""

    group = "code"
    id = "iac_misconfiguration"
    name = "Infrastructure as Code Misconfiguration"
    description = (
        "Scans Terraform, Kubernetes, Dockerfiles and CloudFormation for "
        "public storage, wide-open network rules, privileged containers, "
        "wildcard identity policies and embedded credentials."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.CODE
    cwe = "CWE-284"
    owasp = "A05"
    tags = ["iac", "terraform", "kubernetes", "docker", "cloud", "config"]
    remediation = (
        "Apply the principle of least privilege to the infrastructure: no "
        "public buckets, no 0.0.0.0/0 on administrative ports, no "
        "wildcard identity policies, containers that drop privileges and "
        "do not share the host namespaces, and no credentials in "
        "configuration files."
    )
    references = [
        "https://owasp.org/www-project-top-10-cloud-security/",
        "https://www.cisecurity.org/benchmark/kubernetes",
    ]

    #: File suffixes that hold infrastructure definitions.
    suffixes = (".tf", ".tfvars", ".yaml", ".yml", ".json", ".dockerfile")

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        findings: list[Finding] = []
        root = Path(ctx.code_path)
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if self._is_ignored(path, root):
                continue
            name = path.name.lower()
            if name == "dockerfile" or name.startswith("dockerfile."):
                findings.extend(self._scan_dockerfile(path))
            elif path.suffix.lower() in (".tf", ".tfvars"):
                findings.extend(self._scan_terraform(path))
            elif path.suffix.lower() in (".yaml", ".yml", ".json"):
                text = path.read_text(encoding="utf-8", errors="replace")
                if "AWSTemplateFormatVersion" in text or "Resources" in text:
                    findings.extend(self._scan_cloudformation(path, text))
                else:
                    findings.extend(self._scan_kubernetes(path, text))
        return findings

    # -- helpers ---------------------------------------------------------
    def _is_ignored(self, path: Path, root: Path) -> bool:
        parts = path.relative_to(root).parts
        skip = {
            ".git", ".terraform", "node_modules", "vendor", "__pycache__",
            ".venv", "venv", "dist", "build", ".mypy_cache", "site-packages",
        }
        return any(part in skip for part in parts)

    def _scan_terraform(self, path: Path) -> list[Finding]:
        lines = read_lines(path)
        findings: list[Finding] = []
        block: list[str] = []
        block_type = ""
        block_start = 0

        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("resource ") and '"' in stripped:
                block_type = stripped.split('"')[1]
                block = []
                block_start = number
            elif block_type:
                block.append(line)
                if stripped == "}":
                    findings.extend(
                        self._terraform_findings(path, block_type, block_start, block)
                    )
                    block_type = ""
        return findings

    def _terraform_findings(
        self, path: Path, resource_type: str, start: int, block: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        text = "\n".join(block)

        if resource_type in _PUBLIC_STORAGE_TYPES and any(
            marker in text for marker in _PUBLIC_MARKERS
        ):
            findings.append(
                self._finding(
                    path,
                    start,
                    "Infrastructure exposes storage to the public",
                    f"The {resource_type} resource grants public access. "
                    f"Anything written to that bucket is readable by "
                    f"anyone on the internet.",
                    Severity.CRITICAL,
                    "public access",
                )
            )

        if resource_type in _NETWORK_TYPES and (
            '"0.0.0.0/0"' in text or '"::/0"' in text
        ):
            findings.append(
                self._finding(
                    path,
                    start,
                    "Infrastructure allows traffic from anywhere",
                    f"The {resource_type} resource opens a port to "
                    f"0.0.0.0/0, which is the entire internet. "
                    f"Administrative ports should never be reachable "
                    f"from outside the environment.",
                    Severity.HIGH,
                    "0.0.0.0/0",
                )
            )

        if resource_type in _IDENTITY_TYPES and (
            '"Action": "*"' in text or '"Action":"*"' in text
        ):
            findings.append(
                self._finding(
                    path,
                    start,
                    "Infrastructure grants wildcard permissions",
                    f"The {resource_type} resource allows every action on "
                    f"every resource. This is the policy shape that "
                    f"turns a single compromised key into a full "
                    f"account takeover.",
                    Severity.HIGH,
                    '"Action": "*"',
                )
            )

        hardcoded = re.search(
            r"(password|secret|access_key)\s*=\s*\"(?!\$)[^\"$]{6,}\"", text
        )
        if hardcoded:
            findings.append(
                self._finding(
                    path,
                    start,
                    "Infrastructure file contains a hardcoded credential",
                    "A credential is written literally into the "
                    "infrastructure definition rather than referenced "
                    "from a secret store.",
                    Severity.HIGH,
                    "hardcoded credential",
                )
            )

        return findings

    def _scan_kubernetes(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        for number, line in enumerate(lines, start=1):
            lowered = line.lower()
            for marker in _K8S_PRIVILEGED_EXACT:
                if marker.lower() in lowered:
                    findings.append(
                        self._finding(
                            path,
                            number,
                            "Kubernetes workload runs with elevated privileges",
                            f"The manifest sets '{marker}'. A container "
                            f"that can see the host namespaces, or escalate "
                            f"its own privileges, is one container escape "
                            f"away from the node.",
                            Severity.HIGH,
                            marker,
                        )
                    )
                    break
        return findings

    def _scan_cloudformation(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            template = json.loads(text)
        except (ValueError, TypeError):
            return findings

        resources = template.get("Resources") or {}
        if not isinstance(resources, dict):
            return findings

        for name, resource in resources.items():
            if not isinstance(resource, dict):
                continue
            properties = resource.get("Properties") or {}
            blob = json.dumps(resource)
            if any(marker in blob for marker in _PUBLIC_MARKERS):
                findings.append(
                    self._finding(
                        path,
                        1,
                        "CloudFormation template exposes a resource publicly",
                        f"The resource '{name}' grants public access.",
                        Severity.HIGH,
                        name,
                    )
                )
            if properties.get("Open") or properties.get("CidrIp") == "0.0.0.0/0":
                findings.append(
                    self._finding(
                        path,
                        1,
                        "CloudFormation template opens a port to the world",
                        f"The resource '{name}' allows traffic from "
                        f"0.0.0.0/0.",
                        Severity.HIGH,
                        name,
                    )
                )
        return findings

    def _scan_dockerfile(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        lines = read_lines(path)
        has_user = False
        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("USER "):
                has_user = True
                user = stripped.split(None, 1)[1].strip().lower()
                if user in ("root", "0", "root:root"):
                    findings.append(
                        self._finding(
                            path,
                            number,
                            "Docker image runs as root",
                            "The container's default user is root, so any "
                            "code execution inside it starts with the "
                            "highest privilege available to the container.",
                            Severity.MEDIUM,
                            "USER root",
                        )
                    )
            if stripped.upper().startswith("ADD ") and "http://" in stripped:
                findings.append(
                    self._finding(
                        path,
                        number,
                        "Dockerfile adds a remote file over plain HTTP",
                        "A remote URL added over http:// can be replaced in "
                        "transit, which turns the build into an arbitrary "
                        "code execution primitive.",
                        Severity.MEDIUM,
                        "ADD http://",
                    )
                )
        if lines and not has_user:
            findings.append(
                self._finding(
                    path,
                    1,
                    "Docker image does not set a non-root user",
                    "The image never issues a USER instruction, so every "
                    "process in the container runs as root by default.",
                    Severity.LOW,
                    "no USER instruction",
                )
            )
        return findings

    def _finding(
        self,
        path: Path,
        line_number: int,
        title: str,
        description: str,
        severity: Severity,
        matched: str,
    ) -> Finding:
        return self.finding(
            title=title,
            target=str(path),
            description=f"{description} Found in {path}:{line_number}.",
            severity=severity,
            confidence=Confidence.HIGH,
            evidence_text=f"{path}:{line_number}\n{title}",
            matched=matched[:200],
            file=str(path),
            line=line_number,
        )
