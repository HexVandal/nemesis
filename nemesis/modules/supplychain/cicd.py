"""CI/CD pipeline security.

The pipeline is the most privileged code in most organisations, and it is
usually the least reviewed. The weaknesses that matter are specific and
have names:

- ``pull_request_target`` runs with repository secrets in the context of
  the base branch, so checking out the pull request's code executes the
  attacker's code with the secrets.
- An unpinned third-party action is remote code execution in the build.
- A workflow that interpolates ``${{ github.event.* }}`` into a ``run:``
  block is command injection, because the expression is substituted before
  the shell sees it.
- A build that runs as root, or that mounts the Docker socket, hands the
  whole machine to the build.
"""

from __future__ import annotations

import re
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from ..code.common import read_lines

#: Workflow and CI file locations.
WORKFLOW_DIRS = (".github/workflows", ".github/actions", ".gitlab", ".circleci")
WORKFLOW_SUFFIXES = (".yml", ".yaml", ".gitlab-ci.yml", ".jenkinsfile")
PIPELINE_NAMES = (
    "jenkinsfile", "dockerfile", "azure-pipelines.yml", "azure-pipelines.yaml",
    "bitbucket-pipelines.yml", "buildkite.yml", "drone.yml", "woodpecker.yml",
)

#: The expression that turns a workflow input into a shell command.
_EXPRESSION = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")

#: Contexts whose value is attacker-controlled in a pull request.
_UNTRUSTED_CONTEXTS = (
    "github.event.pull_request",
    "github.event.issue",
    "github.event.comment",
    "github.event.review",
    "github.event.review_comment",
    "github.event.head_commit",
    "github.event.commits",
    "github.event.discussion",
    "github.event.workflow_run",
)

#: Actions that are popular enough to be worth impersonating.
_KNOWN_ACTIONS = (
    "actions/checkout", "actions/setup-python", "actions/setup-node",
    "actions/cache", "actions/upload-artifact", "actions/download-artifact",
    "docker/build-push-action", "github/codeql-action",
)


class CicdPipelineSecurityModule(Module):
    """Audits CI/CD pipeline definitions for the classic weaknesses."""

    group = "supplychain"
    id = "cicd_pipeline_security"
    name = "CI/CD Pipeline Security"
    description = (
        "Audits workflow and pipeline definitions for untrusted pull "
        "request code running with secrets, unpinned third-party actions, "
        "expression injection into shell commands, and containers that "
        "hand the build the whole machine."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = Category.SUPPLY_CHAIN
    capability = Capability.CODE
    cwe = "CWE-94"
    owasp = "A08"
    tags = ["cicd", "github-actions", "pipeline", "supply-chain", "secrets"]
    remediation = (
        "Use pull_request rather than pull_request_target for untrusted "
        "contributions, and never check out the pull request's code in a "
        "privileged context. Pin third-party actions to a commit SHA, "
        "pass untrusted values through the environment rather than "
        "interpolating them into a run block, and do not run the build as "
        "root or mount the Docker socket."
    )
    references = [
        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
        "https://cwe.mitre.org/data/definitions/94.html",
    ]

    max_files = 100

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = Path(ctx.code_path)
        findings: list[Finding] = []
        for path in self._pipeline_files(root)[: self.max_files]:
            findings.extend(self._audit(path, root))
        return findings

    # -- discovery -------------------------------------------------------
    def _pipeline_files(self, root: Path) -> list[Path]:
        skip = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
        found: list[Path] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part in skip for part in path.relative_to(root).parts):
                continue
            lowered = path.name.lower()
            relative = path.relative_to(root).as_posix().lower()
            if lowered in PIPELINE_NAMES or lowered.startswith("dockerfile") or (relative.startswith(".github/workflows/") and path.suffix.lower() in (
                ".yml", ".yaml"
            )) or lowered in (".gitlab-ci.yml", ".gitlab-ci.yaml") or (relative.startswith(".circleci/") and path.suffix.lower() in (".yml", ".yaml")):
                found.append(path)
        return found

    # -- analysis --------------------------------------------------------
    def _audit(self, path: Path, root: Path) -> list[Finding]:
        lines = read_lines(path)
        if not lines:
            return []
        text = "\n".join(lines)
        findings: list[Finding] = []

        is_github = ".github/workflows" in path.as_posix()

        # 1. pull_request_target with a checkout of untrusted code.
        if "pull_request_target" in text and "actions/checkout" in text:
            for number, line in enumerate(lines, start=1):
                if "actions/checkout" in line:
                    window = "\n".join(lines[max(0, number - 6) : number + 3])
                    if "github.event.pull_request" in window or "github.head_ref" in window:
                        findings.append(
                            self._finding(
                                path,
                                number,
                                "Pipeline checks out untrusted code in a privileged context",
                                "This workflow uses pull_request_target and "
                                "checks out the pull request's code. "
                                "pull_request_target runs with access to the "
                                "repository's secrets and a write token, so "
                                "anyone who can open a pull request can run "
                                "code with the repository's credentials.",
                                Severity.CRITICAL,
                                "pull_request_target + checkout of untrusted ref",
                            )
                        )
                        break

        # 2. Expression injection into a run block.
        for number, line in enumerate(lines, start=1):
            if "run:" not in line:
                continue
            script = line.split("run:", 1)[1]
            # A multi-line run block continues on the following lines.
            block = [script]
            for follow in lines[number : number + 12]:
                if follow.strip() and not follow.startswith(" " * (len(line) - len(line.lstrip()) + 2)):
                    break
                block.append(follow)
            block_text = "\n".join(block)
            for expression in _EXPRESSION.findall(block_text):
                if any(context in expression for context in _UNTRUSTED_CONTEXTS):
                    findings.append(
                        self._finding(
                            path,
                            number,
                            "Untrusted input is interpolated into a shell command",
                            f"The expression ${{{{ {expression} }}}} is "
                            f"substituted into a run block. Its value comes "
                            f"from the pull request, so an attacker controls "
                            f"part of a shell command line. Put the value in "
                            f"an environment variable and quote it instead.",
                            Severity.CRITICAL,
                            expression,
                        )
                    )
                    break

        # 3. Unpinned third-party actions.
        if is_github:
            for number, line in enumerate(lines, start=1):
                match = re.search(r"uses:\s*([^\s#]+)", line)
                if not match:
                    continue
                action = match.group(1)
                if action.startswith("./") or action.startswith("docker://"):
                    continue
                if "@" not in action:
                    continue
                name, _, ref = action.partition("@")
                if name in ("actions/checkout", "actions/upload-artifact"):
                    continue
                if re.fullmatch(r"[0-9a-f]{40}", ref):
                    continue  # pinned to a commit SHA, which is the safe form
                if ref in ("main", "master", "latest"):
                    findings.append(
                        self._finding(
                            path,
                            number,
                            "Third-party action is not pinned to a commit",
                            f"'{action}' tracks a branch rather than a "
                            f"commit. Whoever controls that repository can "
                            f"change what this workflow executes, and this "
                            f"workflow runs with the project's secrets. Pin "
                            f"it to a full commit SHA.",
                            Severity.HIGH,
                            action,
                        )
                    )

        # 4. Privileged build containers.
        if "docker.sock" in text:
            findings.append(
                self._finding(
                    path,
                    1,
                    "Pipeline mounts the Docker socket",
                    "Mounting the Docker socket gives the build full control "
                    "of the host, which is root on the machine running the "
                    "agent.",
                    Severity.CRITICAL,
                    "docker.sock",
                )
            )
        if re.search(r"^\s*privileged:\s*true", text, re.MULTILINE | re.IGNORECASE):
            findings.append(
                self._finding(
                    path,
                    1,
                    "Pipeline runs a privileged container",
                    "A privileged container has almost the same authority "
                    "as the host.",
                    Severity.HIGH,
                    "privileged: true",
                )
            )
        if re.search(r"runs-on:\s*self-hosted", text, re.IGNORECASE):
            findings.append(
                self._finding(
                    path,
                    1,
                    "Pipeline runs on a self-hosted runner",
                    "Self-hosted runners are long-lived machines that "
                    "usually sit inside the network perimeter, and a "
                    "compromise of one is a compromise of everything the "
                    "runner can reach.",
                    Severity.MEDIUM,
                    "self-hosted runner",
                )
            )

        # 5. Secrets interpolated into a command line.
        for number, line in enumerate(lines, start=1):
            if "run:" in line and "secrets." in line:
                findings.append(
                    self._finding(
                        path,
                        number,
                        "Secret is interpolated into a shell command",
                        "A secret substituted into a run block is exposed to "
                        "the shell, to the process table, and to anything "
                        "that echoes the command. Pass it through the "
                        "environment instead.",
                        Severity.HIGH,
                        "secrets in run block",
                    )
                )
                break

        return findings

    def _finding(
        self, path: Path, line_number: int, title: str, description: str, severity: Severity, matched: str
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
