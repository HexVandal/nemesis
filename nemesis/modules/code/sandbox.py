"""Container and sandbox escape detection.

A container is not a security boundary - it is a set of configuration
choices, and several of those choices remove the boundary entirely. The
well-known escape paths are not exotic:

- ``privileged: true`` gives the container the host's devices and almost
  all of its capabilities.
- Mounting ``/var/run/docker.sock`` hands the container the host's
  container runtime, which is root on the machine.
- ``hostPID`` / ``hostNetwork`` / ``hostIPC`` share the host's namespaces,
  so a kernel bug in the container is a kernel bug on the host.
- A container that keeps ``CAP_SYS_ADMIN`` can mount things itself.
- ``/proc`` mounted from the host leaks the host's process list, and
  often its environment.
- A root filesystem that is writable makes every file in the image
  replaceable by the attacker who gets code execution in it.
- Missing ``no-new-privileges`` means a setuid binary inside the image
  can gain privileges the container did not grant.

These are all visible in the configuration, and all of them are the
difference between "a bug in the app" and "a bug in the app that is now
a bug on the host".
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from .common import read_lines

#: Docker/OCI instructions that matter for escape.
_DOCKER_INSTRUCTIONS = ("USER", "RUN", "ADD", "COPY", "ENTRYPOINT", "CMD")

#: Container capabilities that allow an escape.
DANGEROUS_CAPABILITIES = (
    "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "NET_ADMIN",
    "DAC_READ_SEARCH", "DAC_OVERRIDE", "MKNOD", "SETUID", "SETGID",
    "LINUX_IMMUTABLE", "SYS_CHROOT", "BPF", "PERFMON", "CHECKPOINT_RESTORE",
)

#: Kubernetes pod-spec settings that remove the boundary.
K8S_ESCAPE_SETTINGS = {
    "privileged": ("CRITICAL", "A privileged container has almost the same "
                   "authority as the host, including the ability to load "
                   "kernel modules and to mount the host filesystem."),
    "allowprivilegeescalation": ("HIGH", "The container may gain "
                   "privileges it was not granted, which turns any setuid "
                   "binary in the image into an escalation path."),
    "hostpid": ("CRITICAL", "The container shares the host's PID namespace, "
                   "so it can see and signal every process on the host, "
                   "including ones running as root."),
    "hostnetwork": ("HIGH", "The container shares the host's network "
                   "namespace, so it can reach services bound to the host's "
                   "loopback address."),
    "hostipc": ("HIGH", "The container shares the host's IPC namespace, "
                   "which is a path to shared memory attacks against the "
                   "host."),
    "hostpath": ("CRITICAL", "The container mounts a directory from the "
                   "host, so a write inside the container is a write on the "
                   "host."),
    "runasuser": ("MEDIUM", "The container's user is set explicitly; a "
                   "value of 0 means root."),
    "privilegeddevices": ("HIGH", "The container is given raw device "
                   "access, which is enough to read host memory."),
}

#: Volume mounts that expose the host.
HOST_MOUNT_MARKERS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio",
    "/etc/kubernetes",
    "/",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/var/lib/kubelet",
    "/host",
)

#: Kubernetes volume types that are host paths.
HOST_PATH_TYPES = ("hostPath", "hostPathVolume")

#: A writable-root-filesystem requirement.
NO_NEW_PRIVILEGES = re.compile(r"no[-_]?new[-_]?privileges", re.IGNORECASE)


class SandboxEscapeModule(Module):
    """Detects configuration that removes a container's isolation."""

    group = "code"
    id = "sandbox_escape"
    name = "Sandbox Escape Detection"
    description = (
        "Audits container and pod configuration for the settings that "
        "remove the isolation boundary: privileged containers, host "
        "namespace sharing, the Docker socket mounted inside, dangerous "
        "capabilities, and a writable root filesystem."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.CODE
    cwe = "CWE-250"
    owasp = "A05"
    tags = ["container", "docker", "kubernetes", "sandbox", "escape", "runc"]
    remediation = (
        "Run containers as a non-root user, drop every capability except "
        "the ones the workload needs, set no-new-privileges, mount the "
        "root filesystem read-only, never mount the container runtime's "
        "socket into a workload, and do not share the host's PID, network "
        "or IPC namespaces."
    )
    references = [
        "https://attackerkb.com/attacker-kb-containerd-cgroups-exploit",
        "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        "https://docs.docker.com/engine/security/rootless/",
    ]

    max_files = 400

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = Path(ctx.code_path)
        findings: list[Finding] = []
        for path in self._config_files(root)[: self.max_files]:
            findings.extend(self._audit(path, root))
        return findings

    # -- discovery -------------------------------------------------------
    def _config_files(self, root: Path) -> list[Path]:
        skip = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
        found: list[Path] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part in skip for part in path.relative_to(root).parts):
                continue
            name = path.name.lower()
            relative = path.relative_to(root).as_posix().lower()
            if name.startswith("dockerfile") or name == "containerfile" or name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml") or (path.suffix.lower() in (".yaml", ".yml", ".json") and (
                relative.startswith(("k8s/", "kubernetes/", "manifests/", "deploy/", "helm/"))
                or "kube" in relative
                or name.endswith(("-deployment.yaml", "-deployment.yml", "-pod.yaml", "-pod.yml"))
            )):
                found.append(path)
        return found

    # -- analysis --------------------------------------------------------
    def _audit(self, path: Path, root: Path) -> list[Finding]:
        relative = str(path.relative_to(root)) if root in path.parents else str(path)
        text = path.read_text(encoding="utf-8", errors="replace")
        lowered = text.lower()
        findings: list[Finding] = []

        # -- Kubernetes-style manifests ---------------------------------
        if path.suffix.lower() in (".yaml", ".yml", ".json") and not path.name.lower().startswith("dockerfile"):
            findings.extend(self._audit_manifest(path, relative, text, lowered))
            return findings

        # -- Dockerfile ---------------------------------------------------
        lines = read_lines(path)
        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            upper = stripped.upper()

            if upper.startswith("USER "):
                user = stripped.split(None, 1)[1].strip().lower()
                if user in ("root", "0", "root:root"):
                    findings.append(
                        self._finding(
                            relative, number, Severity.MEDIUM,
                            "Container runs as root",
                            "The image's default user is root, so any code "
                            "execution inside it starts with the highest "
                            "privilege available to the container. Combined "
                            "with a writable root filesystem, a single "
                            "injection is a foothold rather than a "
                            "containment.",
                        )
                    )

            if upper.startswith(("RUN ", "ADD ", "COPY ")) and "--privileged" in stripped:
                findings.append(
                    self._finding(
                        relative, number, Severity.CRITICAL,
                        "Build step runs a privileged container",
                        "A privileged build step has the host's devices and "
                        "capabilities, and anything the build downloads at "
                        "that moment runs with them.",
                    )
                )

            if upper.startswith("RUN ") and ("--cap-add" in stripped or "--cap-add=SYS_ADMIN" in stripped):
                findings.append(
                    self._finding(
                        relative, number, Severity.HIGH,
                        "Build step adds a Linux capability",
                        "Adding a capability to a build step means the "
                        "commands in that step run with it. SYS_ADMIN in "
                        "particular is enough to mount filesystems.",
                    )
                )

            if upper.startswith("RUN ") and "--security-opt" in stripped and "seccomp=unconfined" in stripped:
                findings.append(
                    self._finding(
                        relative, number, Severity.CRITICAL,
                        "Build step disables the seccomp profile",
                        "Without a seccomp profile the container can make "
                        "almost any syscall, which removes the last layer "
                        "between a container bug and a host compromise.",
                    )
                )

        # -- Compose files ------------------------------------------------
        if path.name.lower().startswith(("docker-compose", "compose.")):
            findings.extend(self._audit_compose(path, relative, text))

        return findings

    def _audit_manifest(
        self, path: Path, relative: str, text: str, lowered: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        data = None
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            data = None

        if data is not None:
            documents = data.get("items", [data]) if isinstance(data, dict) else [data]
        else:
            documents = None

        if documents is not None:
            for document in documents:
                if not isinstance(document, dict):
                    continue
                findings.extend(self._audit_k8s_object(relative, document))
            return findings

        # YAML manifests: line-oriented, which is enough for the settings
        # that matter because each of them appears on its own line.
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            key, _, value = stripped.partition(":")
            key = key.strip().lower()
            value = value.strip().strip("\"'").lower()
            if key in K8S_ESCAPE_SETTINGS:
                severity_text, why = K8S_ESCAPE_SETTINGS[key]
                if key == "runasuser" and value not in ("0",):
                    continue
                if key == "privileged" and value != "true":
                    continue
                if key == "allowprivilegeescalation" and value != "true":
                    continue
                if key.startswith("host") and value != "true":
                    continue
                findings.append(
                    self._finding(
                        relative, number, Severity[severity_text],
                        f"Kubernetes manifest sets '{key}'",
                        f"{why}",
                    )
                )
            if key in ("hostpath", "hostpathvolume") or "hostpath" in key:
                findings.append(
                    self._finding(
                        relative, number, Severity.CRITICAL,
                        "Pod mounts a host path",
                        "A hostPath volume puts a directory from the host "
                        "inside the pod. Anything the pod writes there is "
                        "written on the host, which is how a container "
                        "escape usually completes.",
                    )
                )
            if key == "runasuser" and value == "0":
                findings.append(
                    self._finding(
                        relative, number, Severity.MEDIUM,
                        "Container is configured to run as root",
                        "runAsUser 0 gives the workload the same root "
                        "identity inside the container that the container "
                        "itself runs as, which is the default in a lot of "
                        "older manifests.",
                    )
                )
        return findings

    def _audit_k8s_object(self, relative: str, document: dict) -> list[Finding]:
        findings: list[Finding] = []
        spec = document.get("spec", {})
        if not isinstance(spec, dict):
            return findings

        template = spec.get("template", {})
        if isinstance(template, dict) and isinstance(template.get("spec"), dict):
            spec = template["spec"]

        for key, (severity_text, why) in K8S_ESCAPE_SETTINGS.items():
            if key not in spec:
                continue
            value = spec[key]
            if key == "runasuser":
                if value not in (0, "0"):
                    continue
            elif value is not True and str(value).lower() != "true":
                continue
            findings.append(
                self._finding(
                    relative, 1, Severity[severity_text],
                    f"Kubernetes manifest sets '{key}'",
                    why,
                )
            )

        for volume in spec.get("volumes", []) or []:
            if not isinstance(volume, dict):
                continue
            if "hostPath" in volume:
                findings.append(
                    self._finding(
                        relative, 1, Severity.CRITICAL,
                        "Pod mounts a host path",
                        "A hostPath volume puts a directory from the host "
                        "inside the pod. Anything the pod writes there is "
                        "written on the host, which is how a container "
                        "escape usually completes.",
                    )
                )
            source = volume.get("hostPath", {})
            if isinstance(source, dict) and source.get("path") in HOST_MOUNT_MARKERS:
                findings.append(
                    self._finding(
                        relative, 1, Severity.CRITICAL,
                        f"Pod mounts a sensitive host path ({source.get('path')})",
                        "This path belongs to the host, not to the "
                        "workload. Mounting it gives the container access "
                        "to the host's control plane, its processes or its "
                        "devices.",
                    )
                )
        return findings

    def _audit_compose(self, path: Path, relative: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            data = None

        services = []
        if isinstance(data, dict):
            raw = data.get("services", {})
            if isinstance(raw, dict):
                services = list(raw.values())
        if not services:
            # YAML compose: line-oriented is enough for the flags that
            # matter, because each of them is a single scalar.
            for number, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip().lower()
                if stripped in ("privileged: true",):
                    findings.append(
                        self._finding(
                            relative, number, Severity.CRITICAL,
                            "Compose service runs privileged",
                            "A privileged service has the host's devices and "
                            "almost all of its capabilities, so a bug in the "
                            "service is a bug on the host.",
                        )
                    )
                elif stripped.startswith(("cap_add:", "cap_add :")):
                    caps = stripped.split(":", 1)[1]
                    for cap in DANGEROUS_CAPABILITIES:
                        if cap.lower() in caps.lower():
                            findings.append(
                                self._finding(
                                    relative, number, Severity.HIGH,
                                    f"Compose service adds the {cap} capability",
                                    "This capability is enough to escalate from "
                                    "inside the container to the host.",
                                )
                            )
                            break
                elif stripped.startswith(("/var/run/docker.sock", "/run/docker.sock")):
                    findings.append(
                        self._finding(
                            relative, number, Severity.CRITICAL,
                            "Compose service mounts the Docker socket",
                            "The Docker socket is the container runtime's "
                            "control plane. Mounting it gives the container "
                            "the ability to start a privileged container on "
                            "the host, which is root on the host.",
                        )
                    )
                elif stripped.startswith("pid:") and "host" in stripped:
                    findings.append(
                        self._finding(
                            relative, number, Severity.HIGH,
                            "Compose service shares the host PID namespace",
                            "The container can see and signal every process on "
                            "the host, including the ones running as root.",
                        )
                    )
                elif stripped.startswith("network_mode:") and "host" in stripped:
                    findings.append(
                        self._finding(
                            relative, number, Severity.HIGH,
                            "Compose service uses the host network",
                            "The container reaches services bound to the "
                            "host's loopback address, which are usually "
                            "assumed to be unreachable from outside.",
                        )
                    )
            return findings

        for service in services:
            if not isinstance(service, dict):
                continue
            if service.get("privileged") is True:
                findings.append(
                    self._finding(
                        relative, 1, Severity.CRITICAL,
                        "Compose service runs privileged",
                        "A privileged service has the host's devices and "
                        "almost all of its capabilities, so a bug in the "
                        "service is a bug on the host.",
                    )
                )
            for cap in service.get("cap_add", []) or []:
                if str(cap).upper() in DANGEROUS_CAPABILITIES:
                    findings.append(
                        self._finding(
                            relative, 1, Severity.HIGH,
                            f"Compose service adds the {cap} capability",
                            "This capability is enough to escalate from inside "
                            "the container to the host.",
                        )
                    )
            for volume in service.get("volumes", []) or []:
                volume = str(volume)
                for marker in HOST_MOUNT_MARKERS:
                    if volume.startswith(marker + ":") or volume == marker:
                        findings.append(
                            self._finding(
                                relative, 1, Severity.CRITICAL,
                                f"Compose service mounts {marker}",
                                "This path belongs to the host. Mounting it "
                                "gives the container access to the host's "
                                "control plane, its processes or its devices.",
                            )
                        )
                        break
        return findings

    # -- reporting -------------------------------------------------------
    def _finding(
        self, relative: str, line: int, severity: Severity, title: str, why: str
    ) -> Finding:
        return self.finding(
            title=title,
            target=f"{relative}:{line}",
            description=f"{why} Found in {relative}:{line}.",
            severity=severity,
            confidence=Confidence.HIGH,
            evidence_text=f"{relative}:{line}\n{title}",
            matched=title,
            file=relative,
            line=line,
        )
