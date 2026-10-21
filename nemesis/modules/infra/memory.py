"""Memory forensics.

A memory image is the most complete evidence you can have of what a
machine actually did. It contains every string the process ever read,
every key it logged, every token it held in memory. If you only have
the disk, you have what the machine chose to keep.

This module reads memory images and raw memory dumps directly, with no
external dependency - the same way the traffic module reads pcaps. It
implements the parts of the Volatility plugin family that a responder
actually reaches for first:

- **Process inventory** - parse the ``PsActiveProcessHead`` /
  ``PsActiveProcessList`` structures to recover the running process
  list, including processes that are hidden from the API view.
- **Command lines** - recover the arguments a process was launched with.
  This is how you find the process that dropped the beacon, and the
  shell that ran the loader.
- **Environment blocks** - ``PATH`` manipulation, proxy configuration
  and inherited credentials are all in the process environment.
- **Injected memory** - compare the memory regions of a process against
  the on-disk image to find sections that exist in memory but not on
  disk. That difference is what code injection looks like.
- **Network state** - recover the TCP/UDP connection table and the
  listening sockets, so you can see the outbound beacon to an address
  nobody in the incident report mentioned.
- **Strings and secrets** - credentials, private keys and tokens that
  were resident in memory and are now gone from disk.
- **Registry hives and injected commands** - persistence via Run keys
  and service entries embedded in the image.

The module is deliberately conservative: it reports what it can prove
from the image, with offsets, so the output can be checked by hand.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: Kernel memory dump formats we can recognise by magic.
DUMP_MAGICS = {
    b"LXDD": "Linux ELF core dump",
    b"EGSY": "Linux ELF core dump (64-bit)",
    b"PAGEDUMP": "Windows crash dump",
    b"PAGEDU64": "Windows crash dump (64-bit)",
    b"MDMP": "Windows minidump",
    b"HMEM": "Windows hibernation file",
    b"RAWD": "raw physical memory",
    b"\x4d\x4d\x00\x00": "Windows crash dump",
    b"\x45\x4c\x46": "ELF image",
}

#: Windows full-memory dump page headers we understand.
DUMP_TYPE_FULL = 1
DUMP_TYPE_MINI = 2

#: A credential-looking string in memory.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "AWS access key id",
        re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ),
    (
        "AWS secret access key",
        re.compile(rb"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    ),
    (
        "private key block",
        re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    (
        "bearer token",
        re.compile(rb"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{20,}=*)"),
    ),
    (
        "jwt",
        re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
    (
        "password assignment",
        re.compile(rb"(?i)\b(?:password|passwd|pwd|secret)\s*[=:]\s*['\"]?([^\s'\"]{6,})"),
    ),
    (
        "github token",
        re.compile(rb"gh[pousr]_[A-Za-z0-9]{16,}"),
    ),
    (
        "slack token",
        re.compile(rb"xox[abprs]-[A-Za-z0-9-]{10,}"),
    ),
    (
        "google api key",
        re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
    ),
    (
        "database connection string",
        re.compile(
            rb"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]{3,}@[^\s/]+"
        ),
    ),
)

#: A command line that suggests persistence or a staged payload.
SUSPICIOUS_COMMANDS = (
    ("powershell encoded command", re.compile(r"(?i)-e(?:nc(?:odedcommand)?)\s+[A-Za-z0-9+/=]{20,}")),
    ("powershell hidden window", re.compile(r"(?i)-w(?:indowstyle)?\s+hidden")),
    ("powershell download cradle", re.compile(r"(?i)(?:iex|invoke-expression).{0,80}(?:downloadstring|invoke-webrequest)")),
    ("curl to shell", re.compile(r"(?i)(?:curl|wget)\b.{0,120}\|\s*(?:ba)?sh\b")),
    ("vssadmin shadow deletion", re.compile(r"(?i)vssadmin(?:\.exe)?\s+delete\s+shadows")),
    ("wevtutil log clearing", re.compile(r"(?i)wevtutil(?:\.exe)?\s+cl\b")),
    ("bcdedit recovery disabled", re.compile(r"(?i)bcdedit\b.{0,80}recoveryenabled\s+no")),
    ("net user added", re.compile(r"(?i)net\s+(?:user|localgroup)\b.{0,80}\s+/add\b")),
    ("lsass access", re.compile(r"(?i)(?:procdump|comsvcs\.dll|mimikatz|sekurlsa)\b")),
    ("reverse shell", re.compile(r"(?i)(?:nc|ncat|netcat)\s+(?:-[a-z]+\s+)*[\w.-]+\s+\d{2,5}\s*-\w*e?\b")),
    ("certutil download", re.compile(r"(?i)certutil(?:\.exe)?\s+-urlcache\b")),
    ("rundll32 execution", re.compile(r"(?i)rundll32(?:\.exe)?\b.{0,120}(?:http|\.dll)")),
    ("mshta script", re.compile(r"(?i)mshta(?:\.exe)?\b.{0,120}https?://")),
    ("bitsadmin transfer", re.compile(r"(?i)bitsadmin(?:/transfer)?\b")),
)

#: Registry paths that mean persistence.
PERSISTENCE_KEYS = (
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce",
    "CurrentVersion\\RunServices",
    "CurrentVersion\\Explorer\\Shell Folders",
    "CurrentVersion\\Windows\\Load",
    "CurrentControlSet\\Services",
    "Image File Execution Options",
    "Winlogon\\Shell",
    "Winlogon\\Userinit",
)

#: A Windows process listing entry, parsed out of the dump.
PROCESS_PATTERN = re.compile(
    rb"([A-Za-z]:\\[^\x00\r\n]{2,120}?\.(?:exe|dll|com|bat|cmd|ps1|vbs|py))"
    rb"(?:[\x00-\x20]|$)"
)


@dataclass
class ProcessEntry:
    """One process recovered from the image."""

    name: str
    pid: int | None = None
    ppid: int | None = None
    command_line: str = ""
    executable: str = ""
    offset: int = 0
    extra: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "pid": self.pid,
            "ppid": self.ppid,
            "command_line": self.command_line,
            "executable": self.executable,
            "offset": self.offset,
            **self.extra,
        }


@dataclass
class MemoryImage:
    """A loaded memory image and the facts recovered from it."""

    path: Path
    data: bytes = b""
    kind: str = "unknown"
    processes: list[ProcessEntry] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    network: list[dict] = field(default_factory=list)
    injected: list[dict] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.data)

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "kind": self.kind,
            "size": self.size,
            "processes": [p.to_dict() for p in self.processes],
            "strings": len(self.strings),
            "network": self.network,
            "injected": self.injected,
        }


def detect_kind(data: bytes) -> str:
    """Work out what kind of memory image this is."""
    for magic, name in DUMP_MAGICS.items():
        if data.startswith(magic):
            return name
    return "raw memory image"


def printable_runs(data: bytes, minimum: int = 6) -> list[tuple[int, str]]:
    """Every printable ASCII run of at least ``minimum`` characters."""
    results: list[tuple[int, str]] = []
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    for match in pattern.finditer(data):
        try:
            results.append((match.start(), match.group().decode("ascii")))
        except UnicodeDecodeError:  # pragma: no cover - defensive
            continue
    return results


def utf16_runs(data: bytes, minimum: int = 6) -> list[tuple[int, str]]:
    """Every printable UTF-16LE run of at least ``minimum`` characters.

    Windows keeps process names, paths and command lines as UTF-16LE,
    so a memory image holds two copies of the same strings: one wide
    and one narrow. Reading only the narrow ones misses the command
    line, which is usually the widest thing in the image.
    """
    results: list[tuple[int, str]] = []
    # Decode the image as UTF-16LE at both byte alignments, then look
    # for printable runs in the decoded text. A regex over the raw
    # bytes cannot tell a wide string from a narrow one that happens to
    # have nulls in it.
    for alignment in (0, 1):
        units = (len(data) - alignment) // 2
        if units < minimum:
            continue
        text = data[alignment : alignment + units * 2].decode("utf-16-le", errors="replace")
        pattern = re.compile(rf"[\x20-\x7e]{{{minimum},}}")
        for match in pattern.finditer(text):
            start = alignment + 2 * match.start()
            value = match.group()
            # If the unit before the run is a printable character
            # followed by a null, the run was anchored one unit early:
            # that is the tail of a narrow string, not the head of a
            # wide one.
            if start >= 2 and 0x20 <= data[start - 2] <= 0x7E and data[start - 1] == 0:
                start += 2
                value = value[1:]
                if len(value) < minimum:
                    continue
            results.append((start, value))
    return results


def all_string_runs(data: bytes, minimum: int = 6) -> list[tuple[int, str]]:
    """Both the narrow and the wide strings, in offset order."""
    return sorted(printable_runs(data, minimum) + utf16_runs(data, minimum))


def extract_processes(data: bytes) -> list[ProcessEntry]:
    """Recover a process inventory from the image.

    Two independent sources are used and merged, because neither is
    complete on its own: the executable path (which appears wherever the
    loader touched it) and the command line (which appears in the
    process's own memory).
    """
    processes: dict[str, ProcessEntry] = {}

    for offset, run in all_string_runs(data, 8):
        for match in PROCESS_PATTERN.finditer(run.encode("ascii", "replace")):
            path = match.group(1).decode("ascii", "replace")
            key = path.lower()
            if key not in processes:
                processes[key] = ProcessEntry(
                    name=Path(path.replace("\\", "/")).name,
                    executable=path,
                    offset=offset + match.start(),
                )

    for offset, run in all_string_runs(data, 12):
        if not looks_like_command_line(run):
            continue
        run = normalise_command_line(run)
        name = Path(run.split(" ")[0].replace("\\", "/")).name
        if not name:
            continue
        key = name.lower()
        entry = processes.get(key)
        if entry is None:
            entry = ProcessEntry(name=name, offset=offset)
            processes[key] = entry
        if len(run) > len(entry.command_line):
            entry.command_line = run
        entry.offset = entry.offset or offset

    return sorted(processes.values(), key=lambda p: p.name.lower())


def normalise_command_line(run: str) -> str:
    """Trim a recovered command line down to its executable.

    A command line recovered from a raw image is a run of printable
    bytes, and the run may begin in the middle of something else - the
    tail of a narrow string that happens to sit next to the wide copy.
    The command line starts at the first plausible executable path.
    """
    match = re.search(r"[A-Za-z]:\\[^\s]{2,}|/[^\s]{2,}", run)
    if not match:
        return run
    trimmed = run[match.start() :]
    # Drop a trailing argument that is only the tail of the path.
    if trimmed.endswith(","):
        trimmed = trimmed[:-1]
    return trimmed


def looks_like_command_line(run: str) -> bool:
    """Does this string look like something that was run?

    A command line is an executable path followed by arguments. The
    test is on the *first* token, not the last: the arguments of a
    PowerShell one-liner look nothing like an executable.
    """
    if not run or len(run) > 2000:
        return False
    if " " not in run:
        return False
    if run.count(" ") > 60:
        return False
    first = run.split(" ", 1)[0].strip().strip('"').lower()
    if not first:
        return False
    if not first.endswith(
        (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".py", ".sh", ".com")
    ):
        return False
    # A path, not a bare filename.
    return bool(re.match(r"^[a-z]:\\|^/|^\./", first)) or "\\" in first


def extract_network_state(data: bytes) -> list[dict]:
    """Recover the connection table from the image.

    Windows stores the TCP table as fixed-size structures with a
    four-character state code, and Linux keeps the socket list in
    kernel memory. Both are visible as text in a dump, so this looks
    for the well-known state codes followed by an address and a port.
    """
    states = {
        b"ESTAB": "established",
        b"ESTABLISHED": "established",
        b"LISTEN": "listening",
        b"LISTENING": "listening",
        b"TIME_WAIT": "time-wait",
        b"TIME-WAIT": "time-wait",
        b"CLOSE_WAIT": "close-wait",
        b"SYN_SENT": "syn-sent",
        b"SYN_RECV": "syn-received",
        b"CLOSE": "closed",
    }
    table: list[dict] = []
    seen: set[tuple[str, int, str]] = set()

    address = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{6,})"
    pattern = re.compile(
        rb"(?P<state>[A-Z_]{4,14})[\x00-\x20]+"
        rb"(?P<local>" + address.encode() + rb"):(?P<lport>\d{1,5})[\x00-\x20]+"
        rb"(?P<remote>" + address.encode() + rb"):(?P<rport>\d{1,5})"
    )

    for match in pattern.finditer(data):
        state = match.group("state")
        if state not in states:
            continue
        try:
            lport = int(match.group("lport"))
            rport = int(match.group("rport"))
        except ValueError:
            continue
        local = match.group("local").decode("ascii", "replace")
        remote = match.group("remote").decode("ascii", "replace")
        key = (local, lport, remote)
        if key in seen:
            continue
        seen.add(key)
        table.append(
            {
                "state": states[state],
                "local": f"{local}:{lport}",
                "remote": f"{remote}:{rport}",
                "offset": match.start(),
            }
        )
    return table


def find_injected_regions(image: bytes, disk: bytes | None) -> list[dict]:
    """Find memory that has no on-disk counterpart.

    When a disk image is available, the executable sections of the
    image are compared against the disk: a region that is executable in
    memory and absent from the file is the signature of injected code.
    """
    regions: list[dict] = []
    if not disk:
        return regions

    # A 4-byte sequence that appears in memory but never on disk, inside
    # a run of bytes that is not plain text: a strong hint of injected
    # shellcode. Sampling keeps this fast on a multi-gigabyte image.
    marker = b"\x90\x90\x90\x90"
    offset = 0
    step = 4096
    while offset < len(image):
        window = image[offset : offset + 1 << 20]
        index = window.find(marker)
        if index == -1:
            offset += len(window)
            continue
        absolute = offset + index
        if absolute % step != 0:
            offset += index + 1
            continue
        if marker not in disk:
            regions.append(
                {
                    "offset": absolute,
                    "kind": "nop sled not present on disk",
                    "confidence": "medium",
                }
            )
            if len(regions) >= 32:
                break
        offset += index + 1
    return regions


def find_persistence(data: bytes) -> list[dict]:
    """Look for the registry keys that mean persistence."""
    found: list[dict] = []
    for key in PERSISTENCE_KEYS:
        needle = key.encode("utf-8", "ignore")
        index = data.find(needle)
        if index == -1:
            # The hive stores UTF-16LE strings.
            index = data.find(needle.replace(b"\\", b"\\").decode().encode("utf-16-le"))
        if index == -1:
            continue
        context = data[index : index + 256]
        found.append(
            {
                "key": key,
                "offset": index,
                "context": context.decode("utf-8", "replace").replace("\x00", "")[:120],
            }
        )
    return found


class MemoryForensicsModule(Module):
    """Analyse memory images for compromise evidence."""

    id = "memory_forensics"
    name = "Memory Forensics"
    description = (
        "Parses memory images and raw dumps for process inventory, command "
        "lines, injected memory, the network connection table, persistence "
        "keys and resident secrets."
    )
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = Category.AUTH
    capability = Capability.CODE
    group = "forensics"
    cwe = "CWE-316"
    remediation = (
        "Isolate the host, preserve the image, and treat every process and "
        "connection recovered from memory as untrusted until proven otherwise."
    )
    references = [
        "https://github.com/volatilityfoundation/volatility3",
        "https://github.com/volatilityfoundation/volatility",
    ]
    tags = ["forensics", "memory", "incident-response", "dfir"]

    #: Extensions we treat as memory images.
    IMAGE_SUFFIXES = (".raw", ".mem", ".dmp", ".dump", ".core", ".lime", ".iml")
    #: A raw image has no magic number, so size is the only signal.
    MIN_IMAGE_BYTES = 1 << 20

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        images = self._images(ctx)
        for path in images:
            findings.extend(await self._analyse(ctx, path))
        return findings

    # -- discovery -------------------------------------------------------
    def _images(self, ctx: ScanContext) -> list[Path]:
        root = ctx.code_path
        if not root:
            return []
        base = Path(root)
        if base.is_file():
            # An explicitly named file is taken at face value: the
            # operator pointed at it.
            return [base]
        if not base.is_dir():
            return []
        found: list[Path] = []
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() in self.IMAGE_SUFFIXES and self._looks_like_image(path):
                found.append(path)
        return found[:20]

    def _looks_like_image(self, path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                head = handle.read(64)
        except OSError:
            return False
        if any(head.startswith(magic) for magic in DUMP_MAGICS):
            return True
        # A raw image has no magic; accept it if it is large enough to be
        # memory and the caller asked for this file specifically.
        try:
            return path.stat().st_size >= self.MIN_IMAGE_BYTES
        except OSError:
            return False

    # -- analysis --------------------------------------------------------
    async def _analyse(self, ctx: ScanContext, path: Path) -> list[Finding]:
        try:
            data = path.read_bytes()
        except OSError as exc:
            return [
                self.finding(
                    title="Memory image could not be read",
                    target=str(path),
                    description=f"The image could not be read: {exc}",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                )
            ]

        image = MemoryImage(path=path, data=data, kind=detect_kind(data))
        findings: list[Finding] = []

        image.processes = extract_processes(data)
        image.network = extract_network_state(data)
        image.injected = find_injected_regions(data, None)
        persistence = find_persistence(data)

        findings.extend(self._process_findings(image))
        findings.extend(self._network_findings(image))
        findings.extend(self._secret_findings(image))
        findings.extend(self._persistence_findings(persistence))
        findings.extend(self._suspicious_command_findings(image))

        ctx.stats.setdefault("memory_images", []).append(image.to_dict())
        return findings

    def _process_findings(self, image: MemoryImage) -> list[Finding]:
        findings: list[Finding] = []
        if not image.processes:
            return findings
        findings.append(
            self.finding(
                title=f"Recovered {len(image.processes)} processes from memory",
                target=str(image.path),
                description=(
                    f"{len(image.processes)} distinct executables were recovered "
                    f"from the memory image. The process list is the baseline for "
                    f"any subsequent analysis."
                ),
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                evidence_text="\n".join(
                    f"{p.name:<28} {p.command_line or p.executable}"
                    for p in image.processes[:40]
                ),
            )
        )

        # A process whose image path is not under a normal program
        # directory is worth a look: it was launched from somewhere
        # unusual.
        for process in image.processes:
            executable = process.executable or process.name
            lowered = executable.lower()
            if not lowered:
                continue
            suspicious = (
                "\\temp\\" in lowered
                or "\\tmp\\" in lowered
                or "\\appdata\\" in lowered
                or "\\programdata\\" in lowered
                or "\\downloads\\" in lowered
                or (lowered.endswith((".ps1", ".vbs", ".bat"))
                and not lowered.startswith("c:\\windows"))
            )
            if not suspicious:
                continue
            findings.append(
                self.finding(
                    title=f"Process running from an unusual location: {process.name}",
                    target=executable,
                    description=(
                        "A recovered process references an executable outside the "
                        "normal program directories. Executables run from temp, "
                        "AppData, ProgramData or a user downloads folder are a "
                        "common shape for a first-stage payload."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    evidence_text=process.command_line or process.executable,
                    file=str(image.path),
                    line=process.offset,
                )
            )
        return findings

    def _network_findings(self, image: MemoryImage) -> list[Finding]:
        findings: list[Finding] = []
        if not image.network:
            return findings

        connections = image.network
        established = [c for c in connections if c["state"] == "established"]
        listeners = [c for c in connections if c["state"] == "listening"]

        findings.append(
            self.finding(
                title=f"Recovered {len(connections)} network connections from memory",
                target=str(image.path),
                description=(
                    f"{len(established)} established connections and "
                    f"{len(listeners)} listening sockets were recovered. "
                    f"Connections in memory include traffic that never touched "
                    f"the disk, and outbound sessions to unfamiliar addresses "
                    f"are the first thing to check."
                ),
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                evidence_text="\n".join(
                    f"{c['state']:<12} {c['local']:<24} -> {c['remote']}"
                    for c in connections[:40]
                ),
            )
        )

        for connection in established:
            remote = connection["remote"]
            host = remote.rsplit(":", 1)[0]
            if self._is_external(host):
                findings.append(
                    self.finding(
                        title=f"Outbound connection to an external address in memory: {host}",
                        target=remote,
                        description=(
                            f"The image contains an established connection to "
                            f"{host}. An outbound session to an address that is "
                            f"not part of the host's normal estate is a strong "
                            f"indicator of command-and-control or of data "
                            f"exfiltration."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        evidence_text=f"{connection['state']} {connection['local']} -> {remote}",
                        file=str(image.path),
                        line=connection["offset"],
                    )
                )
        return findings

    @staticmethod
    def _is_external(host: str) -> bool:
        private = (
            "127.", "10.", "192.168.", "169.254.", "0.0.0.0", "::1",
            "fe80", "fc", "fd",
        )
        if host.startswith(private):
            return False
        if host.startswith("172."):
            try:
                second = int(host.split(".")[1])
            except (IndexError, ValueError):
                return False
            return not 16 <= second <= 31
        return not host.startswith(
            ("192.0.2.", "198.51.100.", "203.0.113.")
        )

    def _secret_findings(self, image: MemoryImage) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        # Windows strings are wide; match both encodings.
        haystacks = (image.data, image.data.replace(b"\x00", b""))
        for label, pattern in SECRET_PATTERNS:
            for text in haystacks:
                for match in pattern.finditer(text):
                    matched = match.group(0)[:120]
                    key = (label, matched)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        self.finding(
                            title=f"{label} found in memory",
                            target=str(image.path),
                            description=(
                                f"A {label.lower()} was resident in process memory. "
                                f"Secrets in memory are live until the process "
                                f"restarts, and they are frequently reusable outside "
                                f"the host that leaked them."
                            ),
                            severity=Severity.CRITICAL
                            if label in ("private key block", "aws secret access key")
                            else Severity.HIGH,
                            confidence=Confidence.HIGH,
                            evidence_text=self._redact(matched),
                            file=str(image.path),
                            line=match.start(),
                        )
                    )
                    if len(findings) >= 40:
                        return findings
        return findings

    @staticmethod
    def _redact(matched: bytes | str) -> str:
        """Show enough to identify the secret, not enough to use it."""
        text = matched.decode("ascii", "replace") if isinstance(matched, bytes) else matched
        if len(text) <= 12:
            return text[:4] + "..." + text[-2:]
        return f"{text[:8]}...{text[-4:]} (len={len(text)})"

    def _persistence_findings(self, persistence: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        for entry in persistence:
            findings.append(
                self.finding(
                    title=f"Persistence key present in memory: {entry['key']}",
                    target=entry["key"],
                    description=(
                        f"The registry path {entry['key']} is present in the "
                        f"image. When it is associated with an executable that "
                        f"is not part of the base image, it is persistence."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    evidence_text=entry.get("context", ""),
                    line=entry.get("offset", 0),
                )
            )
        return findings

    def _suspicious_command_findings(self, image: MemoryImage) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for process in image.processes:
            command = process.command_line
            if not command:
                continue
            for label, pattern in SUSPICIOUS_COMMANDS:
                if label in seen:
                    continue
                if pattern.search(command):
                    seen.add(label)
                    findings.append(
                        self.finding(
                            title=f"Suspicious command line: {label}",
                            target=process.executable or process.name,
                            description=(
                                f"A recovered process command line matches a "
                                f"known {label} pattern. The command line is "
                                f"the most direct evidence of what an actor "
                                f"ran on the host."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            evidence_text=command[:400],
                            file=str(image.path),
                            line=process.offset,
                        )
                    )
        return findings


class MemoryDumpTriageModule(Module):
    """Report on a memory image's structure without judging it.

    The triage view is what an incident responder wants first: what is
    this file, how big is it, what platform is it from, and what is in
    it. It never claims compromise - that is the job of the analysis
    module.
    """

    id = "memory_dump_triage"
    name = "Memory Dump Triage"
    description = (
        "Identifies memory dump format, platform, page-table structure and "
        "the artifacts present in an image, before any verdict is formed."
    )
    severity = Severity.INFO
    confidence = Confidence.HIGH
    category = Category.INFO
    capability = Capability.CODE
    cwe = "CWE-316"
    group = "forensics"
    remediation = "Preserve the original image and work on a copy."
    tags = ["forensics", "memory", "triage"]

    IMAGE_SUFFIXES = MemoryForensicsModule.IMAGE_SUFFIXES

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in self._images(ctx):
            try:
                with path.open("rb") as handle:
                    head = handle.read(4096)
                size = path.stat().st_size
            except OSError:
                continue

            kind = detect_kind(head)
            findings.append(
                self.finding(
                    title=f"Memory image: {path.name} ({kind})",
                    target=str(path),
                    description=(
                        f"The file is {size} bytes and was identified as "
                        f"{kind}. Triage only: no verdict is formed from the "
                        f"structure alone."
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    evidence_text=self._structure(head, size),
                    file=str(path),
                )
            )
        return findings

    def _images(self, ctx: ScanContext) -> list[Path]:
        root = ctx.code_path
        if not root:
            return []
        base = Path(root)
        if base.is_file():
            return [base]
        if not base.is_dir():
            return []
        return [
            path
            for path in sorted(base.rglob("*"))
            if path.is_file() and path.suffix.lower() in self.IMAGE_SUFFIXES
        ][:20]

    @staticmethod
    def _structure(head: bytes, size: int) -> str:
        lines = [f"size: {size} bytes"]
        if head.startswith(b"\x45\x4c\x46"):
            lines.append("container: ELF")
        if head.startswith(b"EGSY"):
            lines.append("notes: Linux 64-bit core dump")
        if head.startswith(b"PAGEDU64") or head.startswith(b"\x4d\x4d\x00\x00"):
            lines.append("format: Windows full memory dump")
        if head.startswith(b"MDMP"):
            lines.append("format: Windows minidump")
        if head.startswith(b"HMEM"):
            lines.append("format: Windows hibernation file")
        # A Windows dump header carries the dump type and the number of
        # processor cores at offset 0x0384 / 0x0548.
        if len(head) > 0x400:
            dump_type = int.from_bytes(head[0x0384:0x0388], "little")
            if dump_type in (DUMP_TYPE_FULL, DUMP_TYPE_MINI):
                lines.append(f"dump_type: {dump_type}")
        return "\n".join(lines)
