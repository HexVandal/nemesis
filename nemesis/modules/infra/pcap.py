"""Network traffic analysis.

A capture file is evidence. It contains what actually crossed the wire -
which a scanner that only ever sees one side of a connection cannot know.
This module parses a pcap or pcapng file directly, with no external
dependency, and extracts the things that matter:

- **Cleartext credentials** - HTTP Basic authentication, API keys in
  query strings, `Authorization` headers, form posts over plain HTTP.
- **DNS exfiltration** - a long, high-entropy label under a domain that
  is not the one the client was browsing to. This is the shape of data
  leaving over DNS, and it is easy to recognise once you have the shape.
- **Plaintext protocols carrying sensitive traffic** - SMTP, FTP, IMAP,
  POP3, Telnet.
- **Tunnelled traffic** - a lot of packets to one destination on an
  unusual port, or a single very large flow.
- **The odd port** - a service on a port nobody expects.

The parser reads the pcap file format directly: the global header, each
packet header, and then the link-layer, network and transport headers.
It understands Ethernet, raw IP, Linux SLL, IPv4 and IPv6, and TCP/UDP
ports.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: pcap magic numbers and their byte order / nanosecond flag.
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}

#: pcapng magic.
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

#: Link-layer types.
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LOOP = 108

#: Plaintext protocols and why they matter.
CLEARTEXT_PORTS = {
    21: ("FTP", "every credential and every file crosses the network in cleartext"),
    23: ("Telnet", "the session is cleartext, so the password is too"),
    25: ("SMTP", "mail content and authentication cross the network in cleartext"),
    110: ("POP3", "the mailbox password crosses the network in cleartext"),
    143: ("IMAP", "the mailbox password crosses the network in cleartext"),
    445: ("SMB", "SMB traffic is a well-known lateral-movement path"),
    1433: ("MSSQL", "the database protocol is cleartext unless TLS is negotiated"),
    3306: ("MySQL", "the database protocol is cleartext unless TLS is negotiated"),
    5432: ("PostgreSQL", "the database protocol is cleartext unless TLS is negotiated"),
    6379: ("Redis", "Redis has no authentication by default and speaks cleartext"),
}

#: A credential in a URL query string.
QUERY_CREDENTIAL = re.compile(
    r"(?i)(api[_-]?key|apikey|access[_-]?token|auth|token|password|passwd|pwd|secret|sig|signature)=([^&\s\"']{8,})"
)

#: A DNS label that carries data rather than a hostname.
DNS_LABEL = re.compile(r"^[A-Za-z0-9+/=_-]{20,}$")

#: A hostname that is not a normal name.
BINARY_LABEL = re.compile(r"^[A-Za-z0-9+/=]{16,}$")


@dataclass
class Packet:
    """One parsed packet."""

    timestamp: float
    src: str
    dst: str
    src_port: int
    dst_port: int
    protocol: int
    payload: bytes = b""
    raw_length: int = 0
    tcp_flags: int = 0
    labels: list[str] = field(default_factory=list)


class PcapParser:
    """A dependency-free pcap / pcapng reader."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.endian = "<"
        self.nanoseconds = False
        self.linktype = LINKTYPE_ETHERNET
        self.packets: list[Packet] = []
        self._parse()

    # -- top level -------------------------------------------------------
    def _parse(self) -> None:
        if not self.data:
            return
        if self.data[:4] in PCAP_MAGICS:
            self._parse_pcap()
        elif self.data[:4] == PCAPNG_MAGIC:
            self._parse_pcapng()

    def _parse_pcap(self) -> None:
        magic = self.data[:4]
        self.endian, self.nanoseconds = PCAP_MAGICS[magic]
        # Bytes 4..24 of the global header: version, timezone, sigfigs,
        # snaplen and the link-layer type. The magic is already consumed.
        header = self._unpack("HHIIII", self.data[4:24])
        (
            _vmaj,
            _vmin,
            _tz,
            _sigfigs,
            _snaplen,
            network,
        ) = header
        self.linktype = network & 0xFFFF
        offset = 24
        while offset + 16 <= len(self.data):
            ts_sec, ts_frac, incl_len, orig_len = self._unpack(
                "IIII", self.data[offset : offset + 16]
            )
            offset += 16
            if incl_len > 10_000_000 or offset + incl_len > len(self.data):
                break
            frame = self.data[offset : offset + incl_len]
            offset += incl_len
            timestamp = ts_sec + (ts_frac / 1_000_000_000 if self.nanoseconds else ts_frac / 1_000_000)
            packet = self._parse_frame(frame, timestamp, orig_len)
            if packet is not None:
                self.packets.append(packet)

    def _parse_pcapng(self) -> None:
        """Read the pcapng block structure."""
        offset = 0
        endian = "<"
        while offset + 12 <= len(self.data):
            block_type = self.data[offset : offset + 4]
            if block_type == PCAPNG_MAGIC:
                endian = "<"
                if self.data[offset + 8 : offset + 12] == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                total = struct.unpack_from(endian + "I", self.data, offset + 4)[0]
                offset += total if total >= 12 else 12
                continue
            total = struct.unpack_from(endian + "I", self.data, offset + 4)[0]
            if total < 12:
                break
            if block_type == b"\x01\x00\x00\x00":  # Interface Description Block
                linktype = struct.unpack_from(endian + "H", self.data, offset + 8)[0]
                self.linktype = linktype
            elif block_type == b"\x06\x00\x00\x00":  # Enhanced Packet Block
                ts_high, ts_low, incl_len, orig_len = struct.unpack_from(
                    endian + "IIII", self.data, offset + 8
                )
                frame = self.data[offset + 28 : offset + 28 + incl_len]
                timestamp = ((ts_high << 32) | ts_low) / 1_000_000
                packet = self._parse_frame(frame, timestamp, orig_len)
                if packet is not None:
                    self.packets.append(packet)
            offset += total

    def _unpack(self, fmt: str, data: bytes) -> tuple:
        return struct.unpack(self.endian + fmt, data)

    # -- frame decoding --------------------------------------------------
    def _parse_frame(self, frame: bytes, timestamp: float, orig_len: int) -> Packet | None:
        if not frame:
            return None
        offset = 0
        ethertype = 0x0800

        if self.linktype == LINKTYPE_ETHERNET:
            if len(frame) < 14:
                return None
            ethertype = struct.unpack_from("!H", frame, 12)[0]
            offset = 14
            # 802.1Q VLAN tag.
            while ethertype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
                ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
                offset += 4
        elif self.linktype == LINKTYPE_LINUX_SLL:
            if len(frame) < 16:
                return None
            ethertype = struct.unpack_from("!H", frame, 14)[0]
            offset = 16
        elif self.linktype in (LINKTYPE_RAW, LINKTYPE_NULL, LINKTYPE_LOOP):
            version = frame[0] >> 4
            ethertype = 0x0800 if version == 4 else 0x86DD
            offset = 0
        else:
            return None

        if ethertype == 0x0800:
            return self._parse_ipv4(frame, offset, timestamp, orig_len)
        if ethertype == 0x86DD:
            return self._parse_ipv6(frame, offset, timestamp, orig_len)
        return None

    def _parse_ipv4(
        self, frame: bytes, offset: int, timestamp: float, orig_len: int
    ) -> Packet | None:
        if len(frame) < offset + 20:
            return None
        ihl = (frame[offset] & 0x0F) * 4
        protocol = frame[offset + 9]
        src = ".".join(str(b) for b in frame[offset + 12 : offset + 16])
        dst = ".".join(str(b) for b in frame[offset + 16 : offset + 20])
        return self._parse_transport(
            frame, offset + ihl, protocol, src, dst, timestamp, orig_len
        )

    def _parse_ipv6(
        self, frame: bytes, offset: int, timestamp: float, orig_len: int
    ) -> Packet | None:
        if len(frame) < offset + 40:
            return None
        protocol = frame[offset + 6]
        src = self._ipv6_address(frame, offset + 8)
        dst = self._ipv6_address(frame, offset + 24)
        return self._parse_transport(
            frame, offset + 40, protocol, src, dst, timestamp, orig_len
        )

    @staticmethod
    def _ipv6_address(frame: bytes, offset: int) -> str:
        raw = frame[offset : offset + 16]
        if len(raw) < 16:
            return ""
        groups = [f"{raw[i] << 8 | raw[i + 1]:x}" for i in range(0, 16, 2)]
        return ":".join(groups).rstrip(":") or "::"

    def _parse_transport(
        self,
        frame: bytes,
        offset: int,
        protocol: int,
        src: str,
        dst: str,
        timestamp: float,
        orig_len: int,
    ) -> Packet | None:
        src_port = dst_port = 0
        flags = 0
        payload = b""
        if protocol == 6:  # TCP
            if len(frame) < offset + 20:
                return None
            src_port, dst_port = struct.unpack_from("!HH", frame, offset)
            data_offset = (frame[offset + 12] >> 4) * 4
            flags = frame[offset + 13]
            payload = frame[offset + data_offset :]
        elif protocol == 17:  # UDP
            if len(frame) < offset + 8:
                return None
            src_port, dst_port = struct.unpack_from("!HH", frame, offset)
            payload = frame[offset + 8 :]
        else:
            return None

        packet = Packet(
            timestamp=timestamp,
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            payload=payload,
            raw_length=orig_len,
            tcp_flags=flags,
        )
        return packet


class PcapAnalysisModule(Module):
    """Analyses a packet capture for cleartext credentials and exfiltration."""

    group = "host"
    id = "pcap_analysis"
    name = "Network Traffic Analysis"
    description = (
        "Parses a pcap or pcapng capture and reports cleartext "
        "credentials, API keys in URLs, DNS exfiltration, plaintext "
        "protocols carrying sensitive traffic and unusual flows."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.DISCLOSURE
    capability = Capability.CODE
    cwe = "CWE-319"
    owasp = "A02"
    tags = ["pcap", "network", "traffic", "forensics", "exfiltration", "dns"]
    remediation = (
        "Move every protocol that carries a credential onto TLS, take the "
        "API key out of the query string and into a header, and treat a "
        "DNS tunnel as an incident rather than as noise - a label that "
        "long and random is data, not a hostname."
    )
    references = [
        "https://www.tcpdump.org/manpages/pcap.3pcap.html",
        "https://cwe.mitre.org/data/definitions/319.html",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = Path(ctx.code_path)
        captures = self._captures(root)
        if not captures:
            return []

        findings: list[Finding] = []
        for capture in captures[:5]:
            try:
                data = capture.read_bytes()
            except OSError:
                continue
            parser = PcapParser(data)
            if not parser.packets:
                continue
            findings.extend(self._analyse(capture, parser))
        return findings

    def _captures(self, root: Path) -> list[Path]:
        skip = {".git", "node_modules", "vendor", "__pycache__", ".venv"}
        found: list[Path] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part in skip for part in path.parts):
                continue
            if path.suffix.lower() in (".pcap", ".pcapng", ".cap", ".dmp"):
                found.append(path)
        return found

    # -- analysis --------------------------------------------------------
    def _analyse(self, path: Path, parser: PcapParser) -> list[Finding]:
        findings: list[Finding] = []
        packets = parser.packets

        # 1. Cleartext credentials in HTTP traffic. One finding per
        #    flow: a conversation with twenty requests in it is one
        #    incident, not twenty.
        reported_flows: set[tuple[str, int, str, int]] = set()
        for packet in packets:
            if packet.dst_port not in (80, 8080, 8000, 3128, 8888):
                continue
            flow = (packet.src, packet.src_port, packet.dst, packet.dst_port)
            if flow in reported_flows:
                continue
            reported_flows.add(flow)
            text = packet.payload.decode("utf-8", errors="replace")
            for match in QUERY_CREDENTIAL.finditer(text):
                findings.append(
                    self._finding(
                        path,
                        Severity.HIGH,
                        f"Credential in a cleartext URL query string "
                        f"({packet.src}:{packet.src_port} -> "
                        f"{packet.dst}:{packet.dst_port})",
                        f"A query string carrying '{match.group(1)}' crossed "
                        f"the network in cleartext. Query strings end up in "
                        f"proxy logs, browser history, referrer headers and "
                        f"server access logs, so a credential in one is "
                        f"published in several places at once.",
                        f"parameter: {match.group(1)}\n"
                        f"value: {match.group(2)[:12]}...\n"
                        f"flow: {packet.src}:{packet.src_port} -> "
                        f"{packet.dst}:{packet.dst_port}",
                    )
                )
                break

            if "authorization: basic" in text.lower():
                import base64

                for line in text.splitlines():
                    if line.lower().startswith("authorization:"):
                        value = line.split(":", 1)[1].strip()
                        parts = value.split()
                        encoded = parts[-1] if parts else ""
                        if not parts or parts[0].lower() != "basic":
                            continue
                        try:
                            decoded = base64.b64decode(encoded, validate=True).decode(
                                "utf-8", errors="replace"
                            )
                        except Exception:
                            continue
                        findings.append(
                            self._finding(
                                path,
                                Severity.CRITICAL,
                                f"HTTP Basic authentication in cleartext "
                                f"({packet.src} -> {packet.dst})",
                                "The capture contains a Basic "
                                "Authorization header, which is base64 and "
                                "therefore not encryption. The credential is "
                                "readable by anything on the path.",
                                f"flow: {packet.src} -> {packet.dst}\n"
                                f"account: {decoded.split(':', 1)[0]}\n"
                                f"password: {'*' * min(8, len(decoded.split(':', 1)[-1]))}"
                                f" ({len(decoded.split(':', 1)[-1])} chars)",
                            )
                        )
                        break

        # 2. Plaintext protocols.
        for port, (name, why) in CLEARTEXT_PORTS.items():
            flows = [p for p in packets if p.dst_port == port or p.src_port == port]
            if not flows:
                continue
            findings.append(
                self._finding(
                    path,
                    Severity.MEDIUM,
                    f"{name} traffic in the capture ({len(flows)} packet(s))",
                    f"The capture contains {name} traffic, and {why}. If the "
                    f"traffic leaves the host, everything in it is readable "
                    f"on the way.",
                    f"port: {port}\npackets: {len(flows)}\n"
                    f"peers: {', '.join(sorted({f'{p.src}:{p.src_port}' for p in flows})[:5])}",
                )
            )

        # 3. DNS exfiltration - long random labels.
        dns_flows = [p for p in packets if p.dst_port == 53 or p.src_port == 53]
        for packet in dns_flows:
            labels = self._dns_labels(packet.payload)
            for label in labels:
                if not self._is_data_label(label):
                    continue
                if True:
                    findings.append(
                    self._finding(
                        path,
                        Severity.HIGH,
                        "DNS query carries a long encoded label",
                        f"A DNS query carried the label '{label[:40]}...', "
                        f"which is {len(label)} characters of "
                        f"base64-shaped data rather than a hostname. "
                        f"That is the shape of data leaving over DNS, and "
                        f"it is a common way to exfiltrate from a "
                        f"network where the other egress is closed.",
                        f"label: {label[:80]}\n"
                        f"length: {len(label)}\n"
                        f"flow: {packet.src} -> {packet.dst}",
                        )
                    )
                    break
            else:
                continue
            break

        # 4. An unusual destination port.
        ports: dict[int, int] = {}
        for packet in packets:
            ports[packet.dst_port] = ports.get(packet.dst_port, 0) + 1
        for port, count in sorted(ports.items()):
            if port in (0, 53, 80, 443, 123, 1900, 5353) or count < 20:
                continue
            if 1024 <= port <= 65535 and count > 100:
                findings.append(
                    self._finding(
                        path,
                        Severity.LOW,
                        f"{count} packets to a high destination port ({port})",
                        "Most of the capture's traffic went to one "
                        "unusual high port. That is the shape of a tunnel "
                        "or an exfiltration channel, and it is worth a "
                        "look even when the payload is encrypted.",
                        f"port: {port}\npackets: {count}",
                    )
                )
                break

        return findings

    @staticmethod
    def _is_data_label(label: str) -> bool:
        """Does this DNS label carry data rather than a hostname?

        A real hostname label is short, and it is a word. A thirty
        character run of letters with no hyphen in it is a base32 or
        hex payload that someone split into 63-character pieces.
        """
        if len(label) < 20 or not DNS_LABEL.match(label):
            return False
        if "-" in label:
            return False
        if len(label) >= 30:
            return True
        return not label.isalpha() and not label.isdigit()

    @staticmethod
    def _dns_labels(payload: bytes) -> list[str]:
        """Pull the labels out of a DNS query."""
        labels: list[str] = []
        offset = 12
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                break
            if length & 0xC0:  # compression pointer
                break
            offset += 1
            if offset + length > len(payload):
                break
            labels.append(payload[offset : offset + length].decode("ascii", errors="replace"))
            offset += length
        return labels

    def _finding(
        self, path: Path, severity: Severity, title: str, description: str, evidence: str
    ) -> Finding:
        return self.finding(
            title=title,
            target=str(path),
            description=description,
            severity=severity,
            confidence=Confidence.HIGH,
            evidence_text=f"Capture: {path}\n{evidence}",
            matched=title,
            file=str(path),
        )
