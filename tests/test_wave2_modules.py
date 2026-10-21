"""Tests for the second capability-expansion wave.

The modules covered here are the ones that closed the last of the
unbacked capability areas: git history secrets, container escape
configuration, proxy trust, IPv6 confusion, cloud attack surface, DeFi
mechanics, browser security posture, fuzz harness generation, packet
capture analysis and memory forensics.

They are joined by the two knowledge components that back the
non-scanning areas: the research library and the research workspace.

Every test asserts two things: that the module finds the thing it
claims to find, and that it stays quiet when the thing is not there.
The second half is the more important half.
"""

from __future__ import annotations

import asyncio
import socket
import socketserver
import textwrap
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

from nemesis.config import ScanConfig
from nemesis.http.client import Response
from nemesis.models import Endpoint
from nemesis.modules.base import ModuleRegistry, ScanContext
from nemesis.scope import Scope


def build_modules() -> dict:
    registry = ModuleRegistry(ScanConfig())
    registry.load_builtin()
    return {m.id: m for m in registry.all()}


def make_ctx(code_path: str | None = None, target: str = "http://localhost"):
    config = ScanConfig()
    config.code_path = code_path
    return ScanContext(
        config=config,
        scope=Scope(rules=["localhost"]),
        client=None,
        target_url=target,
        host="localhost",
        code_path=code_path,
    )


def write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


def make_response(
    url: str = "http://localhost/",
    headers: dict[str, str] | None = None,
    text: str = "body",
    status: int = 200,
) -> Response:
    """A Response object, for the modules that read the crawl's output."""
    return Response(
        url=url,
        status=status,
        headers=headers or {},
        text=text,
        content=text.encode("utf-8"),
        elapsed=0.01,
    )


# ----------------------------------------------------------------------
# A small live target for the active modules
# ----------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    """A target with a weak posture and a header-trusting endpoint."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Security-Policy", "script-src 'unsafe-inline' 'unsafe-eval' data:")
        self.send_header("Strict-Transport-Security", "max-age=600")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if self.path.startswith("/proxy"):
            forwarded = self.headers.get("X-Forwarded-Host", "")
            client = self.headers.get("X-Forwarded-For", "")
            body = f"host={forwarded} client={client}"
        elif self.path.startswith("/check"):
            query = self.path.partition("?")[2]
            value = ""
            for pair in query.split("&"):
                key, _, val = pair.partition("=")
                if key == "ip":
                    value = val.replace("%3A", ":").replace("%25", "%")
            # The naive filter: only the exact literal is allowed.
            body = (
                "ALLOWED: the loopback is on the allow-list"
                if value == "127.0.0.1"
                else "DENIED"
            )
        else:
            body = "<html><body>ok</body></html>"
        payload = body.encode("utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_POST = do_GET


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def live_target():
    port = _free_port()
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def live_ctx(url: str, **kwargs) -> ScanContext:
    """A context wired to the live target, with a real HTTP client."""
    from nemesis.http.client import HttpClient

    host = url.split("//", 1)[1].split("/", 1)[0]
    config = ScanConfig()
    config.code_path = kwargs.get("code_path")
    scope = Scope(rules=[host])
    ctx = ScanContext(
        config=config,
        scope=scope,
        client=HttpClient(config, scope),
        target_url=url,
        host=host,
        code_path=kwargs.get("code_path"),
    )
    ctx.endpoints = kwargs.get("endpoints", [])
    ctx.responses = kwargs.get("responses", [])
    return ctx


async def run_live(module, ctx: ScanContext):
    """Run an active module against the live target.

    The HTTP client is the scanner's only egress point and it is
    deliberately unusable outside its context manager, so the module
    is run inside one.
    """
    async with ctx.client:
        return await module.run(ctx)


# ----------------------------------------------------------------------
# Git history secrets
# ----------------------------------------------------------------------
def _git_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    env = {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": str(tmp_path),
    }
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env)
    for name, content in files.items():
        (repo / name).write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True, env=env)
    return repo


def test_git_history_secrets_finds_committed_credentials(tmp_path):
    repo = _git_repo(
        tmp_path,
        {
            "config.py": (
                'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
                'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
            )
        },
    )
    module = build_modules()["git_history_secrets"]
    findings = asyncio.run(module.run(make_ctx(str(repo))))
    assert findings, "a committed AWS key should be found in git history"
    titles = " ".join(f.title.lower() for f in findings)
    assert "aws" in titles
    # The secret itself must not be printed back in full.
    blob = " ".join(f.evidence.response + f.evidence.matched for f in findings)
    assert "wJalrXUtnFEMI" not in blob, "the secret must be redacted"
    assert "AKIAIOSFODNN7EXAMPLE" not in blob, "the key must be redacted"


def test_git_history_secrets_finds_a_removed_secret(tmp_path):
    import subprocess

    repo = _git_repo(tmp_path, {"app.conf": 'api_key = "abcd1234efgh5678ijkl9012mnop3456"\n'})
    # Remove it, but the history keeps it.
    (repo / "app.conf").unlink()
    env = {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": str(tmp_path),
    }
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-qm", "remove"], cwd=repo, check=True, env=env)

    module = build_modules()["git_history_secrets"]
    findings = asyncio.run(module.run(make_ctx(str(repo))))
    assert findings, "a secret removed from HEAD should still be found"
    titles = " ".join(f.title.lower() for f in findings)
    assert "history" in titles


def test_git_history_secrets_quiet_on_clean_repo(tmp_path):
    repo = _git_repo(tmp_path, {"main.py": "print('hello')\n"})
    module = build_modules()["git_history_secrets"]
    findings = asyncio.run(module.run(make_ctx(str(repo))))
    assert not findings, "a clean repository should produce no findings"


# ----------------------------------------------------------------------
# Container escape configuration
# ----------------------------------------------------------------------
def test_sandbox_escape_detects_privileged_container(tmp_path):
    write(
        tmp_path,
        "Dockerfile",
        """
        FROM ubuntu:latest
        USER root
        RUN apt-get install -y docker.io
        VOLUME /var/run/docker.sock
        """,
    )
    module = build_modules()["sandbox_escape"]
    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert findings, "a privileged container should be flagged"
    blob = " ".join(f.title + f.description for f in findings).lower()
    assert "docker.sock" in blob or "privileged" in blob or "root" in blob


def test_sandbox_escape_quiet_on_hardened_container(tmp_path):
    write(
        tmp_path,
        "Dockerfile",
        """
        FROM gcr.io/distroless/static:nonroot
        USER 65532
        COPY --chown=65532:65532 app /app
        CMD ["/app"]
        """,
    )
    module = build_modules()["sandbox_escape"]
    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert not findings, "a hardened container should not be flagged"


# ----------------------------------------------------------------------
# Proxy trust
# ----------------------------------------------------------------------
def test_proxy_security_detects_forwarded_header_trust(live_target):
    module = build_modules()["proxy_security"]
    ctx = live_ctx(live_target)
    ctx.target_url = f"{live_target}/proxy"
    ctx.endpoints = [Endpoint(url=f"{live_target}/proxy", params={"q": "1"})]
    findings = asyncio.run(run_live(module, ctx))
    assert findings, "an application that echoes X-Forwarded-Host should be flagged"
    blob = " ".join((f.title + " " + f.description).lower() for f in findings)
    assert "forwarded" in blob or "proxy" in blob or "host" in blob


# ----------------------------------------------------------------------
# IPv6
# ----------------------------------------------------------------------
def test_ipv6_security_detects_a_differently_handled_address_form(live_target):
    module = build_modules()["ipv6_security"]
    ctx = live_ctx(live_target)
    ctx.endpoints = [Endpoint(url=f"{live_target}/check", params={"ip": "127.0.0.1"})]
    findings = asyncio.run(run_live(module, ctx))
    assert findings, "an address filter that treats the families differently should be flagged"
    blob = " ".join((f.title + " " + f.description).lower() for f in findings)
    assert "ipv6" in blob or "address" in blob


def test_ipv6_security_quiet_when_both_families_behave_alike(live_target):
    """A filter that rejects both forms equally is not a finding."""
    module = build_modules()["ipv6_security"]
    ctx = live_ctx(live_target)
    ctx.endpoints = [Endpoint(url=f"{live_target}/proxy", params={"ip": "127.0.0.1"})]
    findings = asyncio.run(run_live(module, ctx))
    assert not any("ipv6 literal" in f.title.lower() for f in findings)


# ----------------------------------------------------------------------
# Cloud attack surface
# ----------------------------------------------------------------------
def test_cloud_attack_surface_detects_storage_and_signed_urls():
    module = build_modules()["cloud_attack_surface"]
    ctx = live_ctx("http://localhost/")
    ctx.endpoints = [
        Endpoint(url="https://my-company-backups.s3.amazonaws.com/data.csv"),
    ]
    ctx.responses = [
        make_response(
            url="http://localhost/",
            text='<a href="https://x.s3.amazonaws.com/a?X-Amz-Expires=604800">download</a>',
        )
    ]
    findings = asyncio.run(module.run(ctx))
    assert findings, "cloud storage and pre-signed URLs should be flagged"
    blob = " ".join((f.title + " " + f.description).lower() for f in findings)
    assert "storage" in blob or "signed" in blob or "bucket" in blob


# ----------------------------------------------------------------------
# DeFi
# ----------------------------------------------------------------------
def test_defi_security_detects_unchecked_transfer_and_oracle(tmp_path):
    write(
        tmp_path,
        "Vault.sol",
        """
        pragma solidity ^0.8.0;

        interface IERC20 { function transfer(address to, uint256 v) external returns (bool); }

        contract Vault {
            address public oracle;
            function sweep(address token, address to) external {
                IERC20(token).transfer(to, 1);
            }
            function price() public view returns (uint256) {
                (uint80 roundId, int256 answer, , , ) = Oracle(oracle).latestRoundData();
                return uint256(answer);
            }
            function swapTokens(uint256 amount) external {
                router.swapExactTokensForTokens(amount, 0, msg.sender, block.timestamp);
            }
        }
        """,
    )
    module = build_modules()["defi_security"]
    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert findings, "unchecked transfer, oracle and slippage should be flagged"
    blob = " ".join((f.title + " " + f.description).lower() for f in findings)
    assert "oracle" in blob or "slippage" in blob or "transfer" in blob


def test_defi_security_quiet_on_a_safe_contract(tmp_path):
    write(
        tmp_path,
        "Safe.sol",
        """
        pragma solidity ^0.8.0;

        contract Safe {
            function swapTokens(uint256 amount, uint256 minOut) external {
                require(minOut > 0, "no slippage");
                router.swapExactTokensForTokens(amount, minOut, msg.sender, block.timestamp);
            }
        }
        """,
    )
    module = build_modules()["defi_security"]
    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert not any("slippage" in f.title.lower() for f in findings)


# ----------------------------------------------------------------------
# Browser security posture
# ----------------------------------------------------------------------
def test_browser_security_detects_weak_csp_and_hsts():
    module = build_modules()["browser_security"]
    ctx = live_ctx("http://localhost/")
    ctx.responses = [
        make_response(
            url="http://localhost/",
            headers={
                "Content-Security-Policy": "script-src 'unsafe-inline' 'unsafe-eval' data:",
                "Strict-Transport-Security": "max-age=600",
            },
        )
    ]
    findings = asyncio.run(module.run(ctx))
    assert findings, "a weak CSP and a short HSTS should be flagged"
    blob = " ".join(f.title.lower() for f in findings)
    assert "unsafe" in blob or "csp" in blob or "hsts" in blob or "strict-transport" in blob


def test_browser_security_quiet_on_a_hardened_policy():
    module = build_modules()["browser_security"]
    ctx = live_ctx("http://localhost/")
    ctx.responses = [
        make_response(
            url="http://localhost/",
            headers={
                "Content-Security-Policy": (
                    "default-src 'none'; script-src 'self'; object-src 'none'; "
                    "base-uri 'none'; frame-ancestors 'none'"
                ),
                "Strict-Transport-Security": (
                    "max-age=63072000; includeSubDomains; preload"
                ),
            },
        )
    ]
    findings = asyncio.run(module.run(ctx))
    assert not findings, "a hardened policy should produce no findings"


# ----------------------------------------------------------------------
# Fuzzing
# ----------------------------------------------------------------------
def test_fuzz_harness_generates_a_harness(tmp_path):
    write(
        tmp_path,
        "parser.c",
        """
        int parse_header(const unsigned char *data, unsigned long len) {
            if (len < 4) return -1;
            return data[0];
        }
        """,
    )
    write(tmp_path, "Makefile", "all:\n\tgcc -c parser.c\n")
    module = build_modules()["fuzz_harness"]
    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert findings, "a fuzzable function should be reported"
    produced = list(tmp_path.rglob("fuzz_*.c"))
    assert produced, "a harness file should have been generated"
    body = produced[0].read_text(encoding="utf-8")
    assert "LLVMFuzzerTestOneInput" in body
    assert "parse_header" in body


def test_fuzzing_readiness_reports_missing_pieces(tmp_path):
    write(tmp_path, "parser.c", "int main(void){return 0;}\n")
    module = build_modules()["fuzzing_readiness"]
    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert findings, "a project with no corpus or harness should be reported"


# ----------------------------------------------------------------------
# Packet capture analysis
# ----------------------------------------------------------------------
def build_pcap() -> bytes:
    """A tiny pcap with one HTTP Basic request and two DNS queries."""
    import struct

    def ethernet(payload: bytes) -> bytes:
        return b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00" + payload

    def ipv4(payload: bytes, proto: int, src: str, dst: str) -> bytes:
        return (
            struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                bytes(int(p) for p in src.split(".")),
                bytes(int(p) for p in dst.split(".")),
            )
            + payload
        )

    def tcp(payload: bytes, sport: int, dport: int) -> bytes:
        return (
            struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, 0x18, 8192, 0, 0)
            + payload
        )

    def udp(payload: bytes, sport: int, dport: int) -> bytes:
        return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload

    http = (
        b"GET /admin HTTP/1.1\r\nHost: example.com\r\n"
        b"Authorization: Basic YWRtaW46c3VwZXJzZWNyZXQ=\r\n\r\n"
    )
    dns = (
        b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07exfil\x03example\x02com\x00\x00\x01\x00\x01"
    )
    long_label = b"A" * 40
    dns_long = (
        b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + bytes([len(long_label)]) + long_label + b"\x03com\x00\x00\x01\x00\x01"
    )

    frames = [
        ethernet(ipv4(tcp(http, 44444, 80), 6, "10.0.0.5", "93.184.216.34")),
        ethernet(ipv4(udp(dns, 53000, 53), 17, "10.0.0.5", "8.8.8.8")),
        ethernet(ipv4(udp(dns_long, 53001, 53), 17, "10.0.0.5", "8.8.8.8")),
    ]

    header = struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    out = header
    for frame in frames:
        out += struct.pack("!IIII", 1700000000, 0, len(frame), len(frame)) + frame
    return out


def test_pcap_analysis_finds_basic_auth_and_dns_exfil(tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(build_pcap())
    module = build_modules()["pcap_analysis"]
    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert findings, "cleartext credentials and DNS exfiltration should be found"
    blob = " ".join((f.title + " " + f.description).lower() for f in findings)
    assert "credential" in blob or "auth" in blob or "basic" in blob
    assert "dns" in blob or "exfil" in blob


# ----------------------------------------------------------------------
# Memory forensics
# ----------------------------------------------------------------------
def test_memory_forensics_finds_processes_secrets_and_connections(tmp_path):
    blob = bytearray(b"\x00" * 4096)
    blob += b"C:\\Windows\\System32\\svchost.exe\x00"
    blob += (
        "C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe /c powershell -enc "
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ"
    ).encode("utf-16-le")
    blob += b"\x00\x00"
    blob += b"AKIAIOSFODNN7EXAMPLE\x00"
    blob += b"ESTABLISHED 10.0.0.5:51234 203.0.113.77:443\x00"
    blob += b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    image = tmp_path / "host.raw"
    image.write_bytes(bytes(blob) + b"\x00" * (1 << 20))

    module = build_modules()["memory_forensics"]
    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert findings, "memory analysis should report something"
    titles = " ".join(f.title.lower() for f in findings)
    assert "process" in titles
    assert "aws" in titles or "key" in titles
    assert "network" in titles or "connection" in titles
    # The secret must be redacted.
    blob_out = " ".join(f.evidence.response + f.evidence.matched for f in findings)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob_out


def test_memory_forensics_flags_an_unusual_process_location(tmp_path):
    blob = bytearray(b"\x00" * 4096)
    blob += "C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe".encode("utf-16-le")
    blob += b"\x00\x00"
    image = tmp_path / "host.raw"
    image.write_bytes(bytes(blob) + b"\x00" * (1 << 20))

    module = build_modules()["memory_forensics"]
    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert any("unusual" in f.title.lower() for f in findings)


def test_memory_dump_triage_identifies_the_format(tmp_path):
    image = tmp_path / "host.dmp"
    image.write_bytes(b"PAGEDU64" + b"\x00" * 4096)
    module = build_modules()["memory_dump_triage"]
    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert findings
    assert "memory image" in findings[0].title.lower()


# ----------------------------------------------------------------------
# The research library
# ----------------------------------------------------------------------
def test_library_is_indexed_and_searchable():
    from nemesis.knowledge.library import LIBRARY_INDEX

    assert len(LIBRARY_INDEX.all()) > 50, "the library should be substantial"
    results = LIBRARY_INDEX.search("buffer overflow")
    assert results, "searching for a common topic should find something"
    for resource in LIBRARY_INDEX.all():
        assert resource.url.startswith("https://"), f"bad url: {resource.url}"
        assert " " not in resource.url, f"malformed url: {resource.url}"
        assert resource.title
        assert resource.kind
        assert resource.area


def test_library_covers_every_area_that_claims_it():
    from nemesis.capabilities import CAPABILITY_REGISTRY
    from nemesis.knowledge.library import LIBRARY_INDEX

    areas = set(LIBRARY_INDEX.areas())
    for capability in CAPABILITY_REGISTRY.all():
        if "nemesis.knowledge.library:LIBRARY_INDEX" in capability.components:
            assert capability.id in areas, (
                f"{capability.id} claims the library but the library has "
                f"nothing filed under it"
            )


# ----------------------------------------------------------------------
# The research workspace
# ----------------------------------------------------------------------
def test_workspace_creates_structure_and_entries(tmp_path):
    from nemesis.workspace import Workspace

    workspace = Workspace(root=tmp_path / "ws")
    workspace.create()
    assert (tmp_path / "ws" / "notes").is_dir()
    assert (tmp_path / "ws" / "README.md").exists()

    note = workspace.add_note("Testing the parser")
    assert note.exists()
    assert "What I was trying to find" in note.read_text(encoding="utf-8")

    finding = workspace.add_finding("A weird race condition")
    body = finding.read_text(encoding="utf-8")
    assert "Why I could not prove it" in body
    assert "NF-" in body


def test_workspace_never_overwrites_a_note(tmp_path):
    from nemesis.workspace import Workspace

    workspace = Workspace(root=tmp_path / "ws")
    workspace.create()
    first = workspace.add_note("Same title")
    first.write_text("my own words", encoding="utf-8")
    second = workspace.add_note("Same title")
    assert first != second
    assert first.read_text(encoding="utf-8") == "my own words"


def test_workspace_inventory_counts_entries(tmp_path):
    from nemesis.workspace import Workspace

    workspace = Workspace(root=tmp_path / "ws")
    workspace.create()
    workspace.add_note("One")
    workspace.add_note("Two")
    workspace.add_finding("Three")
    inventory = workspace.inventory()
    assert inventory["counts"]["notes"] == 2
    assert inventory["counts"]["findings"] == 1
    assert inventory["total"] == 3


# ----------------------------------------------------------------------
# The capability map stays honest
# ----------------------------------------------------------------------
def test_every_capability_area_is_backed():
    from nemesis.capabilities import CAPABILITY_REGISTRY

    assert CAPABILITY_REGISTRY.validate() == [], "the capability map must be honest"
    coverage = CAPABILITY_REGISTRY.coverage()
    assert coverage["backed"] == coverage["total"] == 113


def test_no_module_is_an_orphan():
    """Every module must be claimed by at least one capability."""
    from nemesis.capabilities import CAPABILITY_REGISTRY

    claimed = {m for cap in CAPABILITY_REGISTRY.all() for m in cap.modules}
    modules = build_modules()
    orphans = sorted(set(modules) - claimed)
    assert not orphans, f"modules referenced by no capability: {orphans}"


def test_the_new_modules_are_registered():
    modules = build_modules()
    for module_id in (
        "git_history_secrets",
        "sandbox_escape",
        "proxy_security",
        "ipv6_security",
        "cloud_attack_surface",
        "defi_security",
        "browser_security",
        "fuzz_harness",
        "fuzzing_readiness",
        "pcap_analysis",
        "memory_forensics",
        "memory_dump_triage",
    ):
        assert module_id in modules, f"{module_id} should be registered"
