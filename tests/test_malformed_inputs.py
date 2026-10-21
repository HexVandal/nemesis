"""Malformed input must never crash the scan.

Every parser here touches bytes the tool did not write: packet captures,
dependency manifests, Content-Security-Policy headers, binaries. A parser that
raises on hostile input takes down the whole module - and a scanner that dies
on a malformed PCAP is a scanner that does not finish the job.

The contract is the same everywhere: **return, never raise**.
"""

from __future__ import annotations

import os
import random

import pytest

from nemesis.knowledge.csp import analyse, parse_policy
from nemesis.modules.deps.manifest import (
    _parse_package_json,
    _parse_pyproject,
    _parse_requirements,
)
from nemesis.modules.infra.pcap import PcapParser
from nemesis.subsystems.binary import identify, triage

#: Byte soup: empty, truncated magic, random noise, huge, and mutated headers.
GARBAGE = [
    b"",
    b"\x00",
    b"\xd4\xc3\xb2\xa1",                      # pcap magic, nothing else
    b"\x0a\x0d\x0d\x0a",                      # pcapng magic, nothing else
    b"\x7fELF",
    b"MZ",
    b"\xff" * 64,
    bytes(range(256)),
    os.urandom(4096),
    b"\x00" * 100_000,
]


class TestPcapParser:
    @pytest.mark.parametrize("payload", GARBAGE)
    def test_garbage_does_not_raise(self, payload):
        parser = PcapParser(payload)
        assert parser.packets is not None

    def test_http_like_bytes_do_not_raise(self):
        payload = b"\xd4\xc3\xb2\xa1" + b"GET / HTTP/1.1\r\nHost: x\r\n\r\n" * 20
        assert PcapParser(payload).packets is not None

    def test_a_truncated_record_is_ignored_not_fatal(self):
        payload = b"\xd4\xc3\xb2\xa1" + b"\x00" * 16 + b"\x01\x02\x03"
        assert PcapParser(payload).packets is not None


class TestManifestParsers:
    @pytest.mark.parametrize(
        "parser,payload",
        [
            (_parse_requirements, ""),
            (_parse_requirements, "not a requirement at all\n"),
            (_parse_requirements, "===\n>>>\n\x00\n"),
            (_parse_requirements, "requests==2.31.0\n" * 500),
            (_parse_pyproject, ""),
            (_parse_pyproject, "[project\n"),
            (_parse_pyproject, "[project]\ndependencies = 5\n"),
            (_parse_pyproject, "[project]\ndependencies = [1, 2, 3]\n"),
            (_parse_package_json, ""),
            (_parse_package_json, "{"),
            (_parse_package_json, '{"dependencies": "not-a-dict"}'),
            (_parse_package_json, '{"dependencies": {"a": {"b": "c"}}}'),
        ],
    )
    def test_bad_manifest_returns_a_list(self, parser, payload):
        result = parser(payload, "test")
        assert isinstance(result, list)

    def test_a_valid_requirement_is_still_parsed(self):
        deps = _parse_requirements("requests==2.31.0\nflask>=3.0\n", "requirements.txt")
        assert {d.name for d in deps} >= {"requests"}

    def test_unpinned_requirements_are_skipped_by_design(self):
        """Only ``==`` gives a version OSV can be asked about.

        This is a documented limitation, not a parser failure: a manifest of
        ``>=`` ranges yields no advisories. Pinned here so the behaviour is a
        decision rather than an accident.
        """
        deps = _parse_requirements("flask>=3.0\ndjango~=4.2\n", "requirements.txt")
        assert deps == []


class TestCspParser:
    @pytest.mark.parametrize(
        "header",
        [
            "",
            ";;;",
            "default-src",
            "default-src 'self'; script-src * 'unsafe-eval' 'unsafe-inline'",
            "a" * 10_000,
            "default-src 'nonce-\x00'; report-uri javascript:alert(1)",
            "script-src 'self'; script-src *",
        ],
    )
    def test_hostile_policies_do_not_raise(self, header):
        policy = parse_policy(header)
        assert isinstance(analyse(policy), list)

    def test_an_empty_policy_is_empty_not_fatal(self):
        """A missing CSP is reported by the headers module, not here.

        This module analyses a policy that exists; it must simply return
        nothing when there is nothing to analyse.
        """
        policy = parse_policy("")
        assert policy.directives == []
        assert analyse(policy) == []


class TestBinaryTriage:
    @pytest.mark.parametrize("payload", [b"", b"\x00", b"not a binary", os.urandom(1024)])
    def test_identify_never_raises(self, payload):
        assert isinstance(identify(payload), str)

    @pytest.mark.parametrize("payload", [b"", b"\x7fELF", b"MZ" + b"\x00" * 62, os.urandom(2048)])
    def test_triage_never_raises(self, tmp_path, payload):
        path = tmp_path / "sample.bin"
        path.write_bytes(payload)
        info = triage(path)
        assert info is not None


class TestRandomisedFuzz:
    """A cheap fuzz pass: random mutations of a plausible file header."""

    def test_pcap_mutations(self):
        rng = random.Random(1337)
        for _ in range(50):
            data = bytearray(b"\xd4\xc3\xb2\xa1" + rng.randbytes(rng.randrange(0, 512)))
            for _ in range(rng.randrange(1, 6)):
                if data:
                    data[rng.randrange(len(data))] = rng.randrange(256)
            assert PcapParser(bytes(data)).packets is not None

    def test_csp_mutations(self):
        rng = random.Random(4242)
        alphabet = "default-src script-src 'self' * ;:\x00\""
        for _ in range(50):
            header = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 200)))
            policy = parse_policy(header)
            assert isinstance(analyse(policy), list)
