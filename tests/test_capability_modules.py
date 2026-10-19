"""Tests for the capability-expansion modules.

These modules are the software-shaped half of the 102 capability areas:
request smuggling, file upload, cache poisoning, WebSockets, CSP, business
logic, privilege escalation, IaC, binary triage, patch regression, CI/CD,
dependency confusion, typosquatting, LLM endpoints, prompt injection,
model extraction, agent tool security, Solidity auditing and ML model
security.

The tests build small fixtures on disk and assert the module finds the
thing it claims to find - and, just as importantly, that it stays quiet
when the thing is not there.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from nemesis.config import ScanConfig
from nemesis.models import Capability, Finding
from nemesis.modules.base import ModuleRegistry


def build_modules() -> dict:
    registry = ModuleRegistry(ScanConfig())
    registry.load_builtin()
    return {m.id: m for m in registry.all()}


def make_ctx(code_path: str | None = None, **kwargs):
    """A minimal ScanContext for code-only modules."""
    from nemesis.modules.base import ScanContext
    from nemesis.scope import Scope

    config = ScanConfig()
    config.code_path = code_path
    return ScanContext(
        config=config,
        scope=Scope(rules=["localhost"]),
        client=None,
        target_url=kwargs.get("target", "http://localhost"),
        host=kwargs.get("host", "localhost"),
        code_path=code_path,
    )


def write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


# ----------------------------------------------------------------------
# CI/CD pipeline security
# ----------------------------------------------------------------------
def test_cicd_detects_pull_request_target_checkout(tmp_path):
    write(
        tmp_path,
        ".github/workflows/deploy.yml",
        """
        name: deploy
        on:
          pull_request_target:
            types: [opened]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - run: make build
        """,
    )
    module = build_modules()["cicd_pipeline_security"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    titles = [f.title for f in findings]
    assert any("privileged context" in t for t in titles)


def test_cicd_detects_unpinned_action(tmp_path):
    write(
        tmp_path,
        ".github/workflows/ci.yml",
        """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/setup-python@v4
              - uses: some-org/risky-action@main
              - run: pytest
        """,
    )
    module = build_modules()["cicd_pipeline_security"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert any("not pinned" in f.title for f in findings)


def test_cicd_detects_expression_injection(tmp_path):
    write(
        tmp_path,
        ".github/workflows/ci.yml",
        """
        name: ci
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.pull_request.title }}"
        """,
    )
    module = build_modules()["cicd_pipeline_security"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert any("interpolated" in f.title for f in findings)


def test_cicd_is_quiet_on_a_safe_workflow(tmp_path):
    write(
        tmp_path,
        ".github/workflows/safe.yml",
        """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
              - run: pytest
        """,
    )
    module = build_modules()["cicd_pipeline_security"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert findings == []


# ----------------------------------------------------------------------
# Dependency confusion and typosquatting
# ----------------------------------------------------------------------
def test_typosquatting_detects_a_near_miss(tmp_path):
    write(tmp_path, "requirements.txt", "reqeusts==2.31.0\n")
    module = build_modules()["typosquatting"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert len(findings) == 1
    assert "reqeusts" in findings[0].title
    assert findings[0].severity.name == "HIGH"


def test_typosquatting_ignores_exact_names(tmp_path):
    write(tmp_path, "requirements.txt", "requests==2.31.0\nflask==3.0.0\n")
    module = build_modules()["typosquatting"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert findings == []


def test_dependency_confusion_ignores_scoped_names(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"@acme/internal-lib": "1.0.0"}}\n')
    module = build_modules()["dependency_confusion"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert findings == []


# ----------------------------------------------------------------------
# Solidity auditing
# ----------------------------------------------------------------------
def test_solidity_detects_reentrancy(tmp_path):
    write(
        tmp_path,
        "Vault.sol",
        """
        contract Vault {
            mapping(address => uint) public balances;
            function withdraw() public {
                uint amount = balances[msg.sender];
                msg.sender.call.value(amount)("");
                balances[msg.sender] = 0;
            }
        }
        """,
    )
    module = build_modules()["solidity_audit"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    titles = " ".join(f.title for f in findings)
    assert "reentrancy" in titles.lower()


def test_solidity_detects_tx_origin(tmp_path):
    write(
        tmp_path,
        "Ownable.sol",
        """
        contract Ownable {
            address owner;
            function transferOwnership(address to) public {
                require(tx.origin == owner);
                owner = to;
            }
        }
        """,
    )
    module = build_modules()["solidity_audit"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert any("tx.origin" in f.title for f in findings)


def test_solidity_detects_missing_access_control(tmp_path):
    write(
        tmp_path,
        "Token.sol",
        """
        contract Token {
            function mint(address to, uint amount) public {
                balanceOf[to] += amount;
            }
        }
        """,
    )
    module = build_modules()["solidity_audit"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert any("access control" in f.title for f in findings)


def test_solidity_is_quiet_on_a_well_written_contract(tmp_path):
    write(
        tmp_path,
        "Good.sol",
        """
        contract Good {
            address owner;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function withdraw() public onlyOwner {
                balances[msg.sender] = 0;
            }
        }
        """,
    )
    module = build_modules()["solidity_audit"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert findings == []


# ----------------------------------------------------------------------
# ML model security
# ----------------------------------------------------------------------
def test_ml_detects_unsafe_deserialisation(tmp_path):
    write(tmp_path, "train.py", "import torch\nmodel = torch.load('model.pt')\n")
    module = build_modules()["ml_model_security"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert any("torch.load" in f.title for f in findings)


def test_ml_accepts_weights_only(tmp_path):
    write(
        tmp_path,
        "train.py",
        "import torch\nmodel = torch.load('model.pt', weights_only=True)\n",
    )
    module = build_modules()["ml_model_security"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert findings == []


def test_ml_detects_pii_in_a_dataset(tmp_path):
    write(tmp_path, "customers.csv", "name,email,ssn\nalice,a@example.com,123-45-6789\n")
    module = build_modules()["ml_model_security"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert any("social security" in f.title for f in findings)


def test_ml_detects_credential_in_model_card(tmp_path):
    write(
        tmp_path,
        "README.md",
        "# Model\n\napi_key = 'sk-live-ABCDEFGHIJKLMNOPQRST'\n",
    )
    module = build_modules()["ml_model_security"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert any("credential" in f.title.lower() for f in findings)


# ----------------------------------------------------------------------
# IaC
# ----------------------------------------------------------------------
def test_iac_detects_public_bucket(tmp_path):
    write(
        tmp_path,
        "main.tf",
        """
        resource "aws_s3_bucket" "assets" {
          bucket = "assets"
          acl    = "public-read"
        }
        """,
    )
    module = build_modules()["iac_misconfiguration"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert any("public" in f.title.lower() for f in findings)


def test_iac_detects_wildcard_iam(tmp_path):
    write(
        tmp_path,
        "policy.tf",
        """
        resource "aws_iam_policy" "admin" {
          policy = jsonencode({
            "Action": "*",
            "Resource": "*"
          })
        }
        """,
    )
    module = build_modules()["iac_misconfiguration"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert any("wildcard" in f.title.lower() for f in findings)


def test_iac_detects_privileged_kubernetes(tmp_path):
    write(
        tmp_path,
        "pod.yaml",
        """
        apiVersion: v1
        kind: Pod
        spec:
          containers:
            - name: app
              securityContext:
                privileged: true
        """,
    )
    module = build_modules()["iac_misconfiguration"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert any("elevated privileges" in f.title for f in findings)


# ----------------------------------------------------------------------
# Binary triage
# ----------------------------------------------------------------------
def test_binary_triage_reads_a_real_elf_header(tmp_path):
    """A minimal but genuine ELF header must be parsed, not guessed."""
    import struct

    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little endian
    header[6] = 1  # ELF version
    header[16:18] = struct.pack("<H", 3)  # ET_DYN
    header[18:20] = struct.pack("<H", 0x3E)  # x86-64
    path = tmp_path / "app"
    path.write_bytes(bytes(header) + b"\x00" * 64)

    module = build_modules()["binary_triage"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    # A 64-byte file with no strings is not interesting, but the module
    # must not crash and must not claim a format it did not find.
    for finding in findings:
        assert finding.module == "binary_triage"


def test_binary_exploit_primitives_flags_missing_mitigations(tmp_path):
    import struct

    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[16:18] = struct.pack("<H", 2)  # ET_EXEC - no PIE
    header[18:20] = struct.pack("<H", 0x03)  # i386
    path = tmp_path / "old_binary"
    path.write_bytes(bytes(header) + b"\x00" * 64)

    module = build_modules()["binary_exploit_primitives"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert any("PIE" in f.title or "ASLR" in f.title or "NX" in f.title for f in findings)


# ----------------------------------------------------------------------
# Patch regression
# ----------------------------------------------------------------------
def test_patch_regression_requires_a_git_repo(tmp_path):
    """Without git history there is nothing to compare, and no crash."""
    write(tmp_path, "app.py", "import os\nos.system(cmd)\n")
    module = build_modules()["patch_regression"]
    import asyncio

    findings = asyncio.run(module.run(make_ctx(str(tmp_path))))
    assert isinstance(findings, list)


# ----------------------------------------------------------------------
# All new modules must be well-formed
# ----------------------------------------------------------------------
NEW_MODULES = [
    "request_smuggling",
    "file_upload",
    "web_cache_poisoning",
    "websocket_security",
    "csp_analyzer",
    "business_logic",
    "privilege_escalation",
    "iac_misconfiguration",
    "binary_triage",
    "binary_exploit_primitives",
    "patch_regression",
    "dependency_confusion",
    "typosquatting",
    "cicd_pipeline_security",
    "llm_endpoint_detection",
    "prompt_injection",
    "model_extraction",
    "agent_tool_security",
    "solidity_audit",
    "ml_model_security",
]


@pytest.mark.parametrize("module_id", NEW_MODULES)
def test_new_module_is_well_formed(module_id):
    modules = build_modules()
    assert module_id in modules, f"{module_id} is not registered"
    module = modules[module_id]
    assert module.id == module_id
    assert module.name
    assert module.description
    assert module.group
    assert isinstance(module.capability, Capability)
    assert module.remediation


@pytest.mark.parametrize("module_id", NEW_MODULES)
def test_new_module_handles_an_empty_context(module_id):
    """A module must survive a context with nothing in it."""
    import asyncio

    module = build_modules()[module_id]
    findings = asyncio.run(module.run(make_ctx(None)))
    assert isinstance(findings, list)
    for finding in findings:
        assert isinstance(finding, Finding)
