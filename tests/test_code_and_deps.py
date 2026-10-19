"""Tests for the source-code and dependency analysis modules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nemesis.config import ScanConfig
from nemesis.modules.base import ScanContext
from nemesis.modules.code.secrets import SecretsModule
from nemesis.modules.deps.manifest import collect_dependencies


@pytest.fixture()
def code_tree(tmp_path: Path) -> Path:
    (tmp_path / "config.py").write_text(
        "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
        "GITHUB_TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "import subprocess\n"
        "def run(cmd):\n"
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixtures.py").write_text(
        "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture()
def ctx(code_tree: Path) -> ScanContext:
    return ScanContext(
        config=ScanConfig(),
        scope=None,  # type: ignore[arg-type]
        client=None,  # type: ignore[arg-type]
        target_url="http://target/",
        host="target",
        code_path=str(code_tree),
    )


class TestSecrets:
    @pytest.mark.asyncio
    async def test_detects_aws_key(self, ctx):
        findings = await SecretsModule(ScanConfig()).run(ctx)
        assert any("AWS" in f.title for f in findings)
        assert any(f.severity.name == "CRITICAL" for f in findings)

    @pytest.mark.asyncio
    async def test_skips_test_fixtures(self, ctx):
        findings = await SecretsModule(ScanConfig()).run(ctx)
        for finding in findings:
            assert "tests/" not in (finding.file or "")

    @pytest.mark.asyncio
    async def test_no_code_path_is_noop(self):
        empty = ScanContext(
            config=ScanConfig(), scope=None, client=None,  # type: ignore[arg-type]
            target_url="http://t/", host="t", code_path=None,
        )
        assert await SecretsModule(ScanConfig()).run(empty) == []


class TestManifests:
    def test_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "requests==2.31.0\nflask>=3.0.0\ndjango==5.0.1\n# comment\n"
        )
        deps = collect_dependencies(tmp_path)
        names = {d.name: d.version for d in deps}
        assert names.get("requests") == "2.31.0"
        assert names.get("django") == "5.0.1"
        # Ranges are not exact, so they are skipped.
        assert "flask" not in names

    def test_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "29.0.0"}})
        )
        deps = collect_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["express"].version == "4.18.0"
        assert by_name["express"].ecosystem == "npm"
        assert by_name["jest"].dev is True

    def test_cargo_toml(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "x"\n\n[dependencies]\nserde = "1.0.100"\n'
        )
        deps = collect_dependencies(tmp_path)
        assert any(d.name == "serde" and d.version == "1.0.100" for d in deps)

    def test_go_mod(self, tmp_path):
        (tmp_path / "go.mod").write_text(
            "module example.com/x\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n"
        )
        deps = collect_dependencies(tmp_path)
        assert any(d.name == "github.com/gin-gonic/gin" and d.version == "v1.9.1" for d in deps)

    def test_pom_xml(self, tmp_path):
        (tmp_path / "pom.xml").write_text(
            "<project><dependencies><dependency>"
            "<groupId>org.apache.logging.log4j</groupId>"
            "<artifactId>log4j-core</artifactId>"
            "<version>2.14.1</version>"
            "</dependency></dependencies></project>"
        )
        deps = collect_dependencies(tmp_path)
        assert any(d.name == "org.apache.logging.log4j:log4j-core" for d in deps)

    def test_node_modules_is_skipped(self, tmp_path):
        nm = tmp_path / "node_modules" / "left-pad"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({"name": "left-pad", "version": "1.0.0"}))
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "1.0.0"}}))
        deps = collect_dependencies(tmp_path)
        assert len([d for d in deps if d.name == "left-pad"]) == 1
