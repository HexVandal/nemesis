"""Tests for the plugin system and configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from nemesis.config import PROFILES, ScanConfig, resolve_profile
from nemesis.modules.base import ModuleRegistry

PLUGIN_SOURCE = '''
from nemesis.models import Capability, Category, Confidence, Finding, Severity
from nemesis.modules.base import Module, ScanContext


class TempPlugin(Module):
    id = "temp_plugin"
    name = "Temporary Plugin"
    description = "A plugin used by the test suite."
    severity = Severity.INFO
    confidence = Confidence.LOW
    category = Category.INFO
    capability = Capability.PASSIVE
    group = "headers"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        return []
'''


class TestPluginLoading:
    def test_plugin_in_a_user_directory_is_registered(self, tmp_path):
        (tmp_path / "temp_plugin.py").write_text(PLUGIN_SOURCE, encoding="utf-8")
        registry = ModuleRegistry(ScanConfig())
        registry.load_builtin()
        registry.load_directory(tmp_path)
        assert any(m.id == "temp_plugin" for m in registry.all())

    def test_the_bundled_example_is_not_loaded_into_every_scan(self):
        # The example used to sit in `plugins/` under a normal name, so every
        # scan quietly ran a 141st module that no capability listed. It is a
        # template now: it must stay out of the registry until copied.
        registry = ModuleRegistry(ScanConfig())
        registry.load_builtin()
        registry.load_directory(Path("nemesis/plugins"))
        assert not any(m.id == "verbose_server_banner" for m in registry.all())
        assert (Path("nemesis/plugins") / "_example_plugin.py").exists()

    def test_files_starting_with_underscore_are_ignored(self, tmp_path):
        (tmp_path / "_private.py").write_text(PLUGIN_SOURCE, encoding="utf-8")
        registry = ModuleRegistry(ScanConfig())
        registry.load_builtin()
        registry.load_directory(tmp_path)
        assert not any(m.id == "temp_plugin" for m in registry.all())

    def test_a_broken_plugin_does_not_stop_the_others(self, tmp_path):
        (tmp_path / "broken.py").write_text("this is not python(", encoding="utf-8")
        (tmp_path / "temp_plugin.py").write_text(PLUGIN_SOURCE, encoding="utf-8")
        registry = ModuleRegistry(ScanConfig())
        registry.load_builtin()
        registry.load_directory(tmp_path)
        assert any(m.id == "temp_plugin" for m in registry.all())

    def test_a_missing_directory_is_ignored(self, tmp_path):
        registry = ModuleRegistry(ScanConfig())
        registry.load_builtin()
        registry.load_directory(tmp_path / "does-not-exist")
        assert len(registry.all()) > 0


class TestConfigLoading:
    def test_yaml_roundtrip(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "target": "https://example.com",
                    "profile": "quick",
                    "scope": ["example.com"],
                    "rate": {"requests_per_second": 5, "global_concurrency": 3},
                }
            ),
            encoding="utf-8",
        )
        config = ScanConfig.load(path)
        assert config.target == "https://example.com"
        assert config.profile == "quick"
        assert config.scope_rules == ["example.com"]
        assert config.rate.requests_per_second == 5
        assert config.rate.global_concurrency == 3

    def test_json_roundtrip(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text('{"target": "https://example.com", "profile": "recon"}', encoding="utf-8")
        config = ScanConfig.load(path)
        assert config.profile == "recon"

    def test_nested_dicts_are_coerced(self):
        config = ScanConfig(rate={"requests_per_second": 42})
        assert config.rate.requests_per_second == 42

    def test_unknown_keys_are_ignored(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text("target: https://example.com\nnot_a_real_key: 5\n", encoding="utf-8")
        config = ScanConfig.load(path)
        assert config.target == "https://example.com"

    def test_missing_file_raises_a_clear_error(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="config file not found"):
            ScanConfig.load(tmp_path / "nope.yaml")

    def test_friendly_aliases_are_accepted(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "target": "https://example.com",
                    "scope": ["example.com"],
                    "exclude": ["example.com/admin"],
                    "output": "/tmp/out",
                    "format": ["json"],
                }
            ),
            encoding="utf-8",
        )
        config = ScanConfig.load(path)
        assert config.scope_rules == ["example.com"]
        assert config.exclusions == ["example.com/admin"]
        assert config.output_dir == "/tmp/out"
        assert config.formats == ["json"]


class TestProfiles:
    def test_every_profile_resolves(self):
        for name in PROFILES:
            config = ScanConfig(profile=name)
            resolve_profile(config)
            assert config.profile == name

    def test_code_profile_selects_only_code_and_deps(self):
        config = ScanConfig(profile="code")
        resolve_profile(config)
        registry = ModuleRegistry(config)
        registry.load_builtin()
        selected = {m.id for m in registry.selected()}
        assert "secrets" in selected
        assert "dependency_vulnerabilities" in selected
        assert "sqli" not in selected
        assert "headers_security" not in selected

    def test_passive_profile_excludes_active_modules(self):
        config = ScanConfig(profile="passive")
        resolve_profile(config)
        registry = ModuleRegistry(config)
        registry.load_builtin()
        selected = {m.id for m in registry.selected()}
        assert "sqli" not in selected
        assert "xss" not in selected
        assert "headers_security" in selected

    def test_group_patterns_select_by_family(self):
        config = ScanConfig(profile="full")
        resolve_profile(config)
        registry = ModuleRegistry(config)
        registry.load_builtin()
        selected = {m.id for m in registry.selected()}
        assert {"sqli", "xss", "nosql_injection"} <= selected

    def test_exclude_beats_include(self):
        config = ScanConfig(profile="full", exclude_modules=["sqli"])
        resolve_profile(config)
        registry = ModuleRegistry(config)
        registry.load_builtin()
        selected = {m.id for m in registry.selected()}
        assert "sqli" not in selected
        assert "xss" in selected
