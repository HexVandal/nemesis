"""The scan engine.

The engine owns the pipeline and nothing else does:

    scope -> crawl -> fingerprint -> modules -> verify -> report

Modules are handed a :class:`~nemesis.modules.base.ScanContext` and return
findings. The engine is responsible for ordering, concurrency, statistics and
making sure a failure in one module never takes down the scan.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .config import ScanConfig, resolve_profile
from .crawler.spider import Spider
from .fingerprint.tech import fingerprint
from .http.client import HttpClient
from .models import Finding, ScanResult, Target, utcnow
from .modules.base import ModuleRegistry, ScanContext
from .scope import Scope

log = logging.getLogger("nemesis.engine")


@dataclass
class ProgressEvent:
    """A progress signal for the console renderer."""

    stage: str
    message: str
    current: int = 0
    total: int = 0

    @property
    def percent(self) -> float:
        if not self.total:
            return 0.0
        return min(100.0, 100.0 * self.current / self.total)


class Engine:
    """Runs a complete scan."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = resolve_profile(config)
        self.registry = ModuleRegistry(self.config)
        self.events: list[ProgressEvent] = []

    # -- setup ------------------------------------------------------------
    def _build_scope(self) -> Scope:
        rules = list(self.config.scope_rules)
        if not rules:
            parsed = urlparse(self.config.target)
            if parsed.hostname:
                rules = [parsed.hostname]
        return Scope(
            rules=rules,
            exclusions=self.config.exclusions,
            default_host=urlparse(self.config.target).hostname,
        )

    def _build_target(self) -> Target:
        parsed = urlparse(self.config.target)
        scheme = parsed.scheme or "https"
        host = parsed.hostname or ""
        port = parsed.port or (443 if scheme == "https" else 80)
        return Target(
            base_url=self.config.target,
            host=host,
            scheme=scheme,
            port=port,
            name=host or self.config.target,
        )

    # -- main -------------------------------------------------------------
    async def run(self) -> ScanResult:
        started = time.monotonic()
        target = self._build_target()
        scope = self._build_scope()

        if not scope:
            raise ValueError(
                "no scope defined - pass --scope or supply a target URL with a host"
            )

        result = ScanResult(target=target)

        # -- load modules --------------------------------------------------
        self.registry.load_builtin()
        self.registry.load_entry_points()
        # Plugins shipped inside the nemesis package load automatically.
        self.registry.load_directory(Path(__file__).parent / "plugins")
        modules = self.registry.selected()
        self._emit("modules", f"{len(modules)} modules selected")

        async with HttpClient(self.config, scope) as client:
            ctx = ScanContext(
                config=self.config,
                scope=scope,
                client=client,
                target_url=self.config.target,
                host=target.host,
                code_path=self.config.code_path,
            )

            # -- crawl ------------------------------------------------------
            endpoints = []
            if not self.config.no_crawl:
                self._emit("crawl", f"crawling {self.config.target}")
                spider = Spider(client, self.config, scope)
                seeds = scope.expand_seed(self.config.target) + list(self.config.seed_urls)
                endpoints, forms, crawl_stats = await spider.crawl(seeds)
                ctx.endpoints = endpoints
                ctx.forms = forms
                ctx.responses = list(spider.responses.values())
                result.endpoints = endpoints
                result.forms = forms
                result.stats["crawl"] = {
                    "pages_fetched": crawl_stats.pages_fetched,
                    "links_discovered": crawl_stats.links_discovered,
                    "forms_discovered": crawl_stats.forms_discovered,
                    "parameters_discovered": crawl_stats.parameters_discovered,
                    "pages_skipped_out_of_scope": crawl_stats.pages_skipped_scope,
                    "external_hosts": sorted(crawl_stats.external_hosts)[:20],
                }
                self._emit(
                    "crawl",
                    f"{crawl_stats.pages_fetched} pages, {len(forms)} forms, "
                    f"{crawl_stats.parameters_discovered} parameters",
                )

                # -- fingerprint -------------------------------------------
                self._emit("fingerprint", "identifying technologies")
                seen_tech = {}
                for response in ctx.responses:
                    for tech in fingerprint(response):
                        key = tech.name.lower()
                        if key not in seen_tech:
                            seen_tech[key] = tech
                ctx.technologies = list(seen_tech.values())
                result.technologies = ctx.technologies
                self._emit("fingerprint", f"{len(ctx.technologies)} technologies identified")

            # -- run modules -----------------------------------------------
            self._emit("scan", f"running {len(modules)} modules")
            findings: list[Finding] = []
            for module in modules:
                self._emit("scan", f"running {module.id}")
                started_module = time.monotonic()
                module_findings = await self.registry.run([module], ctx)
                for finding in module_findings:
                    finding.fingerprint = finding.compute_fingerprint()
                findings.extend(module_findings)
                ctx.stats.setdefault("module_timings", {})[module.id] = round(
                    time.monotonic() - started_module, 2
                )

            # -- dedupe and rank --------------------------------------------
            findings = self._dedupe(findings)
            findings = self._filter(findings)
            result.findings = findings
            result.stats["modules_run"] = len(modules)
            result.stats["requests_sent"] = client.request_count
            result.stats["bytes_received"] = client.bytes_received
            result.stats.update(ctx.stats)

        result.duration_seconds = round(time.monotonic() - started, 2)
        result.finished_at = utcnow()
        return result

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        """Drop duplicate findings, keeping the most confident one."""
        best: dict[str, Finding] = {}
        for finding in findings:
            existing = best.get(finding.fingerprint)
            if existing is None:
                best[finding.fingerprint] = finding
                continue
            if finding.confidence.rank > existing.confidence.rank or (finding.severity.value > existing.severity.value and (
                finding.confidence.rank == existing.confidence.rank
            )):
                best[finding.fingerprint] = finding
        return list(best.values())

    def _filter(self, findings: list[Finding]) -> list[Finding]:
        """Apply the severity floor and rank the result."""
        threshold = self.config.severity_min.value
        kept = [f for f in findings if f.severity.value >= threshold]
        kept.sort(
            key=lambda f: (-f.severity.value, -f.confidence.rank, f.title)
        )
        return kept

    def _emit(self, stage: str, message: str) -> None:
        event = ProgressEvent(stage=stage, message=message)
        self.events.append(event)
        log.debug("[%s] %s", stage, message)
