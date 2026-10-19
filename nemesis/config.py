"""Configuration model for a scan.

Configuration comes from three places, in increasing priority:

1. built-in defaults
2. a YAML file (``--config``)
3. command line flags

Profiles are named bundles of module selections and crawl limits, so common
jobs are one flag: ``nemesis scan https://app.example.com --profile quick``.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

from .models import Severity

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 nemesis/0.1 (+https://github.com/nemesis-sec/nemesis)"
)

#: Modules that mutate server state. They only run when explicitly enabled.
DESTRUCTIVE_MODULES: set[str] = {
    "http_method_probe",
    "xml_external_entity",
    "insecure_deserialization",
    "prototype_pollution",
}


@dataclass
class RateConfig:
    """Politeness and throughput controls."""

    requests_per_second: float = 10.0
    per_host_concurrency: int = 4
    global_concurrency: int = 12
    max_retries: int = 1
    backoff: float = 0.4
    timeout: float = 15.0


@dataclass
class CrawlConfig:
    """Crawler limits."""

    max_pages: int = 300
    max_depth: int = 4
    max_body_bytes: int = 2_000_000
    follow_robots: bool = True
    crawl_delay: float = 0.0
    extensions: list[str] = field(
        default_factory=lambda: [
            ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".json", ".xml",
            ".txt", ".js", ".api", "",
        ]
    )
    skip_extensions: list[str] = field(
        default_factory=lambda: [
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".tar",
            ".gz", ".pdf", ".iso", ".dmg", ".exe", ".dll", ".so",
        ]
    )


@dataclass
class AuthConfig:
    """How to authenticate against the target."""

    mode: str = "none"  # none | header | bearer | basic | cookie | query
    header: str = "Authorization"
    value: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    username: str = ""
    password: str = ""
    query_param: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)


#: Friendlier key names accepted in config files, mapped to real fields.
CONFIG_ALIASES = {
    "scope": "scope_rules",
    "exclude": "exclusions",
    "excludes": "exclusions",
    "include": "include_modules",
    "output": "output_dir",
    "out": "output_dir",
    "format": "formats",
    "severity": "severity_min",
}


@dataclass
class ScanConfig:
    """Everything one scan needs to know."""

    target: str = ""
    scope_rules: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)

    profile: str = "full"
    include_modules: list[str] = field(default_factory=list)
    exclude_modules: list[str] = field(default_factory=list)
    module_tags: list[str] = field(default_factory=list)

    rate: RateConfig = field(default_factory=RateConfig)
    crawl: CrawlConfig = field(default_factory=CrawlConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)

    code_path: str | None = None
    verify: bool = True
    allow_destructive: bool = False
    follow_redirects: bool = True
    max_redirects: int = 5
    user_agent: str = DEFAULT_USER_AGENT
    proxy: str | None = None
    severity_min: Severity = Severity.INFO
    max_findings_per_module: int = 50
    timeout: float = 15.0
    threads: int = 12

    output_dir: str = "nemesis-report"
    formats: list[str] = field(default_factory=lambda: ["console", "json", "markdown"])
    save_evidence: bool = True
    offline: bool = False
    seed_urls: list[str] = field(default_factory=list)
    no_crawl: bool = False
    no_banner: bool = False

    # -- serialisation ----------------------------------------------------
    def __post_init__(self) -> None:
        """Coerce nested plain dicts into their dataclasses.

        Without this, ``ScanConfig(rate={"requests_per_second": 5})`` would
        leave a dict where a :class:`RateConfig` is expected, and the failure
        would only surface deep inside the HTTP client.
        """
        for attribute, cls in (
            ("rate", RateConfig),
            ("crawl", CrawlConfig),
            ("auth", AuthConfig),
        ):
            value = getattr(self, attribute)
            if isinstance(value, dict):
                known = {f.name for f in fields(cls)}
                setattr(self, attribute, cls(**{k: v for k, v in value.items() if k in known}))

        if isinstance(self.severity_min, str):
            self.severity_min = Severity[self.severity_min.upper()]

    def to_dict(self) -> dict[str, Any]:
        def _convert(value: Any) -> Any:
            if isinstance(value, Severity):
                return value.name
            if isinstance(value, dict):
                return {k: _convert(v) for k, v in value.items()}
            if isinstance(value, list):
                return [_convert(v) for v in value]
            return value

        return _convert(asdict(self))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanConfig:
        """Build a config from a plain dict, ignoring unknown keys.

        A few friendlier aliases are accepted so that a hand-written config
        file reads naturally: ``scope`` for ``scope_rules``, ``exclude``
        for ``exclusions`` and so on.
        """
        known = {f.name for f in fields(cls)}
        data = dict(data)

        for alias, field_name in CONFIG_ALIASES.items():
            if alias in data and field_name not in data:
                data[field_name] = data.pop(alias)

        kwargs: dict[str, Any] = {k: v for k, v in data.items() if k in known}

        for nested in ("rate", "crawl", "auth"):
            if nested in kwargs and isinstance(kwargs[nested], dict):
                sub_cls = {"rate": RateConfig, "crawl": CrawlConfig, "auth": AuthConfig}[nested]
                sub_known = {f.name for f in fields(sub_cls)}
                kwargs[nested] = sub_cls(
                    **{k: v for k, v in kwargs[nested].items() if k in sub_known}
                )

        if "severity_min" in kwargs and isinstance(kwargs["severity_min"], str):
            kwargs["severity_min"] = Severity[kwargs["severity_min"].upper()]

        return cls(**kwargs)

    @classmethod
    def load(cls, path: str | Path) -> ScanConfig:
        """Load a YAML or JSON config file."""
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"config file not found: {p}")
        text = p.read_text(encoding="utf-8")
        if p.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ValueError(f"config file {path} must contain a mapping")
        return cls.from_dict(data)


#: Named module bundles. Each profile is a set of module-id globs plus limits.
PROFILES: dict[str, dict[str, Any]] = {
    "quick": {
        "description": "Fast triage: passive checks plus the highest-signal active probes.",
        "include": [
            "headers/*", "config/*", "disclosure/*",
            "injection/sqli", "injection/xss", "traversal/path_traversal",
        ],
        "exclude": [],
        "crawl": {"max_pages": 40, "max_depth": 2},
    },
    "web": {
        "description": "Full web application assessment: everything that speaks HTTP.",
        "include": [],
        "exclude": ["code/*", "deps/*", "host/*"],
        "crawl": {"max_pages": 300, "max_depth": 4},
    },
    "code": {
        "description": "Static analysis and supply chain review of a local checkout.",
        "include": [
            "code/*", "deps/*", "blockchain/*", "supplychain/*",
            "ml_model_security",
        ],
        "exclude": [],
        "crawl": {"max_pages": 0, "max_depth": 0},
    },
    "ai": {
        "description": "AI and LLM application security: endpoints, prompt injection, tools, models.",
        "include": ["ai/*"],
        "exclude": [],
        "crawl": {"max_pages": 120, "max_depth": 3},
    },
    "blockchain": {
        "description": "Smart contract auditing of a local Solidity tree.",
        "include": ["blockchain/*"],
        "exclude": [],
        "crawl": {"max_pages": 0, "max_depth": 0},
    },
    "recon": {
        "description": "Passive and low-impact discovery only - no exploitation.",
        "include": [
            "headers/*", "config/*", "disclosure/*", "host/*", "supply-chain/*",
        ],
        "exclude": [],
        "crawl": {"max_pages": 100, "max_depth": 3},
    },
    "full": {
        "description": "Everything: web, host, source and dependency layers.",
        "include": [],
        "exclude": [],
        "crawl": {"max_pages": 300, "max_depth": 4},
    },
    "passive": {
        "description": "No additional requests beyond the crawl. Zero noise.",
        "include": ["headers/*", "config/*", "host/*"],
        "exclude": [],
        "crawl": {"max_pages": 60, "max_depth": 2},
    },
}


def resolve_profile(config: ScanConfig) -> ScanConfig:
    """Apply the selected profile's module selection and crawl limits."""
    profile = PROFILES.get(config.profile)
    if not profile:
        return config

    include = list(config.include_modules)
    for pattern in profile.get("include", []):
        if pattern not in include:
            include.append(pattern)

    exclude = list(config.exclude_modules)
    for pattern in profile.get("exclude", []):
        if pattern not in exclude:
            exclude.append(pattern)

    config.include_modules = include
    config.exclude_modules = exclude

    for key, value in profile.get("crawl", {}).items():
        if hasattr(config.crawl, key):
            setattr(config.crawl, key, value)
    return config
