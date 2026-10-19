"""Crawler package."""

from .parser import (
    EXPOSED_PATHS,
    INTERESTING_FILES,
    INTERESTING_PARAMS,
    ParsedPage,
    parse_html,
)
from .spider import CrawlStats, Spider, normalize_url

__all__ = [
    "EXPOSED_PATHS",
    "INTERESTING_FILES",
    "INTERESTING_PARAMS",
    "CrawlStats",
    "ParsedPage",
    "Spider",
    "normalize_url",
    "parse_html",
]
