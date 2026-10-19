"""Report generation."""

from .html import write_html
from .json_report import write_json
from .markdown import write_markdown
from .sarif import write_sarif

__all__ = ["write_html", "write_json", "write_markdown", "write_sarif"]
