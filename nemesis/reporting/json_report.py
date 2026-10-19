"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import ScanResult


def write_json(result: ScanResult, path: str | Path) -> Path:
    """Write the full scan result as JSON."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8"
    )
    return target
