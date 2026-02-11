"""Scanner engine implementation."""

from __future__ import annotations

from typing import Any

from scanner.filesystem import collect_source_files


def scan(path: str) -> dict[str, Any]:
    """Scan filesystem and return Step 1 result payload."""
    source_files = collect_source_files(path)

    return {
        "summary": {
            "scanned_files": len(source_files),
            "findings_count": 0,
        },
        "findings": [],
    }
