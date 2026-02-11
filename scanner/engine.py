"""Scanner engine implementation."""

from typing import Any


def scan(path: str) -> dict[str, Any]:
    """Scan a directory path and return Step 1 stub output."""
    _ = path
    return {
        "summary": {
            "scanned_files": 0,
            "findings_count": 0,
            "duration_ms": 0,
        },
        "findings": [],
    }
