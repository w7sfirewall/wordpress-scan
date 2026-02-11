"""Scanner engine implementation."""

from pathlib import Path
from typing import Any

from scanner.detectors import detect_file
from scanner.filesystem import collect_source_files


def scan(path: str) -> dict[str, Any]:
    """Scan filesystem and return Step 1 result payload."""
    root_path = Path(path).resolve()
    source_files = collect_source_files(path)
    findings: list[dict[str, Any]] = []

    for file_path in source_files:
        findings.extend(detect_file(file_path=file_path, root_path=root_path))

    return {
        "summary": {
            "scanned_files": len(source_files),
            "findings_count": len(findings),
        },
        "findings": findings,
    }
