"""Scanner engine implementation."""

from pathlib import Path
from time import perf_counter
from typing import Any

from loguru import logger

from models import Finding, MethodType
from scanner.detectors import detect_file
from scanner.filesystem import collect_source_files


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by file, line, method, and url."""
    unique_findings: dict[tuple[str, int, MethodType, str | None], Finding] = {}
    for finding in findings:
        if finding.dedupe_key not in unique_findings:
            unique_findings[finding.dedupe_key] = finding
    return list(unique_findings.values())


def scan(path: str) -> dict[str, Any]:
    """Scan filesystem and return Step 1 result payload."""
    started_at = perf_counter()
    root_path = Path(path).resolve()
    source_files = collect_source_files(path)
    scanned_files = 0
    findings: list[Finding] = []

    for file_path in source_files:
        try:
            findings.extend(detect_file(file_path=file_path, root_path=root_path))
            scanned_files += 1
        except UnicodeDecodeError as exc:
            logger.warning(f"Skipping file with unicode decode error: {file_path} ({exc})")
        except OSError as exc:
            logger.warning(f"Skipping unreadable file: {file_path} ({exc})")

    deduplicated_findings = _deduplicate_findings(findings)
    duration_ms = int((perf_counter() - started_at) * 1000)

    return {
        "summary": {
            "scanned_files": scanned_files,
            "findings_count": len(deduplicated_findings),
            "duration_ms": duration_ms,
        },
        "findings": [finding.to_dict() for finding in deduplicated_findings],
    }
