"""Scanner engine implementation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from models import Finding, FindingKind, MethodType
from scanner.detectors import detect_file
from scanner.filesystem import collect_source_files


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by file, line, method, and kind."""
    unique_findings: dict[tuple[str, int, MethodType, FindingKind], Finding] = {}
    for finding in findings:
        if finding.dedupe_key not in unique_findings:
            unique_findings[finding.dedupe_key] = finding
    return list(unique_findings.values())


def scan(path: str) -> dict[str, Any]:
    """Scan filesystem and return Step 1 result payload."""
    root_path = Path(path).resolve()
    source_files = collect_source_files(path)
    findings: list[Finding] = []

    for file_path in source_files:
        findings.extend(detect_file(file_path=file_path, root_path=root_path))

    deduplicated_findings = _deduplicate_findings(findings)

    return {
        "summary": {
            "scanned_files": len(source_files),
            "findings_count": len(deduplicated_findings),
        },
        "findings": [finding.to_dict() for finding in deduplicated_findings],
    }
