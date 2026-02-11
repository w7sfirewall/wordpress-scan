"""CLI entry point for the WordPress endpoint scanner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from loguru import logger

from scanner.engine import scan


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line parser."""
    parser = argparse.ArgumentParser(description="Scan WordPress endpoints")
    parser.add_argument("--path", required=True, help="Directory path to scan")
    parser.add_argument(
        "--format",
        choices=("json", "table"),
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--output",
        help="Optional file path to write output (overwrites existing file)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug output",
    )
    return parser


def configure_logging(verbose: bool) -> None:
    """Configure loguru output for CLI messages."""
    logger.remove()
    min_level = "DEBUG" if verbose else "INFO"
    error_level_no = logger.level("ERROR").no

    logger.add(
        sys.stdout,
        level=min_level,
        format="{message}",
        filter=lambda record: record["level"].no < error_level_no,
    )
    logger.add(sys.stderr, level="ERROR", format="{message}")


def format_json_output(result: dict[str, Any]) -> str:
    """Render scan result as pretty JSON."""
    return json.dumps(result, indent=2)


def _build_aligned_table(rows: list[list[str]]) -> list[str]:
    """Return table rows with simple aligned columns."""
    if not rows:
        return []

    column_widths = [0] * len(rows[0])
    for row in rows:
        for index, value in enumerate(row):
            column_widths[index] = max(column_widths[index], len(value))

    return [
        " | ".join(value.ljust(column_widths[index]) for index, value in enumerate(row))
        for row in rows
    ]


def format_table_output(result: dict[str, Any]) -> str:
    """Render scan result as a human-readable table."""
    summary = result.get("summary", {})
    scanned_files = summary.get("scanned_files", 0)
    findings_count = summary.get("findings_count", 0)

    findings = result.get("findings", [])

    table_rows: list[list[str]] = [
        ["FILE", "LINE", "METHOD", "KIND", "CONFIDENCE"],
    ]
    for finding in findings:
        table_rows.append(
            [
                str(finding.get("file", "")),
                str(finding.get("line", "")),
                str(finding.get("method", "")),
                str(finding.get("kind", "")),
                str(finding.get("confidence", "")),
            ]
        )

    lines = [
        "=== Scan Summary ===",
        f"Scanned files: {scanned_files}",
        f"Findings: {findings_count}",
        "",
        "=== Findings ===",
        *_build_aligned_table(table_rows),
    ]

    return "\n".join(lines)


def write_output_file(output_path: str, content: str) -> None:
    """Write rendered content to an output file, overwriting if it exists."""
    Path(output_path).write_text(f"{content}\n", encoding="utf-8")


def main() -> int:
    """Run the scanner CLI."""
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(verbose=args.verbose)

    target_path = Path(args.path)
    if not target_path.exists():
        logger.error(f"Error: path does not exist: {target_path}")
        return 1
    if not target_path.is_dir():
        logger.error(f"Error: path is not a directory: {target_path}")
        return 1

    if args.verbose:
        logger.debug(f"[DEBUG] Starting scan for: {target_path}")

    result = scan(str(target_path))

    if args.format == "json":
        rendered_output = format_json_output(result)
    else:
        rendered_output = format_table_output(result)

    logger.info(rendered_output)

    if args.output:
        try:
            write_output_file(args.output, rendered_output)
        except OSError as exc:
            logger.error(f"Error: failed to write output file '{args.output}': {exc}")
            return 1
        if args.verbose:
            logger.debug(f"[DEBUG] Wrote output to: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
