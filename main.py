"""CLI entry point for the WordPress endpoint scanner."""

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
    """Configure loguru output for console logging."""
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


def format_table_output(result: dict[str, Any]) -> str:
    """Render scan result as a human-readable table."""
    summary = result.get("summary", {})
    scanned_files = summary.get("scanned_files", 0)
    findings_count = summary.get("findings_count", 0)
    duration_ms = summary.get("duration_ms", 0)

    lines = [
        "=== Scan Summary ===",
        f"Scanned files: {scanned_files}",
        f"Findings: {findings_count}",
        f"Duration: {duration_ms} ms",
        "",
        "=== Findings ===",
        "FILE | LINE | METHOD | KIND | CONFIDENCE",
    ]

    findings = result.get("findings", [])
    for finding in findings:
        lines.append(
            " | ".join(
                [
                    str(finding.get("file", "")),
                    str(finding.get("line", "")),
                    str(finding.get("method", "")),
                    str(finding.get("kind", "")),
                    str(finding.get("confidence", "")),
                ]
            )
        )

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
