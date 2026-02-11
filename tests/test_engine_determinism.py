"""Tests for deterministic ordering and deduplication in scanner engine."""

from pathlib import Path

from scanner.engine import scan


def test_scan_returns_sorted_and_deduplicated_findings(tmp_path: Path) -> None:
    """Verify scan output is stable: sorted and deduplicated by key fields."""
    file_b = tmp_path / "b.php"
    file_a = tmp_path / "a.php"

    file_b.write_text(
        "<?php\nwp_remote_post('https://example.com/b', $args);\n",
        encoding="utf-8",
    )
    file_a.write_text(
        "\n".join(
            [
                "<?php",
                "$dup = 'https://example.com/dup';",
                "wp_remote_post($dup, $args); wp_remote_post($dup, $args);",
                "wp_remote_post('https://example.com/a', $args);",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = scan(str(tmp_path))
    findings = result["findings"]

    ordering = [(item["file"], item["line"], item["method"], item["url"]) for item in findings]
    assert ordering == sorted(ordering)

    assert result["summary"]["findings_count"] == 3
    assert len(findings) == 3
