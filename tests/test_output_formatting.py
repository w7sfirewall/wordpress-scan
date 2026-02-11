"""Tests for JSON/table output formatting and URL rendering."""

import json
import sys
from pathlib import Path

import pytest

import main as cli_main
from scanner.engine import scan


def test_json_formatting_from_scan_contains_url_field(tmp_path: Path) -> None:
    """Verify JSON formatting preserves URL in findings."""
    sample_file = tmp_path / "sample.php"
    sample_file.write_text(
        "<?php\nwp_remote_post('https://example.com/endpoint', $args);\n",
        encoding="utf-8",
    )

    result = scan(str(tmp_path))
    rendered = cli_main.format_json_output(result)
    payload = json.loads(rendered)

    assert payload["summary"]["findings_count"] == 1
    assert payload["findings"][0]["url"] == "https://example.com/endpoint"


def test_table_output_prints_url_column_and_placeholder_for_missing_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify table output includes URL column and '-' for missing URL values."""
    sample_file = tmp_path / "sample.php"
    sample_file.write_text(
        "\n".join(
            [
                "<?php",
                "wp_remote_post('https://example.com/with-url', $args);",
                "wp_remote_post($dynamic_url);",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--path", str(tmp_path), "--format", "table"],
    )
    exit_code = cli_main.main()
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "FILE" in captured.out
    assert "LINE" in captured.out
    assert "METHOD" in captured.out
    assert "KIND" in captured.out
    assert "CONFIDENCE" in captured.out
    assert "URL" in captured.out
    assert "https://example.com/with-url" in captured.out
    assert " | -" in captured.out or "| -" in captured.out
