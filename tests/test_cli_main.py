"""Tests for CLI argument parsing and top-level CLI behavior."""

import json
import sys
from pathlib import Path

import pytest

import main as cli_main


def _run_main(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> int:
    """Run CLI entrypoint with a mocked argv."""
    monkeypatch.setattr(sys, "argv", ["main.py", *args])
    return cli_main.main()


def test_missing_required_path_argument_exits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify argparse exits when --path is missing."""
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, [])

    assert exc_info.value.code == 2


def test_invalid_path_returns_graceful_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Verify invalid scan path returns exit code 1 with clear stderr message."""
    invalid_path = tmp_path / "not-found"

    exit_code = _run_main(monkeypatch, ["--path", str(invalid_path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "path does not exist" in captured.err


def test_json_output_from_cli_is_parseable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Verify --format json prints valid JSON payload."""
    (tmp_path / "clean.php").write_text("<?php\necho 'ok';\n", encoding="utf-8")

    exit_code = _run_main(monkeypatch, ["--path", str(tmp_path), "--format", "json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["summary"]["scanned_files"] == 1
    assert payload["summary"]["findings_count"] == 0
    assert "duration_ms" in payload["summary"]
    assert isinstance(payload["findings"], list)
