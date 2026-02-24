"""Tests for recursive filesystem scanning rules."""

from pathlib import Path

import pytest

from scanner.filesystem import collect_source_files


def test_collect_source_files_filters_extensions_and_excluded_directories(
    tmp_path: Path,
) -> None:
    """Verify scanner includes only supported files and skips excluded dirs."""
    include_php = tmp_path / "index.php"
    include_inc = tmp_path / "config.inc"
    include_phtml = tmp_path / "view.phtml"
    include_nested = tmp_path / "src" / "nested.php"

    skip_extension = tmp_path / "readme.txt"
    skip_vendor = tmp_path / "vendor" / "vendor.php"
    skip_node_modules = tmp_path / "node_modules" / "bundle.php"
    skip_git = tmp_path / ".git" / "hooks.php"
    skip_venv = tmp_path / ".venv" / "ignored.php"

    for file_path in [
        include_php,
        include_inc,
        include_phtml,
        include_nested,
        skip_extension,
        skip_vendor,
        skip_node_modules,
        skip_git,
        skip_venv,
    ]:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text("<?php\n", encoding="utf-8")

    discovered = {Path(path) for path in collect_source_files(str(tmp_path))}
    expected = {
        include_php.resolve(),
        include_inc.resolve(),
        include_phtml.resolve(),
        include_nested.resolve(),
    }

    assert discovered == expected
    assert all(path.is_absolute() for path in discovered)


def test_collect_source_files_raises_when_path_does_not_exist(tmp_path: Path) -> None:
    """Verify missing path raises a clear FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        collect_source_files(str(tmp_path / "missing"))
