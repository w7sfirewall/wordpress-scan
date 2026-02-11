"""Filesystem utilities for source file discovery."""

from __future__ import annotations

from pathlib import Path

INCLUDED_EXTENSIONS = {".php", ".inc", ".phtml"}
EXCLUDED_DIRECTORIES = {
    "node_modules",
    "vendor",
    ".git",
    "__pycache__",
    "venv",
    ".venv",
}


def collect_source_files(root_path: str) -> list[str]:
    """Recursively collect matching source files from a directory tree.

    Args:
        root_path: Directory to scan.

    Returns:
        Absolute file paths for files with supported extensions.

    Raises:
        FileNotFoundError: If the path does not exist.
        NotADirectoryError: If the path is not a directory.
    """
    root = Path(root_path)
    if not root.exists():
        raise FileNotFoundError(f"Scan path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Scan path is not a directory: {root}")

    discovered_files: list[str] = []
    pending_dirs: list[Path] = [root]

    while pending_dirs:
        current_dir = pending_dirs.pop()
        for entry in current_dir.iterdir():
            if entry.is_dir():
                if entry.name in EXCLUDED_DIRECTORIES:
                    continue
                pending_dirs.append(entry)
                continue

            if entry.is_file() and entry.suffix.lower() in INCLUDED_EXTENSIONS:
                discovered_files.append(str(entry.resolve()))

    return discovered_files
