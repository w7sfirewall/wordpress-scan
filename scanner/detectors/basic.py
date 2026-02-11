"""Basic regex detectors for WordPress mutation endpoints."""

import re
from pathlib import Path
from typing import Any

WP_REMOTE_POST_RE = re.compile(r"\bwp_remote_post\s*\(")
WP_REMOTE_REQUEST_RE = re.compile(r"\bwp_remote_request\s*\(")
HTTP_METHOD_RE = re.compile(
    r"""['"]method['"]\s*=>\s*['"](POST|PUT|PATCH)['"]""",
    re.IGNORECASE,
)

REGISTER_REST_ROUTE_RE = re.compile(r"\bregister_rest_route\s*\(")
REST_METHOD_RE = re.compile(
    r"""['"]methods['"]\s*=>\s*['"](POST|PUT|PATCH|CREATABLE|EDITABLE)['"]""",
    re.IGNORECASE,
)

ADMIN_POST_RE = re.compile(r"""\badd_action\s*\(\s*['"]admin_post_[^'"]*['"]""")
AJAX_RE = re.compile(r"""\badd_action\s*\(\s*['"]wp_ajax_[^'"]*['"]""")


def _normalize_method(raw_method: str) -> str:
    """Normalize method token into scanner output values."""
    method = raw_method.upper()
    if method in {"POST", "PUT", "PATCH"}:
        return method
    if method == "CREATABLE":
        return "POST"
    return "UNKNOWN"


def _make_finding(
    relative_file: str,
    line_no: int,
    method: str,
    kind: str,
    evidence: str,
) -> dict[str, Any]:
    """Create a finding record."""
    return {
        "file": relative_file,
        "line": line_no,
        "method": method,
        "kind": kind,
        "evidence": evidence,
    }


def detect_file(file_path: str | Path, root_path: str | Path) -> list[dict[str, Any]]:
    """Detect findings in one file using line-by-line regex checks."""
    resolved_file = Path(file_path).resolve()
    resolved_root = Path(root_path).resolve()

    try:
        relative_file = resolved_file.relative_to(resolved_root).as_posix()
    except ValueError:
        relative_file = resolved_file.as_posix()

    findings: list[dict[str, Any]] = []
    with resolved_file.open("r", encoding="utf-8", errors="ignore") as file_handle:
        for line_no, line in enumerate(file_handle, start=1):
            trimmed_line = line.strip()
            if not trimmed_line:
                continue

            if WP_REMOTE_POST_RE.search(trimmed_line):
                findings.append(
                    _make_finding(
                        relative_file=relative_file,
                        line_no=line_no,
                        method="POST",
                        kind="wp_http_api",
                        evidence=trimmed_line,
                    )
                )

            if WP_REMOTE_REQUEST_RE.search(trimmed_line):
                request_method_match = HTTP_METHOD_RE.search(trimmed_line)
                if request_method_match:
                    findings.append(
                        _make_finding(
                            relative_file=relative_file,
                            line_no=line_no,
                            method=request_method_match.group(1).upper(),
                            kind="wp_http_api",
                            evidence=trimmed_line,
                        )
                    )

            if REGISTER_REST_ROUTE_RE.search(trimmed_line):
                rest_method_match = REST_METHOD_RE.search(trimmed_line)
                if rest_method_match:
                    findings.append(
                        _make_finding(
                            relative_file=relative_file,
                            line_no=line_no,
                            method=_normalize_method(rest_method_match.group(1)),
                            kind="rest_route",
                            evidence=trimmed_line,
                        )
                    )

            if ADMIN_POST_RE.search(trimmed_line):
                findings.append(
                    _make_finding(
                        relative_file=relative_file,
                        line_no=line_no,
                        method="UNKNOWN",
                        kind="admin_post",
                        evidence=trimmed_line,
                    )
                )

            if AJAX_RE.search(trimmed_line):
                findings.append(
                    _make_finding(
                        relative_file=relative_file,
                        line_no=line_no,
                        method="UNKNOWN",
                        kind="ajax",
                        evidence=trimmed_line,
                    )
                )

    return findings
