"""Basic regex detectors for WordPress mutation endpoints."""

from __future__ import annotations

import re
from pathlib import Path

from models import ConfidenceLevel, Finding, FindingKind, MethodType

WP_REMOTE_POST_RE = re.compile(r"\bwp_remote_post\s*\(")
WP_REMOTE_REQUEST_RE = re.compile(r"\bwp_remote_request\s*\(")
HTTP_METHOD_RE = re.compile(
    r"""['"]method['"]\s*=>\s*['"](POST|PUT|PATCH)['"]""",
    re.IGNORECASE,
)

REGISTER_REST_ROUTE_RE = re.compile(r"\bregister_rest_route\s*\(")
REST_METHOD_ASSIGNMENT_RE = re.compile(r"""['"]methods['"]\s*=>\s*(.+)""", re.IGNORECASE)
REST_METHOD_TOKEN_RE = re.compile(
    r"""['"](POST|PUT|PATCH|CREATABLE|EDITABLE)['"]""",
    re.IGNORECASE,
)

ADMIN_POST_RE = re.compile(r"""\badd_action\s*\(\s*['"]admin_post_[^'"]*['"]""")
AJAX_RE = re.compile(r"""\badd_action\s*\(\s*['"]wp_ajax_[^'"]*['"]""")


def _resolve_rest_method(token: str) -> tuple[MethodType, ConfidenceLevel]:
    """Map rest-route method token into output method and confidence."""
    method_token = token.upper()
    if method_token in {"POST", "PUT", "PATCH"}:
        return method_token, "high"
    if method_token == "CREATABLE":
        return "POST", "medium"
    if method_token == "EDITABLE":
        return "PUT", "medium"
    return "UNKNOWN", "medium"


def _extract_rest_methods(line: str) -> list[tuple[MethodType, ConfidenceLevel]]:
    """Extract one or multiple rest-route methods from a single line."""
    assignment_match = REST_METHOD_ASSIGNMENT_RE.search(line)
    if not assignment_match:
        return []

    method_tokens = REST_METHOD_TOKEN_RE.findall(assignment_match.group(1))
    resolved_methods: list[tuple[MethodType, ConfidenceLevel]] = []
    for token in method_tokens:
        resolved_methods.append(_resolve_rest_method(token))
    return resolved_methods


def _make_finding(
    relative_file: str,
    line_no: int,
    method: MethodType,
    kind: FindingKind,
    evidence: str,
    confidence: ConfidenceLevel,
) -> Finding:
    """Create a finding model instance."""
    return Finding(
        file=relative_file,
        line=line_no,
        method=method,
        kind=kind,
        evidence=evidence,
        confidence=confidence,
    )


def detect_file(file_path: str | Path, root_path: str | Path) -> list[Finding]:
    """Detect findings in one file using line-by-line regex checks."""
    resolved_file = Path(file_path).resolve()
    resolved_root = Path(root_path).resolve()

    try:
        relative_file = resolved_file.relative_to(resolved_root).as_posix()
    except ValueError:
        relative_file = resolved_file.as_posix()

    findings: list[Finding] = []
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
                        confidence="high",
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
                            confidence="high",
                        )
                    )

            if REGISTER_REST_ROUTE_RE.search(trimmed_line):
                for method, confidence in _extract_rest_methods(trimmed_line):
                    findings.append(
                        _make_finding(
                            relative_file=relative_file,
                            line_no=line_no,
                            method=method,
                            kind="rest_route",
                            evidence=trimmed_line,
                            confidence=confidence,
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
                        confidence="medium",
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
                        confidence="medium",
                    )
                )

    return findings
