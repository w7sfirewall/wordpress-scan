"""Basic regex detectors for WordPress mutation endpoints."""

import re
from pathlib import Path

from models import ConfidenceLevel, Finding, FindingKind, MethodType

WP_HTTP_CALL_RE = re.compile(
    r"""wp_remote_(post|request|get)\s*\((.*?)\)""",
    re.IGNORECASE | re.DOTALL,
)
WP_HTTP_METHOD_RE = re.compile(
    r"""['"]method['"]\s*=>\s*['"](POST|PUT|PATCH)['"]""",
    re.IGNORECASE | re.DOTALL,
)
FIRST_ARGUMENT_LITERAL_RE = re.compile(r"""^\s*['"]([^'"]+)['"]""", re.DOTALL)
FIRST_ARGUMENT_VARIABLE_RE = re.compile(r"""^\s*(\$[a-zA-Z_][a-zA-Z0-9_]*)""", re.DOTALL)
VARIABLE_ASSIGNMENT_RE = re.compile(
    r"""\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"]([^'"]+)['"]\s*;""",
    re.IGNORECASE | re.DOTALL,
)

REGISTER_REST_ROUTE_RE = re.compile(r"\bregister_rest_route\s*\(")
REGISTER_REST_ROUTE_ARGS_RE = re.compile(
    r"""\bregister_rest_route\s*\(\s*"""
    r"""(?P<q1>['"])(?P<namespace>[^'"]+)(?P=q1)\s*,\s*"""
    r"""(?P<q2>['"])(?P<route>[^'"]+)(?P=q2)"""
)
REST_METHOD_ASSIGNMENT_RE = re.compile(r"""['"]methods['"]\s*=>\s*(.+)""", re.IGNORECASE)
REST_METHOD_TOKEN_RE = re.compile(
    r"""['"](POST|PUT|PATCH|CREATABLE|EDITABLE)['"]""",
    re.IGNORECASE,
)

ADMIN_POST_RE = re.compile(r"""\badd_action\s*\(\s*['"]admin_post_[^'"]*['"]""")
AJAX_RE = re.compile(
    r"""\badd_action\s*\(\s*['"]wp_ajax_(?:nopriv_)?(?P<action>[A-Za-z0-9_]+)['"]"""
)


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


def _collect_variable_assignments(content: str) -> dict[str, str]:
    """Collect simple variable assignments to literal strings in this file."""
    assignments: dict[str, str] = {}
    for variable_name, literal_value in VARIABLE_ASSIGNMENT_RE.findall(content):
        assignments[f"${variable_name}"] = literal_value
    return assignments


def _extract_first_argument_url(
    argument_block: str,
    assignments: dict[str, str],
) -> tuple[str | None, ConfidenceLevel]:
    """Extract first-argument URL from a call argument block."""
    literal_match = FIRST_ARGUMENT_LITERAL_RE.search(argument_block)
    if literal_match:
        return literal_match.group(1), "high"

    variable_match = FIRST_ARGUMENT_VARIABLE_RE.search(argument_block)
    if variable_match:
        variable_name = variable_match.group(1)
        return assignments.get(variable_name), "medium"

    return None, "medium"


def _resolve_http_method(function_name: str, argument_block: str) -> MethodType:
    """Resolve method for wp_remote_* calls."""
    function_name = function_name.lower()
    if function_name == "post":
        return "POST"
    if function_name == "request":
        method_match = WP_HTTP_METHOD_RE.search(argument_block)
        if method_match:
            return method_match.group(1).upper()
        return "UNKNOWN"
    return "UNKNOWN"


def _make_finding(
    relative_file: str,
    line_no: int,
    method: MethodType,
    kind: FindingKind,
    evidence: str,
    confidence: ConfidenceLevel,
    url: str | None = None,
) -> Finding:
    """Create a finding model instance."""
    return Finding(
        file=relative_file,
        line=line_no,
        method=method,
        kind=kind,
        evidence=evidence,
        confidence=confidence,
        url=url,
    )


def _detect_wp_http_api(
    content: str,
    relative_file: str,
) -> list[Finding]:
    """Detect wp_remote_* calls from whole-file content."""
    findings: list[Finding] = []
    assignments = _collect_variable_assignments(content)

    for match in WP_HTTP_CALL_RE.finditer(content):
        function_name = match.group(1)
        argument_block = match.group(2)
        line_no = content.count("\n", 0, match.start()) + 1

        method = _resolve_http_method(function_name=function_name, argument_block=argument_block)
        if method not in {"POST", "PUT", "PATCH"}:
            continue

        url, confidence = _extract_first_argument_url(
            argument_block=argument_block,
            assignments=assignments,
        )
        evidence = match.group(0).strip().splitlines()[0].strip()

        findings.append(
            _make_finding(
                relative_file=relative_file,
                line_no=line_no,
                method=method,
                kind="wp_http_api",
                evidence=evidence,
                confidence=confidence,
                url=url,
            )
        )

    return findings


def detect_file(file_path: str | Path, root_path: str | Path) -> list[Finding]:
    """Detect findings in one file."""
    resolved_file = Path(file_path).resolve()
    resolved_root = Path(root_path).resolve()

    try:
        relative_file = resolved_file.relative_to(resolved_root).as_posix()
    except ValueError:
        relative_file = resolved_file.as_posix()

    with resolved_file.open("r", encoding="utf-8") as file_handle:
        content = file_handle.read()

    findings: list[Finding] = _detect_wp_http_api(content=content, relative_file=relative_file)

    for line_no, line in enumerate(content.splitlines(), start=1):
        trimmed_line = line.strip()
        if not trimmed_line:
            continue

        if REGISTER_REST_ROUTE_RE.search(trimmed_line):
            route_args_match = REGISTER_REST_ROUTE_ARGS_RE.search(trimmed_line)
            rest_url = None
            if route_args_match:
                namespace = route_args_match.group("namespace")
                route = route_args_match.group("route")
                rest_url = f"/wp-json/{namespace}{route}"

            for method, confidence in _extract_rest_methods(trimmed_line):
                findings.append(
                    _make_finding(
                        relative_file=relative_file,
                        line_no=line_no,
                        method=method,
                        kind="rest_route",
                        evidence=trimmed_line,
                        confidence=confidence,
                        url=rest_url,
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

        ajax_match = AJAX_RE.search(trimmed_line)
        if ajax_match:
            action_name = ajax_match.group("action")
            findings.append(
                _make_finding(
                    relative_file=relative_file,
                    line_no=line_no,
                    method="UNKNOWN",
                    kind="ajax",
                    evidence=trimmed_line,
                    confidence="medium",
                    url=f"/wp-admin/admin-ajax.php?action={action_name}",
                )
            )

    return findings
