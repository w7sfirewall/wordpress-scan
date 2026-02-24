"""Basic regex detectors for WordPress mutation endpoints."""

import re
from pathlib import Path

from models import ConfidenceLevel, Finding, FindingKind, MethodType

MUTATION_METHODS = {"POST", "PUT", "PATCH"}

WP_HTTP_CALL_RE = re.compile(
    r"""wp_remote_(post|request|get)\s*\((.*?)\)""",
    re.IGNORECASE | re.DOTALL,
)
WP_HTTP_METHOD_RE = re.compile(
    r"""['"]method['"]\s*=>\s*['"](POST|PUT|PATCH)['"]""",
    re.IGNORECASE | re.DOTALL,
)
WP_REMOTE_FUNCTION_DEFINITION_RE = re.compile(
    r"""\bfunction\s+wp_remote_(post|request|get)\s*\(""",
    re.IGNORECASE,
)
FIRST_ARGUMENT_LITERAL_RE = re.compile(r"""^\s*['"]([^'"]+)['"]""", re.DOTALL)
FIRST_ARGUMENT_VARIABLE_RE = re.compile(r"""^\s*(\$[a-zA-Z_][a-zA-Z0-9_]*)""", re.DOTALL)
VARIABLE_ASSIGNMENT_RE = re.compile(
    r"""\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"]([^'"]+)['"]\s*;""",
    re.IGNORECASE | re.DOTALL,
)

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

AJAX_RE = re.compile(
    r"""\badd_action\s*\(\s*['"]wp_ajax_(?:nopriv_)?(?P<action>[A-Za-z0-9_]+)['"]"""
)
ADMIN_POST_RE = re.compile(
    r"""\badd_action\s*\(\s*['"]admin_post_(?:nopriv_)?(?P<action>[A-Za-z0-9_]+)['"]"""
)


def _is_http_core_file(relative_file: str) -> bool:
    """Return True if file belongs to WordPress HTTP core internals."""
    normalized = relative_file.replace("\\", "/")
    file_name = Path(normalized).name

    if normalized.endswith("wp-includes/http.php"):
        return True
    if file_name == "class-wp-http.php":
        return True
    if file_name.startswith("class-wp-http-") and file_name.endswith(".php"):
        return True
    return False


def _resolve_rest_method(token: str) -> tuple[MethodType, ConfidenceLevel] | None:
    """Map rest-route method token into output method and confidence."""
    method_token = token.upper()
    if method_token in MUTATION_METHODS:
        return method_token, "high"
    if method_token == "CREATABLE":
        return "POST", "medium"
    if method_token == "EDITABLE":
        return "PUT", "medium"
    return None


def _extract_rest_methods(line: str) -> list[tuple[MethodType, ConfidenceLevel]]:
    """Extract one or multiple rest-route methods from a single line."""
    assignment_match = REST_METHOD_ASSIGNMENT_RE.search(line)
    if not assignment_match:
        return []

    methods: list[tuple[MethodType, ConfidenceLevel]] = []
    for token in REST_METHOD_TOKEN_RE.findall(assignment_match.group(1)):
        resolved = _resolve_rest_method(token)
        if resolved:
            methods.append(resolved)
    return methods


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


def _resolve_http_method(function_name: str, argument_block: str) -> MethodType | None:
    """Resolve mutation method for wp_remote_* calls."""
    normalized_name = function_name.lower()
    if normalized_name == "post":
        return "POST"
    if normalized_name != "request":
        return None

    method_match = WP_HTTP_METHOD_RE.search(argument_block)
    if not method_match:
        return None

    method = method_match.group(1).upper()
    if method in MUTATION_METHODS:
        return method
    return None


def _make_finding(
    relative_file: str,
    line_no: int,
    method: MethodType,
    kind: FindingKind,
    confidence: ConfidenceLevel,
    url: str,
) -> Finding:
    """Create a finding model instance."""
    return Finding(
        file=relative_file,
        line=line_no,
        method=method,
        kind=kind,
        confidence=confidence,
        url=url,
    )


def _is_function_definition(content: str, match_start: int) -> bool:
    """Return True when matched wp_remote_* token is a function definition."""
    line_start = content.rfind("\n", 0, match_start) + 1
    line_end = content.find("\n", match_start)
    if line_end == -1:
        line_end = len(content)
    line_text = content[line_start:line_end]
    return bool(WP_REMOTE_FUNCTION_DEFINITION_RE.search(line_text))


def _detect_wp_http_api(content: str, relative_file: str) -> list[Finding]:
    """Detect wp_remote_* mutation calls from whole-file content."""
    findings: list[Finding] = []
    assignments = _collect_variable_assignments(content)

    for match in WP_HTTP_CALL_RE.finditer(content):
        if _is_function_definition(content, match.start()):
            continue

        function_name = match.group(1)
        argument_block = match.group(2)
        line_no = content.count("\n", 0, match.start()) + 1

        method = _resolve_http_method(function_name=function_name, argument_block=argument_block)
        if not method:
            continue

        url, confidence = _extract_first_argument_url(
            argument_block=argument_block,
            assignments=assignments,
        )
        if not url:
            continue

        findings.append(
            _make_finding(
                relative_file=relative_file,
                line_no=line_no,
                method=method,
                kind="wp_http_api",
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

    if _is_http_core_file(relative_file):
        return []

    with resolved_file.open("r", encoding="utf-8") as file_handle:
        content = file_handle.read()

    findings: list[Finding] = _detect_wp_http_api(content=content, relative_file=relative_file)

    for line_no, line in enumerate(content.splitlines(), start=1):
        trimmed_line = line.strip()
        if not trimmed_line:
            continue

        route_args_match = REGISTER_REST_ROUTE_ARGS_RE.search(trimmed_line)
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
                        confidence=confidence,
                        url=rest_url,
                    )
                )

        ajax_match = AJAX_RE.search(trimmed_line)
        if ajax_match:
            action_name = ajax_match.group("action")
            if action_name:
                findings.append(
                    _make_finding(
                        relative_file=relative_file,
                        line_no=line_no,
                        method="POST",
                        kind="ajax",
                        confidence="high",
                        url=f"/wp-admin/admin-ajax.php?action={action_name}",
                    )
                )

        admin_post_match = ADMIN_POST_RE.search(trimmed_line)
        if admin_post_match:
            action_name = admin_post_match.group("action")
            if action_name:
                findings.append(
                    _make_finding(
                        relative_file=relative_file,
                        line_no=line_no,
                        method="POST",
                        kind="admin_post",
                        confidence="high",
                        url=f"/wp-admin/admin-post.php?action={action_name}",
                    )
                )

    return findings
