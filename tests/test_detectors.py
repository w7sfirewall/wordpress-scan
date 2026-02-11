"""Tests for regex detector behavior on synthetic PHP snippets."""

from pathlib import Path

from scanner.detectors import detect_file


def _has_finding(
    findings: list[dict[str, object]],
    *,
    line: int,
    method: str,
    kind: str,
    url: str,
    confidence: str,
) -> bool:
    """Return True when one finding matches all expected fields."""
    return any(
        finding["line"] == line
        and finding["method"] == method
        and finding["kind"] == kind
        and finding["url"] == url
        and finding["confidence"] == confidence
        for finding in findings
    )


def test_detector_extracts_mutation_findings_only(tmp_path: Path) -> None:
    """Verify detector emits only resolved mutation findings with stable fields."""
    sample_file = tmp_path / "sample.php"
    sample_file.write_text(
        "\n".join(
            [
                "<?php",
                "$resolved_url = 'https://api.wordpress.org/plugins/update-check/1.1/';",
                "wp_remote_post($resolved_url, $args);",
                "wp_remote_post('https://example.com/foo', $args);",
                "wp_remote_post($dynamic_url);",
                "wp_remote_request(",
                '    "https://example.test",',
                "    ['method' => 'PATCH']",
                ");",
                "wp_remote_request($request_url, ['method' => 'PUT']);",
                "wp_remote_get('https://example.test/get');",
                "wp_remote_request('https://example.test/ignored', ['method' => 'GET']);",
                "register_rest_route('demo/v1', '/items', ['methods' => ['POST', 'PUT']]);",
                "register_rest_route('demo/v1', '/edit', ['methods' => 'EDITABLE']);",
                "register_rest_route('demo/v1', '/create', ['methods' => 'CREATABLE']);",
                "add_action('wp_ajax_my_action', 'handler');",
                'add_action("wp_ajax_nopriv_guest_action", "handler");',
                "add_action('admin_post_sync_now', 'handler');",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    findings = [finding.to_dict() for finding in detect_file(sample_file, tmp_path)]

    assert _has_finding(
        findings,
        line=3,
        method="POST",
        kind="wp_http_api",
        url="https://api.wordpress.org/plugins/update-check/1.1/",
        confidence="medium",
    )
    assert _has_finding(
        findings,
        line=4,
        method="POST",
        kind="wp_http_api",
        url="https://example.com/foo",
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=6,
        method="PATCH",
        kind="wp_http_api",
        url="https://example.test",
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=13,
        method="POST",
        kind="rest_route",
        url="/wp-json/demo/v1/items",
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=13,
        method="PUT",
        kind="rest_route",
        url="/wp-json/demo/v1/items",
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=14,
        method="PUT",
        kind="rest_route",
        url="/wp-json/demo/v1/edit",
        confidence="medium",
    )
    assert _has_finding(
        findings,
        line=15,
        method="POST",
        kind="rest_route",
        url="/wp-json/demo/v1/create",
        confidence="medium",
    )
    assert _has_finding(
        findings,
        line=16,
        method="POST",
        kind="ajax",
        url="/wp-admin/admin-ajax.php?action=my_action",
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=17,
        method="POST",
        kind="ajax",
        url="/wp-admin/admin-ajax.php?action=guest_action",
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=18,
        method="POST",
        kind="admin_post",
        url="/wp-admin/admin-post.php?action=sync_now",
        confidence="high",
    )

    assert all(finding["method"] in {"POST", "PUT", "PATCH"} for finding in findings)
    assert all(isinstance(finding["url"], str) and finding["url"] for finding in findings)

    assert not any(
        finding["kind"] == "wp_http_api" and finding["line"] in {5, 10, 11, 12}
        for finding in findings
    )


def test_detector_skips_wp_remote_function_definitions(tmp_path: Path) -> None:
    """Verify function definitions of wp_remote_* are not emitted as findings."""
    sample_file = tmp_path / "defs.php"
    sample_file.write_text(
        "\n".join(
            [
                "<?php",
                "function wp_remote_post($url, $args = array()) {",
                "    return false;",
                "}",
                "function wp_remote_request($url, $args = array()) {",
                "    return false;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    findings = detect_file(sample_file, tmp_path)
    assert findings == []


def test_detector_skips_http_core_files(tmp_path: Path) -> None:
    """Verify detector ignores WordPress HTTP core implementation files."""
    core_file = tmp_path / "wp-includes" / "class-wp-http-curl.php"
    core_file.parent.mkdir(parents=True, exist_ok=True)
    core_file.write_text(
        "<?php\nwp_remote_post('https://example.com/should-not-appear', $args);\n",
        encoding="utf-8",
    )

    findings = detect_file(core_file, tmp_path)
    assert findings == []
