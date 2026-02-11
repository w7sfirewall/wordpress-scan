"""Tests for regex detector behavior on synthetic PHP snippets."""

from pathlib import Path

from scanner.detectors import detect_file


def _has_finding(
    findings: list[dict[str, object]],
    *,
    line: int,
    method: str,
    kind: str,
    url: str | None,
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


def test_detector_extracts_methods_urls_and_confidence_from_patterns(tmp_path: Path) -> None:
    """Verify detector extracts expected fields across supported patterns."""
    sample_file = tmp_path / "sample.php"
    sample_file.write_text(
        "\n".join(
            [
                "<?php",
                "wp_remote_post('https://example.com/foo', $args);",
                "wp_remote_post($dynamic_url);",
                'wp_remote_request("https://example.test", [\'method\' => \'PATCH\']);',
                "wp_remote_request($request_url, ['method' => 'PUT']);",
                "wp_remote_post('https://example.com/multi',",
                "    $args",
                ");",
                'wp_remote_request("https://example.test/multi", [\'method\' => \'POST\',',
                "    'timeout' => 10",
                "]);",
                "register_rest_route('demo/v1', '/items', ['methods' => ['POST', 'PUT']]);",
                "register_rest_route('demo/v1', '/edit', ['methods' => 'EDITABLE']);",
                "register_rest_route('demo/v1', '/create', ['methods' => 'CREATABLE']);",
                "add_action('wp_ajax_my_action', 'handler');",
                'add_action("wp_ajax_nopriv_guest_action", "handler");',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    findings = [finding.to_dict() for finding in detect_file(sample_file, tmp_path)]

    assert _has_finding(
        findings,
        line=2,
        method="POST",
        kind="wp_http_api",
        url="https://example.com/foo",
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=3,
        method="POST",
        kind="wp_http_api",
        url=None,
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=4,
        method="PATCH",
        kind="wp_http_api",
        url="https://example.test",
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=5,
        method="PUT",
        kind="wp_http_api",
        url=None,
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=6,
        method="POST",
        kind="wp_http_api",
        url="https://example.com/multi",
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=9,
        method="POST",
        kind="wp_http_api",
        url="https://example.test/multi",
        confidence="high",
    )

    assert _has_finding(
        findings,
        line=12,
        method="POST",
        kind="rest_route",
        url="/wp-json/demo/v1/items",
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=12,
        method="PUT",
        kind="rest_route",
        url="/wp-json/demo/v1/items",
        confidence="high",
    )
    assert _has_finding(
        findings,
        line=13,
        method="PUT",
        kind="rest_route",
        url="/wp-json/demo/v1/edit",
        confidence="medium",
    )
    assert _has_finding(
        findings,
        line=14,
        method="POST",
        kind="rest_route",
        url="/wp-json/demo/v1/create",
        confidence="medium",
    )

    assert _has_finding(
        findings,
        line=15,
        method="UNKNOWN",
        kind="ajax",
        url="/wp-admin/admin-ajax.php?action=my_action",
        confidence="medium",
    )
    assert _has_finding(
        findings,
        line=16,
        method="UNKNOWN",
        kind="ajax",
        url="/wp-admin/admin-ajax.php?action=guest_action",
        confidence="medium",
    )
