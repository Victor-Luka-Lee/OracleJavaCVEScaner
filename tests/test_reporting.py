from datetime import datetime, timezone
import json

from jvi.engine import evaluate_asset
from jvi.models import ScanReport
from jvi.reporting import DISCLAIMER, csv_report, html_report, json_report


def _report(database, asset):
    return ScanReport(
        scan_time="2026-11-18T17:11:00+09:00",
        started_at="2026-11-18T17:11:00+09:00",
        completed_at="2026-11-18T17:11:09+09:00",
        environment={
            "os": "Windows",
            "os_release": "11",
            "architecture": "AMD64",
            "hostname": "test-host",
        },
        scope={
            "mode": "extended",
            "roots": [asset.install_path],
            "examined_entries": 123,
            "max_depth": 7,
            "max_files": 100_000,
            "timeout_seconds": 180,
            "follow_symlinks": False,
            "java_execution_enabled": False,
            "package_metadata_enabled": True,
            "incomplete": False,
            "limit_reasons": [],
        },
        assets=[asset],
        findings=evaluate_asset(asset, database),
        database_version=database["database_version"],
        sources=database["sources"],
        limitations=[DISCLAIMER],
        advisories=database["advisories"],
    )


def test_json_csv_html_reports_are_generated(database, asset_factory):
    report = _report(database, asset_factory("21.0.13.0.3"))
    parsed = json.loads(json_report(report))
    assert parsed["assets"][0]["full_version"] == "21.0.13.0.3"
    assert parsed["started_at"] == "2026-11-18T17:11:00+09:00"
    csv_text = csv_report(report)
    assert "cve_id,status,vendor" in csv_text
    assert "CVE-2026-114941,AFFECTED" in csv_text
    assert "NOT_ASSESSED" in csv_text
    html = html_report(report)
    assert "<!doctype html>" in html.lower()
    assert DISCLAIMER in html
    assert "https://www.oracle.com/security-alerts/cspunov2026.html" in html
    assert "NOT_ASSESSED" in html


def test_html_contains_complete_overview_asset_and_finding_detail(database, asset_factory):
    asset = asset_factory("1.8.0_513-b04", path="C:/Program Files/Java/jre8")
    asset.evidence.extend(["release file", "package metadata"])
    report = _report(database, asset)
    html = html_report(report)
    for expected in [
        "test-host",
        "Windows / 11 / AMD64",
        "2026-11-18T17:11:00+09:00",
        "2026-11-18T17:11:09+09:00",
        database["database_version"],
        "C:/Program Files/Java/jre8",
        "release file",
        "package metadata",
        "update=513",
        "build=4",
        "CVE 판정 상세",
        "판정 근거",
        "신뢰도",
        "권고 사항",
        "탐색 오류 및 미확인 영역",
    ]:
        assert expected in html


def test_html_print_controls_and_a4_css_are_self_contained(database, asset_factory):
    html = html_report(_report(database, asset_factory("21.0.13.0.3")))
    lowered = html.lower()
    assert "PDF로 저장 / 인쇄" in html
    assert "브라우저 인쇄 창" in html
    assert "window.print()" in html
    assert "@page" in html
    assert "size:a4portrait" in lowered.replace(" ", "")
    assert "@media print" in lowered
    assert ".no-print" in html
    assert "display:table-header-group" in lowered.replace(" ", "")
    assert "page-break-inside:avoid" in lowered.replace(" ", "")
    assert "overflow-wrap:anywhere" in lowered.replace(" ", "")
    assert "word-break:break-all" in lowered.replace(" ", "")
    assert "맑은 고딕" in html
    assert "print-color-adjust:exact" in lowered.replace(" ", "")
    assert "<link" not in lowered
    assert " src=" not in lowered


def test_report_escapes_content_and_blocks_unsafe_url_schemes(database, asset_factory):
    asset = asset_factory("21.0.13.0.3", path='=cmd|"<script>alert(1)</script>')
    asset.evidence.append('<img src=x onerror="alert(2)">')
    report = _report(database, asset)
    report.environment["hostname"] = '<svg onload="alert(3)">'
    report.sources.append("javascript:alert(4)")
    report.findings[0].advisory_urls.append("data:text/html,bad")
    html = html_report(report)
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert "<svg onload" not in html
    assert 'href="javascript:' not in html
    assert 'href="data:' not in html
    assert "차단된 링크" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "'=cmd" in csv_report(report)


def test_html_handles_no_java_and_many_rows(database, asset_factory):
    report = _report(database, asset_factory("21.0.13.0.3"))
    report.assets = []
    report.findings = []
    empty = html_report(report)
    assert "탐지된 Java 자산이 없습니다" in empty
    assert "CVE 판정 결과가 없습니다" in empty

    report = _report(database, asset_factory("21.0.13.0.3"))
    report.assets = report.assets * 15
    report.findings = report.findings * 15
    many = html_report(report)
    assert many.count("CVE-2026-") > 20
    assert "thead { display:table-header-group; }" in many


def test_csv_includes_scan_errors_and_incomplete_reason(database, asset_factory):
    report = _report(database, asset_factory("21.0.13.0.3"))
    report.errors.append("권한 오류 fixture")
    report.scope["incomplete"] = True
    report.scope["limit_reasons"] = ["timeout"]
    output = csv_report(report)
    assert "SCAN_ERROR" in output
    assert "권한 오류 fixture" in output
    assert "SCAN_INCOMPLETE" in output
    assert "timeout" in output
