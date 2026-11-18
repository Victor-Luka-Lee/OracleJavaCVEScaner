from datetime import datetime, timezone
import json

from jvi.engine import evaluate_asset
from jvi.models import ScanReport
from jvi.reporting import DISCLAIMER, csv_report, html_report, json_report


def _report(database, asset):
    return ScanReport(
        scan_time=datetime.now(timezone.utc).isoformat(),
        environment={"os": "fixture", "hostname": "test"},
        scope={"roots": [asset.install_path]},
        assets=[asset],
        findings=evaluate_asset(asset, database),
        database_version=database["database_version"],
        sources=database["sources"],
        limitations=[DISCLAIMER],
    )


def test_json_csv_html_reports_are_generated(database, asset_factory):
    report = _report(database, asset_factory("21.0.13.0.3"))
    parsed = json.loads(json_report(report))
    assert parsed["assets"][0]["full_version"] == "21.0.13.0.3"
    csv_text = csv_report(report)
    assert "cve_id,status,vendor" in csv_text
    assert "CVE-2026-114941,AFFECTED" in csv_text
    html = html_report(report)
    assert "<!doctype html>" in html.lower()
    assert DISCLAIMER in html
    assert "https://www.oracle.com/security-alerts/cspunov2026.html" in html
    assert "<script" not in html.lower()


def test_report_escapes_paths_and_csv_formulas(database, asset_factory):
    asset = asset_factory("21.0.13.0.3", path='=cmd|\"<script>alert(1)</script>')
    report = _report(database, asset)
    assert "<script>alert" not in html_report(report)
    assert "'=cmd" in csv_report(report)

