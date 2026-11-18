from datetime import datetime, timezone

from jvi.cli import _human_summary
from jvi.engine import evaluate_asset
from jvi.models import ScanReport


def test_human_cli_summary_includes_not_assessed(database, asset_factory):
    asset = asset_factory("1.8.0_401-b10")
    report = ScanReport(
        scan_time=datetime.now(timezone.utc).isoformat(),
        environment={"os": "fixture"},
        scope={"roots": [asset.install_path]},
        assets=[asset],
        findings=evaluate_asset(asset, database),
        database_version=database["database_version"],
        sources=database["sources"],
        limitations=[],
    )
    summary = _human_summary(report)
    assert "NOT_ASSESSED=6" in summary
    assert "CVE-2026-114938: NOT_ASSESSED" in summary
