from datetime import datetime, timezone
import json

import pytest

from jvi import cli
from jvi.cli import _human_summary
from jvi.cli import _parser, main
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


def test_no_arguments_enters_automatic_mode(monkeypatch):
    monkeypatch.setattr("jvi.autorun.run_automatic_scan", lambda: 3)
    assert main([]) == 3


def test_help_does_not_enter_automatic_mode(monkeypatch, capsys):
    called = False

    def unexpected():
        nonlocal called
        called = True
        return 0

    monkeypatch.setattr("jvi.autorun.run_automatic_scan", unexpected)
    with pytest.raises(SystemExit) as raised:
        main(["--help"])
    assert raised.value.code == 0
    assert called is False
    assert "Java Vulnerability Inspector" in capsys.readouterr().out


def test_existing_scan_and_ui_commands_still_parse():
    parser = _parser()
    quick = parser.parse_args(["scan", "--quick"])
    extended = parser.parse_args(["scan", "--extended"])
    custom = parser.parse_args(["scan", "--path", "/usr/lib/jvm"])
    ui = parser.parse_args(["ui"])
    assert quick.command == extended.command == custom.command == "scan"
    assert quick.quick is True
    assert extended.extended is True
    assert custom.path == ["/usr/lib/jvm"]
    assert ui.command == "ui"


@pytest.mark.parametrize(("format_name", "suffix"), [("json", ".json"), ("csv", ".csv")])
def test_explicit_cli_json_and_csv_output_remain_available(
    tmp_path, monkeypatch, database, asset_factory, format_name, suffix
):
    asset = asset_factory("21.0.13.0.3")
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
    monkeypatch.setattr(cli, "build_report", lambda args: report)
    output = tmp_path / f"explicit{suffix}"
    assert main(["scan", "--quick", "--format", format_name, "--output", str(output)]) == 0
    assert output.is_file()
    if format_name == "json":
        assert json.loads(output.read_text(encoding="utf-8"))["assets"][0]["full_version"] == "21.0.13.0.3"
    else:
        assert "cve_id,status,vendor" in output.read_text(encoding="utf-8")
