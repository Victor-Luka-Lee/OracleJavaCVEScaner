from __future__ import annotations

from datetime import datetime
from io import StringIO
import json
from pathlib import Path

import pytest

from jvi import autorun
from jvi.advisory import AdvisoryDataError
from jvi.autorun import AutoExitCode
from jvi.discovery import DiscoveryResult


FIXED_NOW = datetime(2026, 11, 18, 17, 11, 0)
ENVIRONMENT = {
    "os": "Windows",
    "os_release": "11",
    "architecture": "AMD64",
    "python": "3.12.10",
    "hostname": "server/한글 01",
}


def _result(*, assets=None, errors=None, stopped=False, incomplete=False, reasons=None):
    return DiscoveryResult(
        assets=assets or [],
        errors=errors or [],
        examined_entries=17,
        stopped=stopped,
        incomplete=incomplete,
        limit_reasons=reasons or [],
        roots=["C:\\Program Files", "C:\\Program Files (x86)"],
    )


def _prepare(monkeypatch, database, discovery_result, captured_config=None):
    monkeypatch.setattr(autorun, "load_database", lambda *args, **kwargs: database)
    monkeypatch.setattr(autorun, "environment_summary", lambda: dict(ENVIRONMENT))

    def fake_discover(config, **kwargs):
        if captured_config is not None:
            captured_config.append(config)
        return discovery_result

    monkeypatch.setattr("jvi.workflow.discover", fake_discover)


def _run(tmp_path, monkeypatch, database, discovery_result, *, fallback=None, captured_config=None):
    _prepare(monkeypatch, database, discovery_result, captured_config)
    stdout = StringIO()
    stderr = StringIO()
    code = autorun.run_automatic_scan(
        primary_dir=tmp_path,
        fallback_dir=fallback,
        now=FIXED_NOW,
        stdout=stdout,
        stderr=stderr,
    )
    return code, stdout.getvalue(), stderr.getvalue()


def test_no_argument_workflow_uses_bounded_extended_defaults(tmp_path, monkeypatch, database):
    configs = []
    code, output, errors = _run(
        tmp_path,
        monkeypatch,
        database,
        _result(),
        captured_config=configs,
    )
    assert code == AutoExitCode.COMPLETE
    assert errors == ""
    config = configs[0]
    assert config.mode == "extended"
    assert config.max_depth == 7
    assert config.max_files == 100_000
    assert config.timeout_seconds == 180
    assert config.follow_symlinks is False
    assert config.allow_java_execution is False
    assert config.collect_package_info is True
    assert "[1/4] 시스템 환경 확인" in output
    assert "[2/4] Java 설치 정보 탐색" in output
    assert "[3/4] CVE 취약점 분석" in output
    assert "[4/4] 보고서 생성" in output


def test_java_absent_still_saves_all_reports(tmp_path, monkeypatch, database):
    code, output, _ = _run(tmp_path, monkeypatch, database, _result())
    assert code == AutoExitCode.COMPLETE
    report_dir = tmp_path / "reports"
    files = sorted(path.name for path in report_dir.iterdir())
    assert files == [
        "JVI_SERVER_01_20261118_171100.csv",
        "JVI_SERVER_01_20261118_171100.html",
        "JVI_SERVER_01_20261118_171100.json",
        "JVI_SERVER_01_20261118_171100.log",
    ]
    payload = json.loads((report_dir / "JVI_SERVER_01_20261118_171100.json").read_text(encoding="utf-8"))
    assert payload["assets"] == []
    assert payload["scope"]["automatic_mode"] is True
    assert "탐지된 Java 자산: 0개" in output
    assert "전체 CVE 판정: 0건" in output


def test_multiple_java_installations_and_affected_exit(
    tmp_path, monkeypatch, database, asset_factory
):
    assets = [
        asset_factory("17.0.21.0.3", path="C:/Java/oracle17"),
        asset_factory(
            "21.0.13.0.3",
            vendor="Eclipse Adoptium",
            product="OpenJDK",
            distribution="Eclipse Temurin",
            path="C:/Java/temurin21",
        ),
    ]
    code, output, _ = _run(tmp_path, monkeypatch, database, _result(assets=assets))
    assert code == AutoExitCode.AFFECTED
    assert "탐지된 Java 자산: 2개" in output
    assert "전체 CVE 판정: 12건" in output
    assert "CVE 영향 확인(AFFECTED): 3건" in output


def test_timeout_is_partial_not_success(tmp_path, monkeypatch, database):
    result = _result(stopped=True, incomplete=True, reasons=["timeout"])
    code, output, _ = _run(tmp_path, monkeypatch, database, result)
    assert code == AutoExitCode.PARTIAL
    assert "일부 점검 미완료" in output
    assert "탐색 제한 도달: timeout" in output
    assert " 점검 완료\n" not in output


def test_report_directory_falls_back_when_primary_is_not_writable(
    tmp_path, monkeypatch, database
):
    fallback = tmp_path / "user-state" / "JVI" / "reports"
    original = autorun._ensure_writable_directory

    def guarded(path):
        if path == tmp_path / "reports":
            raise PermissionError("read only")
        return original(path)

    monkeypatch.setattr(autorun, "_ensure_writable_directory", guarded)
    code, output, _ = _run(tmp_path, monkeypatch, database, _result(), fallback=fallback)
    assert code == AutoExitCode.COMPLETE
    assert fallback.is_dir()
    assert len(list(fallback.glob("JVI_*"))) == 4
    assert "사용자별 보고서 경로로 전환" in output


def test_report_directory_total_permission_failure_is_fatal(
    tmp_path, monkeypatch, database
):
    monkeypatch.setattr(autorun, "environment_summary", lambda: dict(ENVIRONMENT))
    monkeypatch.setattr(
        autorun,
        "_ensure_writable_directory",
        lambda path: (_ for _ in ()).throw(PermissionError("denied")),
    )
    stdout, stderr = StringIO(), StringIO()
    code = autorun.run_automatic_scan(
        primary_dir=tmp_path,
        fallback_dir=tmp_path / "fallback",
        now=FIXED_NOW,
        stdout=stdout,
        stderr=stderr,
    )
    assert code == AutoExitCode.FATAL_ERROR
    assert "보고서를 저장할 수 없습니다" in stderr.getvalue()
    assert "점검 완료" not in stdout.getvalue()


def test_database_error_is_logged_and_never_reported_as_success(tmp_path, monkeypatch):
    monkeypatch.setattr(autorun, "environment_summary", lambda: dict(ENVIRONMENT))
    monkeypatch.setattr(
        autorun,
        "load_database",
        lambda *args, **kwargs: (_ for _ in ()).throw(AdvisoryDataError("bad checksum")),
    )
    stdout, stderr = StringIO(), StringIO()
    code = autorun.run_automatic_scan(
        primary_dir=tmp_path,
        now=FIXED_NOW,
        stdout=stdout,
        stderr=stderr,
    )
    assert code == AutoExitCode.FATAL_ERROR
    assert "취약점 DB 오류" in stderr.getvalue()
    assert "점검 완료" not in stdout.getvalue()
    log = next((tmp_path / "reports").glob("*.log"))
    assert "bad checksum" in log.read_text(encoding="utf-8")


def test_unexpected_scan_exception_is_logged(tmp_path, monkeypatch, database):
    monkeypatch.setattr(autorun, "load_database", lambda *args, **kwargs: database)
    monkeypatch.setattr(autorun, "environment_summary", lambda: dict(ENVIRONMENT))
    monkeypatch.setattr(
        "jvi.workflow.discover",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("scanner exploded")),
    )
    stdout, stderr = StringIO(), StringIO()
    code = autorun.run_automatic_scan(
        primary_dir=tmp_path,
        now=FIXED_NOW,
        stdout=stdout,
        stderr=stderr,
    )
    assert code == AutoExitCode.FATAL_ERROR
    assert "예기치 않은 오류" in stderr.getvalue()
    assert "점검 완료" not in stdout.getvalue()
    assert "scanner exploded" in next((tmp_path / "reports").glob("*.log")).read_text(encoding="utf-8")


def test_report_filename_collision_never_overwrites(tmp_path):
    directory = tmp_path / "reports"
    directory.mkdir()
    first = autorun.reserve_report_paths(directory, "host", FIXED_NOW)
    second = autorun.reserve_report_paths(directory, "host", FIXED_NOW)
    try:
        assert first.stem == "JVI_HOST_20261118_171100"
        assert second.stem == "JVI_HOST_20261118_171100_01"
    finally:
        first.release()
        second.release()


def test_windows_and_linux_user_report_paths(tmp_path):
    windows = autorun.user_report_directory(
        platform_name="win32",
        environ={"LOCALAPPDATA": str(tmp_path / "Local")},
        home=tmp_path,
    )
    linux_xdg = autorun.user_report_directory(
        platform_name="linux",
        environ={"XDG_STATE_HOME": str(tmp_path / "state")},
        home=tmp_path,
    )
    linux_default = autorun.user_report_directory(
        platform_name="linux", environ={}, home=tmp_path
    )
    assert windows == tmp_path / "Local" / "JVI" / "reports"
    assert linux_xdg == tmp_path / "state" / "JVI" / "reports"
    assert linux_default == tmp_path / ".local" / "state" / "JVI" / "reports"


def test_hostname_is_safe_for_filename():
    assert autorun.safe_hostname("../../서버 name:01") == "NAME_01"
    assert autorun.safe_hostname("한글") == "HOST"
