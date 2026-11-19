from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path

import pytest

from jvi import autorun
from jvi.advisory import AdvisoryDataError
from jvi.autorun import AutoExitCode
from jvi.discovery import DiscoveryIssue, DiscoveryResult, SkippedPath


FIXED_NOW = datetime(2026, 11, 18, 17, 11, 0)
ENVIRONMENT = {
    "os": "Windows",
    "os_release": "11",
    "architecture": "AMD64",
    "python": "3.12.10",
    "hostname": "server/한글 01",
}


def _result(
    *,
    assets=None,
    errors=None,
    stopped=False,
    incomplete=False,
    reasons=None,
    issues=None,
    skipped_paths=None,
    root_links=None,
):
    issue_values = issues or []
    return DiscoveryResult(
        assets=assets or [],
        errors=errors if errors is not None else [item.summary() for item in issue_values],
        examined_entries=17,
        stopped=stopped,
        incomplete=incomplete,
        limit_reasons=reasons or [],
        roots=["C:\\Program Files", "C:\\Program Files (x86)"],
        issues=issue_values,
        skipped_paths=skipped_paths or [],
        root_links=root_links or [],
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
    for step in range(1, 6):
        assert f"[{step}/5]" in output


def test_java_absent_saves_one_html_in_unique_run_directory(tmp_path, monkeypatch, database):
    code, output, _ = _run(tmp_path, monkeypatch, database, _result())
    assert code == AutoExitCode.COMPLETE
    run_dir = tmp_path / "reports" / "2026-11-18_17-11-00"
    assert [path.name for path in run_dir.iterdir()] == ["JVI_SERVER_01.html"]
    html = (run_dir / "JVI_SERVER_01.html").read_text(encoding="utf-8")
    assert "탐지된 Java 자산이 없습니다" in html
    assert "SERVER" not in html  # environment keeps the original host text, safely escaped
    assert "server/한글 01" in html
    assert "탐지된 Java 자산: 0개" in output
    assert "전체 CVE 판정: 0건" in output
    assert not list(run_dir.glob("*.json"))
    assert not list(run_dir.glob("*.csv"))
    assert not list(run_dir.glob("*.log"))


def test_multiple_java_installations_and_affected_exit(tmp_path, monkeypatch, database, asset_factory):
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


def test_normally_skipped_junction_does_not_make_one_click_partial(tmp_path, monkeypatch, database):
    result = _result(
        skipped_paths=[
            SkippedPath(
                path=r"C:\Program Files\Windows NT\보조프로그램",
                path_type="junction",
                reason="link_not_followed",
                reparse_tag=0xA0000003,
            )
        ]
    )
    code, output, errors = _run(tmp_path, monkeypatch, database, result)
    assert code == AutoExitCode.COMPLETE
    assert " 점검 완료" in output
    assert "정상 제외된 연결 디렉터리: 1개" in output
    assert "실제 접근 권한 오류: 0건" in output
    assert errors == ""


def test_real_permission_issue_keeps_one_click_partial(tmp_path, monkeypatch, database):
    issue = DiscoveryIssue(
        category="permission",
        path=r"C:\Program Files\RestrictedJava",
        operation="디렉터리 열기",
        error_type="PermissionError",
        message="access denied",
    )
    result = _result(issues=[issue], incomplete=True)
    code, output, errors = _run(tmp_path, monkeypatch, database, result)
    assert code == AutoExitCode.PARTIAL
    assert "일부 점검 미완료" in output
    assert "실제 접근 권한 오류: 1건" in output
    assert "RestrictedJava" in errors


def test_report_directory_falls_back_when_primary_is_not_writable(tmp_path, monkeypatch, database):
    fallback = tmp_path / "user-state" / "JVI" / "reports"
    original = autorun._ensure_writable_directory

    def guarded(path):
        if path == tmp_path / "reports":
            raise PermissionError("read only")
        return original(path)

    monkeypatch.setattr(autorun, "_ensure_writable_directory", guarded)
    code, output, _ = _run(tmp_path, monkeypatch, database, _result(), fallback=fallback)
    assert code == AutoExitCode.COMPLETE
    assert (fallback / "2026-11-18_17-11-00" / "JVI_SERVER_01.html").is_file()
    assert "사용자별 보고서 경로로 전환" in output


def test_report_directory_total_permission_failure_is_fatal(tmp_path, monkeypatch):
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


def test_database_error_never_reports_success(tmp_path, monkeypatch):
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
    assert "bad checksum" in stderr.getvalue()
    assert "점검 완료" not in stdout.getvalue()


def test_unexpected_scan_exception_is_reported(tmp_path, monkeypatch, database):
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
    assert "scanner exploded" in stderr.getvalue()
    assert "점검 완료" not in stdout.getvalue()


def test_run_directory_collision_is_atomic_and_preserves_existing_content(tmp_path):
    report_root = tmp_path / "reports"
    report_root.mkdir()
    first = autorun.reserve_report_directory(report_root, "host", FIXED_NOW)
    marker = first.directory / "keep.txt"
    marker.write_text("preserve", encoding="utf-8")
    second = autorun.reserve_report_directory(report_root, "host", FIXED_NOW)
    assert first.directory.name == "2026-11-18_17-11-00"
    assert second.directory.name == "2026-11-18_17-11-00_001"
    assert marker.read_text(encoding="utf-8") == "preserve"


def test_concurrent_run_directory_reservations_are_unique(tmp_path):
    report_root = tmp_path / "reports"
    report_root.mkdir()
    with ThreadPoolExecutor(max_workers=8) as pool:
        runs = list(
            pool.map(
                lambda _: autorun.reserve_report_directory(report_root, "host", FIXED_NOW),
                range(20),
            )
        )
    names = {run.directory.name for run in runs}
    assert len(names) == 20
    assert "2026-11-18_17-11-00" in names
    assert "2026-11-18_17-11-00_019" in names


def test_different_scan_times_use_different_directories(tmp_path):
    report_root = tmp_path / "reports"
    report_root.mkdir()
    first = autorun.reserve_report_directory(report_root, "host", FIXED_NOW)
    second = autorun.reserve_report_directory(report_root, "host", FIXED_NOW + timedelta(seconds=1))
    assert first.directory.name != second.directory.name


def test_windows_linux_and_unicode_report_paths(tmp_path):
    windows = autorun.user_report_directory(
        platform_name="win32",
        environ={"LOCALAPPDATA": str(tmp_path / "Local Data")},
        home=tmp_path,
    )
    linux_xdg = autorun.user_report_directory(
        platform_name="linux",
        environ={"XDG_STATE_HOME": str(tmp_path / "상태 공간")},
        home=tmp_path,
    )
    linux_default = autorun.user_report_directory(platform_name="linux", environ={}, home=tmp_path)
    assert windows == tmp_path / "Local Data" / "JVI" / "reports"
    assert linux_xdg == tmp_path / "상태 공간" / "JVI" / "reports"
    assert linux_default == tmp_path / ".local" / "state" / "JVI" / "reports"
    windows.mkdir(parents=True)
    run = autorun.reserve_report_directory(windows, "서버 name", FIXED_NOW)
    assert run.directory.is_dir()


def test_execution_directory_uses_executable_when_frozen(monkeypatch, tmp_path):
    executable = tmp_path / "JVI.exe"
    executable.write_bytes(b"")
    monkeypatch.setattr(autorun.sys, "frozen", True, raising=False)
    monkeypatch.setattr(autorun.sys, "executable", str(executable))
    monkeypatch.setattr(autorun.sys, "_MEIPASS", str(tmp_path / "_MEI123"), raising=False)
    assert autorun.execution_directory() == tmp_path


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../서버 name:01", "NAME_01"),
        ("한글", "HOST"),
        ("CON", "HOST_CON"),
        ("LPT1.txt", "HOST_LPT1.TXT"),
    ],
)
def test_hostname_is_safe_for_filename(raw, expected):
    assert autorun.safe_hostname(raw) == expected
