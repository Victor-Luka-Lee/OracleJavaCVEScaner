"""One-click, no-argument local scan orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
import os
from pathlib import Path
import re
import sys
import time
import traceback
from typing import Mapping, TextIO
import unicodedata

from .advisory import AdvisoryDataError, DEFAULT_ADVISORY, load_database
from .discovery import ScanConfig, environment_summary
from .models import ScanReport, Status
from .reporting import write_report
from .workflow import execute_scan


class AutoExitCode(IntEnum):
    COMPLETE = 0
    AFFECTED = 1
    FATAL_ERROR = 2
    PARTIAL = 3
    AFFECTED_PARTIAL = 4


class ReportDirectoryError(OSError):
    """Raised when neither the primary nor fallback report root is writable."""


@dataclass(frozen=True, slots=True)
class ReportRun:
    """A uniquely reserved directory for one automatic scan."""

    root: Path
    directory: Path
    html: Path


class RunLogger:
    """Write Korean progress messages to the supplied console streams."""

    def __init__(self, stdout: TextIO, stderr: TextIO) -> None:
        self.stdout = stdout
        self.stderr = stderr

    def emit(self, message: str = "", *, error: bool = False) -> None:
        print(message, file=self.stderr if error else self.stdout, flush=True)

    def exception(self, context: str, exc: BaseException) -> None:
        self.emit(f"{context}: {exc.__class__.__name__}: {exc}", error=True)
        detail = "".join(traceback.format_exception(exc)).rstrip()
        self.emit(detail, error=True)


_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CLOCK$",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


def safe_hostname(value: str) -> str:
    """Normalize an untrusted hostname into a portable file-name component."""
    normalized = unicodedata.normalize("NFKD", value or "")
    ascii_name = normalized.encode("ascii", "ignore").decode("ascii")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", ascii_name).strip("._-")
    safe = (safe[:64] or "HOST").upper()
    if safe.split(".", 1)[0] in _WINDOWS_RESERVED_NAMES:
        safe = f"HOST_{safe}"
    return safe


def execution_directory() -> Path:
    """Return the source/launcher directory, never a PyInstaller _MEIPASS path."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    argv0 = Path(sys.argv[0]) if sys.argv else Path()
    if argv0.name.lower() not in {"", "__main__.py"} and argv0.exists():
        return argv0.resolve().parent
    return Path.cwd().resolve()


def user_report_directory(
    *,
    platform_name: str | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    env = os.environ if environ is None else environ
    user_home = Path.home() if home is None else home
    name = (platform_name or sys.platform).lower()
    if name.startswith("win"):
        base = Path(env.get("LOCALAPPDATA", str(user_home / "AppData" / "Local")))
    else:
        state = env.get("XDG_STATE_HOME")
        base = Path(state).expanduser() if state else user_home / ".local" / "state"
        if not base.is_absolute():
            base = user_home / base
    return base / "JVI" / "reports"


def _ensure_writable_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    probe = path / f".jvi-write-test-{os.getpid()}"
    descriptor = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    os.close(descriptor)
    probe.unlink()


def select_report_directory(primary_base: Path, fallback: Path | None = None) -> tuple[Path, list[str]]:
    """Choose the report root, falling back to a per-user state directory."""
    warnings: list[str] = []
    primary = primary_base / "reports"
    try:
        _ensure_writable_directory(primary)
        return primary, warnings
    except OSError as exc:
        warnings.append(f"기본 보고서 경로 사용 불가: {primary} ({exc.__class__.__name__})")
    secondary = fallback or user_report_directory()
    try:
        _ensure_writable_directory(secondary)
        warnings.append(f"사용자별 보고서 경로로 전환: {secondary}")
        return secondary, warnings
    except OSError as exc:
        raise ReportDirectoryError(
            f"보고서를 저장할 수 없습니다. 기본 경로={primary}, 사용자 경로={secondary}: {exc}"
        ) from exc


def reserve_report_directory(report_root: Path, hostname: str, when: datetime) -> ReportRun:
    """Atomically reserve one immutable scan directory without overwriting data."""
    base = when.strftime("%Y-%m-%d_%H-%M-%S")
    for number in range(10_000):
        name = base if number == 0 else f"{base}_{number:03d}"
        directory = report_root / name
        try:
            directory.mkdir(exist_ok=False)
        except FileExistsError:
            continue
        return ReportRun(
            root=report_root,
            directory=directory,
            html=directory / f"JVI_{safe_hostname(hostname)}.html",
        )
    raise FileExistsError(f"사용 가능한 보고서 실행 폴더를 만들 수 없습니다: {base}")


def automatic_scan_config() -> ScanConfig:
    return ScanConfig(
        mode="extended",
        max_depth=7,
        max_files=100_000,
        timeout_seconds=180.0,
        follow_symlinks=False,
        allow_java_execution=False,
        collect_package_info=True,
    )


def _summary(logger: RunLogger, report: ScanReport, run: ReportRun, elapsed: float) -> None:
    counts = {status: 0 for status in Status}
    for finding in report.findings:
        counts[finding.status] += 1
    incomplete = bool(report.scope.get("incomplete") or report.errors)
    logger.emit("")
    logger.emit("========================================")
    logger.emit(" 일부 점검 미완료" if incomplete else " 점검 완료")
    logger.emit("========================================")
    logger.emit(f"탐지된 Java 자산: {len(report.assets)}개")
    logger.emit(f"전체 CVE 판정: {len(report.findings)}건")
    logger.emit(f"CVE 영향 확인(AFFECTED): {counts[Status.AFFECTED]}건")
    logger.emit(f"수정 확인(FIXED): {counts[Status.FIXED]}건")
    logger.emit(f"잠재 영향(POTENTIALLY_AFFECTED): {counts[Status.POTENTIALLY_AFFECTED]}건")
    logger.emit(
        "판정 불가 및 미평가: "
        f"UNKNOWN {counts[Status.UNKNOWN]}건 + NOT_ASSESSED {counts[Status.NOT_ASSESSED]}건"
    )
    logger.emit(f"탐색 오류: {len(report.errors)}건")
    reasons = report.scope.get("limit_reasons") or []
    logger.emit(f"탐색 제한 도달: {', '.join(str(item) for item in reasons) if reasons else '없음'}")
    logger.emit(f"점검 소요 시간: {elapsed:.2f}초")
    logger.emit(f"보고서 실행 폴더: {run.directory}")
    logger.emit(f"HTML 보고서: {run.html}")


def _exit_code(report: ScanReport) -> AutoExitCode:
    affected = any(item.status == Status.AFFECTED for item in report.findings)
    partial = bool(report.scope.get("incomplete") or report.errors)
    if affected and partial:
        return AutoExitCode.AFFECTED_PARTIAL
    if partial:
        return AutoExitCode.PARTIAL
    if affected:
        return AutoExitCode.AFFECTED
    return AutoExitCode.COMPLETE


def run_automatic_scan(
    *,
    primary_dir: Path | None = None,
    fallback_dir: Path | None = None,
    now: datetime | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the no-input, extended assessment and save one self-contained HTML report."""
    monotonic_started = time.monotonic()
    scan_started = now or datetime.now().astimezone()
    logger = RunLogger(stdout or sys.stdout, stderr or sys.stderr)
    logger.emit("========================================")
    logger.emit(" Java Vulnerability Inspector")
    logger.emit(" Oracle Java CVE Scanner")
    logger.emit("========================================")
    logger.emit("")
    logger.emit("[1/5] 시스템 환경 및 취약점 DB 확인")
    environment = environment_summary()
    logger.emit(
        f"운영체제: {environment.get('os', 'UNKNOWN')} {environment.get('os_release', '')} / "
        f"아키텍처: {environment.get('architecture', 'UNKNOWN')}"
    )
    logger.emit(f"호스트명: {environment.get('hostname', 'UNKNOWN')}")

    try:
        report_root, warnings = select_report_directory(
            primary_dir or execution_directory(), fallback=fallback_dir
        )
        for warning in warnings:
            logger.emit(warning)
        logger.emit("취약점 DB 로드 및 SHA-256 무결성 검증")
        database = load_database(DEFAULT_ADVISORY, verify_integrity=True)
        logger.emit(f"취약점 DB 버전: {database['database_version']}")
        printed: set[str] = set()

        def phase(name: str) -> None:
            if name == "discovery" and name not in printed:
                logger.emit("[2/5] Java 설치 정보 탐색")
                printed.add(name)
            elif name == "evaluation" and name not in printed:
                logger.emit("[3/5] CVE 취약점 분석")
                printed.add(name)

        report = execute_scan(
            automatic_scan_config(),
            database,
            phase=phase,
            environment=environment,
            started_at=scan_started,
        )
        report.scope["automatic_mode"] = True
        for scan_error in report.errors:
            logger.emit(f"탐색 오류: {scan_error}", error=True)
        if report.scope.get("incomplete"):
            reasons = report.scope.get("limit_reasons") or ["access_errors"]
            logger.emit(f"일부 점검 미완료: {', '.join(str(item) for item in reasons)}")

        logger.emit("[4/5] 보고서 폴더 생성 및 HTML 저장")
        run = reserve_report_directory(
            report_root,
            environment.get("hostname", "HOST"),
            scan_started,
        )
        report.scope["report_directory"] = str(run.directory)
        write_report(report, "html", run.html, overwrite=False)
        logger.emit("[5/5] 결과 요약 및 저장 위치 안내")
        elapsed = time.monotonic() - monotonic_started
        _summary(logger, report, run, elapsed)
        return int(_exit_code(report))
    except AdvisoryDataError as exc:
        logger.exception("취약점 DB 오류로 자동 점검 실패", exc)
        return int(AutoExitCode.FATAL_ERROR)
    except (OSError, ReportDirectoryError) as exc:
        logger.exception("보고서 또는 파일 시스템 오류로 자동 점검 실패", exc)
        return int(AutoExitCode.FATAL_ERROR)
    except Exception as exc:
        logger.exception("예기치 않은 오류로 자동 점검 실패", exc)
        return int(AutoExitCode.FATAL_ERROR)
