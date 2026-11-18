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
    pass


@dataclass(frozen=True, slots=True)
class ReportPaths:
    directory: Path
    stem: str
    html: Path
    json: Path
    csv: Path
    log: Path
    reservation: Path

    def release(self) -> None:
        try:
            self.reservation.unlink(missing_ok=True)
        except OSError:
            pass


class RunLogger:
    """Mirror Korean console progress into a UTF-8 execution log."""

    def __init__(self, stdout: TextIO, stderr: TextIO) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self._history: list[tuple[str, str]] = []
        self._handle: TextIO | None = None

    def attach(self, path: Path) -> None:
        self._handle = path.open("x", encoding="utf-8", newline="")
        for level, message in self._history:
            self._write_log(level, message)

    def _write_log(self, level: str, message: str) -> None:
        if self._handle is None:
            return
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        self._handle.write(f"{stamp} {level} {message}\n")
        self._handle.flush()

    def emit(self, message: str = "", *, error: bool = False) -> None:
        level = "ERROR" if error else "INFO"
        print(message, file=self.stderr if error else self.stdout, flush=True)
        self._history.append((level, message))
        self._write_log(level, message)

    def exception(self, context: str, exc: BaseException) -> None:
        self.emit(f"{context}: {exc.__class__.__name__}: {exc}", error=True)
        detail = "".join(traceback.format_exception(exc)).rstrip()
        self._history.append(("TRACE", detail))
        self._write_log("TRACE", detail)

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None


def safe_hostname(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value or "")
    ascii_name = normalized.encode("ascii", "ignore").decode("ascii")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", ascii_name).strip("._-")
    return (safe[:64] or "HOST").upper()


def execution_directory() -> Path:
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


def reserve_report_paths(directory: Path, hostname: str, when: datetime) -> ReportPaths:
    base = f"JVI_{safe_hostname(hostname)}_{when.strftime('%Y%m%d_%H%M%S')}"
    for number in range(10_000):
        stem = base if number == 0 else f"{base}_{number:02d}"
        outputs = {suffix: directory / f"{stem}.{suffix}" for suffix in ("html", "json", "csv", "log")}
        if any(path.exists() for path in outputs.values()):
            continue
        reservation = directory / f".{stem}.lock"
        try:
            descriptor = os.open(reservation, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(descriptor)
        except FileExistsError:
            continue
        return ReportPaths(
            directory=directory,
            stem=stem,
            html=outputs["html"],
            json=outputs["json"],
            csv=outputs["csv"],
            log=outputs["log"],
            reservation=reservation,
        )
    raise FileExistsError(f"사용 가능한 보고서 파일명을 만들 수 없습니다: {base}")


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


def _summary(logger: RunLogger, report: ScanReport, paths: ReportPaths, elapsed: float) -> None:
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
    logger.emit(f"잠재 영향(POTENTIALLY_AFFECTED): {counts[Status.POTENTIALLY_AFFECTED]}건")
    logger.emit(
        "판정 불가 및 미평가: "
        f"UNKNOWN {counts[Status.UNKNOWN]}건 + NOT_ASSESSED {counts[Status.NOT_ASSESSED]}건"
    )
    logger.emit(f"탐색 오류: {len(report.errors)}건")
    reasons = report.scope.get("limit_reasons") or []
    logger.emit(f"탐색 제한 도달: {', '.join(reasons) if reasons else '없음'}")
    logger.emit(f"점검 소요 시간: {elapsed:.2f}초")
    logger.emit(f"HTML 보고서: {paths.html}")
    logger.emit(f"JSON 보고서: {paths.json}")
    logger.emit(f"CSV 보고서: {paths.csv}")
    logger.emit(f"실행 로그: {paths.log}")


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
    """Run the no-input, extended local assessment and save four artifacts."""
    started = time.monotonic()
    logger = RunLogger(stdout or sys.stdout, stderr or sys.stderr)
    paths: ReportPaths | None = None
    logger.emit("========================================")
    logger.emit(" Java Vulnerability Inspector")
    logger.emit(" Oracle Java CVE Scanner")
    logger.emit("========================================")
    logger.emit("")
    logger.emit("[1/4] 시스템 환경 확인")
    environment = environment_summary()
    logger.emit(
        f"운영체제: {environment.get('os', 'UNKNOWN')} {environment.get('os_release', '')} / "
        f"아키텍처: {environment.get('architecture', 'UNKNOWN')}"
    )
    logger.emit(f"호스트명: {environment.get('hostname', 'UNKNOWN')}")

    try:
        report_dir, warnings = select_report_directory(
            primary_dir or execution_directory(), fallback=fallback_dir
        )
        paths = reserve_report_paths(
            report_dir,
            environment.get("hostname", "HOST"),
            now or datetime.now().astimezone(),
        )
        logger.attach(paths.log)
        for warning in warnings:
            logger.emit(warning)

        logger.emit("취약점 DB 로드 및 SHA-256 무결성 검증")
        database = load_database(DEFAULT_ADVISORY, verify_integrity=True)
        logger.emit(f"취약점 DB 버전: {database['database_version']}")
        printed: set[str] = set()

        def phase(name: str) -> None:
            if name == "discovery" and name not in printed:
                logger.emit("[2/4] Java 설치 정보 탐색")
                printed.add(name)
            elif name == "evaluation" and name not in printed:
                logger.emit("[3/4] CVE 취약점 분석")
                printed.add(name)

        report = execute_scan(
            automatic_scan_config(),
            database,
            phase=phase,
            environment=environment,
        )
        report.scope["automatic_mode"] = True
        report.scope["report_directory"] = str(report_dir)
        for scan_error in report.errors:
            logger.emit(f"탐색 오류: {scan_error}", error=True)
        if report.scope.get("incomplete"):
            reasons = report.scope.get("limit_reasons") or ["access_errors"]
            logger.emit(f"일부 점검 미완료: {', '.join(reasons)}")
        logger.emit("[4/4] 보고서 생성")
        write_report(report, "html", paths.html, overwrite=False)
        write_report(report, "json", paths.json, overwrite=False)
        write_report(report, "csv", paths.csv, overwrite=False)
        elapsed = time.monotonic() - started
        _summary(logger, report, paths, elapsed)
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
    finally:
        logger.close()
        if paths is not None:
            paths.release()
