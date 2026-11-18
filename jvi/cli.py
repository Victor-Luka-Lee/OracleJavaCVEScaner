"""Command line interface for JVI."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
import sys
from typing import Sequence

from .advisory import AdvisoryDataError, DEFAULT_ADVISORY, load_database
from .discovery import ScanConfig
from .models import ScanReport, Status
from .reporting import DISCLAIMER, render, write_report
from .workflow import execute_scan


LOG = logging.getLogger("jvi")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jvi",
        description="Java Vulnerability Inspector",
        epilog="인자 없이 실행하면 제한된 extended 자동 점검과 보고서 저장을 수행합니다.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="로컬 Java 자산을 읽기 전용으로 점검")
    modes = scan.add_mutually_exclusive_group()
    modes.add_argument("--quick", action="store_true", help="PATH/JAVA_HOME 및 표준 Java 위치 점검")
    modes.add_argument("--extended", action="store_true", help="Program Files, /opt, /usr/local까지 확장")
    scan.add_argument("--path", action="append", default=[], metavar="DIR", help="사용자 지정 경로(반복 가능)")
    scan.add_argument("--max-depth", type=int, default=5)
    scan.add_argument("--max-files", type=int, default=50_000)
    scan.add_argument("--timeout", type=float, default=60.0, metavar="SECONDS")
    scan.add_argument("--follow-symlinks", action="store_true", help="순환 감지와 함께 심볼릭 링크 추적")
    scan.add_argument("--allow-java-execution", action="store_true", help="메타데이터가 없을 때 java -version 실행 승인")
    scan.add_argument("--no-package-info", action="store_true", help="Linux 패키지 소유자 조회 생략")
    scan.add_argument("--advisory", default=str(DEFAULT_ADVISORY), help="취약점 JSON 경로")
    scan.add_argument("--no-integrity-check", action="store_true", help="동반 SHA-256 검증 파일 무시")
    scan.add_argument("--format", choices=["human", "json", "csv", "html"], default="human")
    scan.add_argument("--output", help="출력 파일 또는 기존 디렉터리")
    scan.add_argument("--verbose", action="store_true")
    subparsers.add_parser("ui", help="Streamlit 로컬 UI 실행")
    return parser


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.command != "scan":
        return
    if args.max_depth < 0:
        parser.error("--max-depth must be >= 0")
    if args.max_files < 1:
        parser.error("--max-files must be >= 1")
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")


def build_report(args: argparse.Namespace) -> ScanReport:
    database = load_database(args.advisory, verify_integrity=not args.no_integrity_check)
    mode = "extended" if args.extended else "quick"
    config = ScanConfig(
        roots=[Path(item) for item in args.path],
        mode=mode,
        max_depth=args.max_depth,
        max_files=args.max_files,
        timeout_seconds=args.timeout,
        follow_symlinks=args.follow_symlinks,
        allow_java_execution=args.allow_java_execution,
        collect_package_info=not args.no_package_info,
    )
    return execute_scan(
        config,
        database,
        progress=lambda count, path: LOG.debug("examined=%s path=%s", count, path),
    )


def _human_summary(report: ScanReport) -> str:
    counts = {status: 0 for status in Status}
    for finding in report.findings:
        counts[finding.status] += 1
    lines = [
        "Java Vulnerability Inspector (JVI)",
        f"탐지 자산: {len(report.assets)}",
        "판정: " + ", ".join(f"{status.value}={counts[status]}" for status in Status),
        f"취약점 DB: {report.database_version}",
        f"주의: {DISCLAIMER}",
    ]
    for asset in report.assets:
        lines.append(f"- {asset.vendor} / {asset.product} / {asset.full_version or 'UNKNOWN'} / {asset.install_path}")
        for finding in (item for item in report.findings if item.asset is asset):
            if finding.status in {
                Status.AFFECTED,
                Status.POTENTIALLY_AFFECTED,
                Status.NOT_ASSESSED,
                Status.UNKNOWN,
            }:
                lines.append(f"  {finding.cve_id}: {finding.status.value} - {finding.rationale}")
    if report.errors:
        lines.append(f"탐색 오류: {len(report.errors)}건 (--verbose 로그 또는 JSON/HTML 보고서 확인)")
    return "\n".join(lines)


def _run_ui() -> int:
    try:
        from streamlit.web import cli as stcli
    except ImportError:
        print("Streamlit이 설치되지 않았습니다. `python -m pip install -e .` 후 다시 실행하십시오.", file=sys.stderr)
        return 2
    ui_path = Path(__file__).with_name("ui.py")
    sys.argv = ["streamlit", "run", str(ui_path)]
    return int(stcli.main() or 0)


def main(argv: Sequence[str] | None = None) -> int:
    # Produce deterministic Unicode output when redirected on legacy Windows
    # code pages. Interactive consoles supporting Unicode continue to work.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    if not effective_argv:
        from .autorun import run_automatic_scan

        return run_automatic_scan()
    parser = _parser()
    args = parser.parse_args(effective_argv)
    _validate_args(args, parser)
    if args.command == "ui":
        return _run_ui()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )
    try:
        report = build_report(args)
    except AdvisoryDataError as exc:
        print(f"취약점 데이터 오류: {exc}", file=sys.stderr)
        return 2
    if args.output:
        if args.format == "human":
            Path(args.output).write_text(_human_summary(report), encoding="utf-8")
            output = Path(args.output)
        else:
            output = write_report(report, args.format, args.output)
        print(f"보고서 저장: {output}")
    else:
        print(_human_summary(report) if args.format == "human" else render(report, args.format))
    return 0

