"""Command line interface for JVI."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
from typing import Sequence

from .advisory import AdvisoryDataError, DEFAULT_ADVISORY, load_database
from .discovery import ScanConfig, discover, environment_summary
from .engine import evaluate_assets
from .models import ScanReport, Status
from .reporting import DISCLAIMER, render, write_report


LOG = logging.getLogger("jvi")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jvi", description="Java Vulnerability Inspector")
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
    result = discover(config, progress=lambda count, path: LOG.debug("examined=%s path=%s", count, path))
    findings = evaluate_assets(result.assets, database)
    limitations = [
        DISCLAIMER,
        "Oracle 공지에 명시된 정확한 제품/빌드만 영향 범위로 사용하며 이전 버전을 임의 확장하지 않습니다.",
        "공식 영향·해결 목록에 없는 버전은 안전으로 간주하지 않고 NOT_ASSESSED로 분류합니다.",
        "OpenJDK 계열은 배포판별 공식 수정 공지가 이 DB에 없으면 NOT_ASSESSED입니다.",
        "기본 점검은 release 파일과 로컬 메타데이터를 사용하며 Java 바이너리를 실행하지 않습니다.",
        "내장 런타임은 설정한 깊이·파일 수·시간 제한 안에서만 발견됩니다.",
    ]
    if result.stopped:
        limitations.append("사용자 중단 또는 탐색 제한 도달로 점검이 조기에 종료되었습니다.")
    return ScanReport(
        scan_time=datetime.now(timezone.utc).isoformat(),
        environment=environment_summary(),
        scope={
            "mode": mode,
            "roots": result.roots,
            "max_depth": config.max_depth,
            "max_files": config.max_files,
            "timeout_seconds": config.timeout_seconds,
            "follow_symlinks": config.follow_symlinks,
            "java_execution_enabled": config.allow_java_execution,
            "examined_entries": result.examined_entries,
            "stopped": result.stopped,
        },
        assets=result.assets,
        findings=findings,
        database_version=database["database_version"],
        sources=database["sources"],
        limitations=limitations,
        errors=result.errors,
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
    parser = _parser()
    args = parser.parse_args(argv)
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

