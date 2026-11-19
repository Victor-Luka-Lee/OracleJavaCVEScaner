"""Shared local scan workflow used by CLI, UI, and one-click mode."""

from __future__ import annotations

from datetime import datetime
import threading
from typing import Any, Callable

from .discovery import ProgressCallback, ScanConfig, discover, environment_summary
from .engine import evaluate_assets
from .models import ScanReport
from .reporting import DISCLAIMER


PhaseCallback = Callable[[str], None]


def execute_scan(
    config: ScanConfig,
    database: dict[str, Any],
    *,
    stop_event: threading.Event | None = None,
    progress: ProgressCallback | None = None,
    phase: PhaseCallback | None = None,
    environment: dict[str, str] | None = None,
    started_at: datetime | None = None,
) -> ScanReport:
    """Discover assets, evaluate every CVE, and assemble a report model."""
    scan_started = started_at or datetime.now().astimezone()
    if phase:
        phase("discovery")
    result = discover(config, stop_event=stop_event, progress=progress)
    if phase:
        phase("evaluation")
    findings = evaluate_assets(result.assets, database)
    issue_counts = {
        "permission": sum(
            issue.category == "permission" or issue.error_type == "PermissionError"
            for issue in result.issues
        ),
        "filesystem": sum(issue.category == "filesystem" for issue in result.issues),
        "java_metadata": sum(issue.category == "java_metadata" for issue in result.issues),
    }
    skipped_link_count = sum(
        item.path_type in {"junction", "symbolic_link", "reparse_point"}
        for item in result.skipped_paths
    )
    limitations = [
        DISCLAIMER,
        "Oracle 공지에 명시된 정확한 제품/빌드만 영향 범위로 사용하며 이전 버전을 임의 확장하지 않습니다.",
        "공식 영향·해결 목록에 없는 버전은 안전으로 간주하지 않고 NOT_ASSESSED로 분류합니다.",
        "OpenJDK 계열은 배포판별 공식 수정 공지가 이 DB에 없으면 NOT_ASSESSED입니다.",
        "기본 점검은 release 파일과 로컬 메타데이터를 사용하며 Java 바이너리를 실행하지 않습니다.",
        "내장 런타임은 설정한 깊이·파일 수·시간 제한 안에서만 발견됩니다.",
    ]
    if skipped_link_count:
        limitations.append(
            f"follow_symlinks=False 정책에 따라 자동 발견된 연결 디렉터리 {skipped_link_count}개를 "
            "정상적으로 제외했습니다. 이 제외만으로 점검 미완료로 처리하지 않습니다."
        )
    if result.root_links:
        limitations.append(
            f"탐색 루트로 지정된 연결 경로 {len(result.root_links)}개는 해당 루트만 진입하고, "
            "그 아래에서 발견되는 연결 지점에는 일반 링크 정책을 적용했습니다."
        )
    if result.incomplete:
        reasons = [*result.limit_reasons, *sorted({issue.category for issue in result.issues})]
        limitations.append(
            f"일부 점검 미완료: 탐색 제한 또는 오류가 발생했습니다 ({', '.join(reasons)})."
        )
    scan_completed = datetime.now().astimezone()
    return ScanReport(
        scan_time=scan_started.isoformat(),
        environment=environment or environment_summary(),
        scope={
            "mode": config.mode,
            "roots": result.roots,
            "max_depth": config.max_depth,
            "max_files": config.max_files,
            "timeout_seconds": config.timeout_seconds,
            "follow_symlinks": config.follow_symlinks,
            "java_execution_enabled": config.allow_java_execution,
            "package_metadata_enabled": config.collect_package_info,
            "examined_entries": result.examined_entries,
            "stopped": result.stopped,
            "incomplete": result.incomplete,
            "limit_reasons": result.limit_reasons,
            "issue_counts": issue_counts,
            "issues": [issue.to_dict() for issue in result.issues],
            "skipped_paths": [item.to_dict() for item in result.skipped_paths],
            "skipped_link_count": skipped_link_count,
            "root_links": [item.to_dict() for item in result.root_links],
        },
        assets=result.assets,
        findings=findings,
        database_version=database["database_version"],
        sources=database["sources"],
        limitations=limitations,
        errors=result.errors,
        started_at=scan_started.isoformat(),
        completed_at=scan_completed.isoformat(),
        advisories=list(database.get("advisories", [])),
    )
