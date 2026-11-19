"""Offline JSON, CSV, and self-contained HTML reports."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from html import escape
import io
import json
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from .models import Asset, Finding, ScanReport, Status


DISCLAIMER = "버전 기반 취약점 영향 평가이며 실제 취약점 악용 성공 여부를 입증하는 검사가 아님"


def json_report(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


def _csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def csv_report(report: ScanReport) -> str:
    output = io.StringIO(newline="")
    fields = [
        "cve_id",
        "status",
        "vendor",
        "product",
        "distribution",
        "version",
        "special_build",
        "install_path",
        "confidence",
        "rationale",
        "recommendation",
        "exploitability",
        "database_version",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for finding in report.findings:
        writer.writerow(
            {
                "cve_id": _csv_safe(finding.cve_id),
                "status": finding.status.value,
                "vendor": _csv_safe(finding.asset.vendor),
                "product": _csv_safe(finding.asset.product),
                "distribution": _csv_safe(finding.asset.distribution),
                "version": _csv_safe(finding.asset.full_version),
                "special_build": _csv_safe(finding.asset.special_build),
                "install_path": _csv_safe(finding.discovered_path),
                "confidence": finding.confidence,
                "rationale": _csv_safe(finding.rationale),
                "recommendation": _csv_safe(finding.recommendation),
                "exploitability": _csv_safe(finding.exploitability),
                "database_version": finding.database_version,
            }
        )
    for error in report.errors:
        writer.writerow(
            {
                "status": "SCAN_ERROR",
                "rationale": _csv_safe(error),
                "database_version": report.database_version,
            }
        )
    if report.scope.get("incomplete"):
        reasons = ", ".join(report.scope.get("limit_reasons") or ["access_errors"])
        writer.writerow(
            {
                "status": "SCAN_INCOMPLETE",
                "rationale": _csv_safe(f"일부 점검 미완료: {reasons}"),
                "database_version": report.database_version,
            }
        )
    return output.getvalue()


def _safe_link(url: str) -> str | None:
    parsed = urlparse(str(url))
    if parsed.scheme.lower() not in {"https", "http"} or not parsed.netloc:
        return None
    return escape(str(url), quote=True)


def _text(value: Any, default: str = "-") -> str:
    if value is None or value == "":
        value = default
    return escape(str(value))


def _items(values: Iterable[Any], *, empty: str = "없음") -> str:
    rows = "".join(f"<li>{_text(value)}</li>" for value in values)
    return rows or f"<li>{escape(empty)}</li>"


_STATUS_PRIORITY = {
    Status.AFFECTED: 0,
    Status.POTENTIALLY_AFFECTED: 1,
    Status.UNKNOWN: 2,
    Status.NOT_ASSESSED: 3,
    Status.FIXED: 4,
    Status.NOT_AFFECTED: 5,
}


def _asset_key(asset: Asset) -> tuple[str, str, str, str, str]:
    return (
        asset.install_path,
        asset.vendor,
        asset.product,
        asset.distribution,
        asset.full_version or "",
    )


def _asset_status(asset: Asset, findings: list[Finding]) -> str:
    statuses = [item.status for item in findings if _asset_key(item.asset) == _asset_key(asset)]
    if not statuses:
        return Status.NOT_ASSESSED.value
    return min(statuses, key=lambda status: _STATUS_PRIORITY[status]).value


def _badge(status: str) -> str:
    css = status.lower().replace("_", "-")
    return f'<span class="badge status-{escape(css)}">{escape(status)}</span>'


def _advisory_index(report: ScanReport) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("cve_id")): item
        for item in report.advisories
        if isinstance(item, dict) and item.get("cve_id")
    }


def _reference_links(urls: Iterable[str]) -> str:
    links: list[str] = []
    for url in urls:
        safe = _safe_link(url)
        if safe is None:
            links.append(f'<span class="invalid-link">차단된 링크: {_text(url)}</span>')
        else:
            links.append(f'<a href="{safe}" rel="noopener noreferrer">{_text(url)}</a>')
    return "<br>".join(links) or "-"


def _version_text(asset: Asset) -> str:
    parts = [asset.full_version or "UNKNOWN"]
    if asset.update_number is not None:
        parts.append(f"update={asset.update_number}")
    if asset.build_number is not None:
        parts.append(f"build={asset.build_number}")
    if asset.special_build:
        parts.append(f"special={asset.special_build}")
    return " / ".join(parts)


def html_report(report: ScanReport) -> str:
    """Render a UTF-8, offline HTML report optimized for A4 browser printing."""
    counts = {status: 0 for status in Status}
    for finding in report.findings:
        counts[finding.status] += 1
    advisories = _advisory_index(report)
    incomplete = bool(report.scope.get("incomplete") or report.errors)
    result_label = "일부 점검 미완료" if incomplete else "점검 완료"
    structured_issues = [
        item for item in (report.scope.get("issues") or []) if isinstance(item, dict)
    ]
    skipped_paths = [
        item for item in (report.scope.get("skipped_paths") or []) if isinstance(item, dict)
    ]
    root_links = [
        item for item in (report.scope.get("root_links") or []) if isinstance(item, dict)
    ]
    issue_counts = report.scope.get("issue_counts") or {}
    permission_issues = [
        item
        for item in structured_issues
        if item.get("category") == "permission" or item.get("error_type") == "PermissionError"
    ]
    filesystem_issues = [
        item for item in structured_issues if item.get("category") == "filesystem"
    ]
    metadata_issues = [
        item for item in structured_issues if item.get("category") == "java_metadata"
    ]
    skipped_links = [
        item
        for item in skipped_paths
        if item.get("path_type") in {"junction", "symbolic_link", "reparse_point"}
    ]
    permission_count = int(issue_counts.get("permission", len(permission_issues)) or 0)
    skipped_link_count = int(report.scope.get("skipped_link_count", len(skipped_links)) or 0)
    limit_reasons = report.scope.get("limit_reasons") or []

    metric_values = [
        ("Java 자산", len(report.assets)),
        ("영향 확인", counts[Status.AFFECTED]),
        ("수정 확인", counts[Status.FIXED]),
        ("잠재 영향", counts[Status.POTENTIALLY_AFFECTED]),
        ("판정 불가/미평가", counts[Status.UNKNOWN] + counts[Status.NOT_ASSESSED]),
        ("실제 권한 오류", permission_count),
        ("제한 도달", "예" if limit_reasons else "아니오"),
        ("정상 제외 연결", skipped_link_count),
    ]
    metrics = "".join(
        f'<div class="metric"><span>{escape(label)}</span><strong>{value}</strong></div>'
        for label, value in metric_values
    )

    overview = [
        ("호스트", report.environment.get("hostname", "UNKNOWN")),
        (
            "운영체제 / 아키텍처",
            " / ".join(
                part
                for part in [
                    report.environment.get("os", "UNKNOWN"),
                    report.environment.get("os_release", ""),
                    report.environment.get("architecture", "UNKNOWN"),
                ]
                if part
            ),
        ),
        ("점검 시작", report.started_at or report.scan_time),
        ("점검 종료", report.completed_at or "-"),
        ("취약점 DB", report.database_version),
        ("최종 결과", result_label),
    ]
    overview_rows = "".join(
        f"<tr><th>{escape(label)}</th><td>{_text(value)}</td></tr>" for label, value in overview
    )

    asset_rows = "".join(
        '<tbody class="row-group"><tr>'
        f"<td>{_text(asset.vendor)}</td>"
        f"<td>{_text(asset.product)}</td>"
        f"<td>{_text(asset.distribution)}</td>"
        f'<td class="version-cell">{_text(_version_text(asset))}</td>'
        f'<td class="path-cell">{_text(asset.install_path)}</td>'
        f'<td class="evidence-cell">{_items(asset.evidence)}</td>'
        f"<td>{_badge(_asset_status(asset, report.findings))}</td>"
        "</tr></tbody>"
        for asset in report.assets
    ) or '<tbody><tr><td colspan="7" class="empty">탐지된 Java 자산이 없습니다.</td></tr></tbody>'

    finding_rows: list[str] = []
    finding_cards: list[str] = []
    for finding in report.findings:
        advisory = advisories.get(finding.cve_id, {})
        cve_type = advisory.get("description_ko") or advisory.get("component") or "-"
        severity = advisory.get("severity")
        cvss = advisory.get("cvss_score")
        if severity or cvss is not None:
            cve_type = f"{cve_type} ({severity or '-'} / CVSS {cvss if cvss is not None else '-'})"
        finding_rows.append(
            '<tbody class="row-group"><tr>'
            f"<td><strong>{_text(finding.cve_id)}</strong></td>"
            f"<td>{_text(cve_type)}</td>"
            f"<td>{_text(finding.asset.product)}<br><span class=\"secondary\">{_text(finding.asset.vendor)} · {_text(finding.asset.full_version, 'UNKNOWN')}</span></td>"
            f"<td>{_badge(finding.status.value)}</td>"
            f'<td class="long-cell">{_text(finding.rationale)}</td>'
            f"<td>{_text(finding.confidence)}</td>"
            f'<td class="long-cell">{_text(finding.recommendation)}</td>'
            f'<td class="references-cell">{_reference_links(finding.advisory_urls)}</td>'
            "</tr></tbody>"
        )
        finding_cards.append(
            '<article class="finding-card">'
            f'<div class="finding-card-title"><strong>{_text(finding.cve_id)}</strong>{_badge(finding.status.value)}</div>'
            '<table class="finding-card-table"><tbody>'
            f"<tr><th>유형 / 심각도</th><td>{_text(cve_type)}</td></tr>"
            f"<tr><th>대상 자산</th><td>{_text(finding.asset.product)} · {_text(finding.asset.vendor)} · {_text(finding.asset.full_version, 'UNKNOWN')}</td></tr>"
            f"<tr><th>판정 근거</th><td>{_text(finding.rationale)}</td></tr>"
            f"<tr><th>신뢰도</th><td>{_text(finding.confidence)}</td></tr>"
            f"<tr><th>권고 사항</th><td>{_text(finding.recommendation)}</td></tr>"
            f'<tr><th>공식 참조</th><td class="references-cell">{_reference_links(finding.advisory_urls)}</td></tr>'
            "</tbody></table></article>"
        )
    finding_html = "".join(finding_rows) or '<tbody><tr><td colspan="8" class="empty">CVE 판정 결과가 없습니다.</td></tr></tbody>'
    finding_card_html = (
        "".join(
            '<div class="finding-page">'
            + ('<h2 class="print-findings-title">CVE 판정 상세</h2>' if index == 0 else "")
            + finding_cards[index]
            + "</div>"
            for index in range(len(finding_cards))
        )
        or '<p class="empty">CVE 판정 결과가 없습니다.</p>'
    )

    roots = report.scope.get("roots") or []
    scope_rows = [
        ("탐색 모드", report.scope.get("mode", "-")),
        ("탐색 루트", ", ".join(str(item) for item in roots) or "없음"),
        ("확인 항목", report.scope.get("examined_entries", "-")),
        ("최대 깊이", report.scope.get("max_depth", "-")),
        ("최대 파일", report.scope.get("max_files", "-")),
        ("제한 시간(초)", report.scope.get("timeout_seconds", "-")),
        ("심볼릭 링크 추적", report.scope.get("follow_symlinks", "-")),
        ("Java 실행 허용", report.scope.get("java_execution_enabled", "-")),
        ("패키지 메타데이터", report.scope.get("package_metadata_enabled", "-")),
        ("실제 접근 권한 오류", permission_count),
        ("파일 시스템 오류", int(issue_counts.get("filesystem", len(filesystem_issues)) or 0)),
        ("Java 메타데이터 오류", int(issue_counts.get("java_metadata", len(metadata_issues)) or 0)),
        ("정상 제외 연결 디렉터리", skipped_link_count),
        ("제한/중단 사유", ", ".join(str(item) for item in limit_reasons) or "없음"),
    ]
    scope_table = "".join(
        f"<tr><th>{escape(label)}</th><td class=\"long-cell\">{_text(value)}</td></tr>"
        for label, value in scope_rows
    )

    source_items = "".join(
        f"<li>{_reference_links([str(url)])}</li>" for url in report.sources
    ) or "<li>없음</li>"
    limitation_items = _items(report.limitations)

    def issue_lines(values: list[dict[str, Any]]) -> list[str]:
        return [
            f"{item.get('path', '-')} — {item.get('operation', '-')} "
            f"({item.get('error_type', 'OSError')}: {item.get('message', '-')})"
            for item in values
        ]

    permission_items = _items(issue_lines(permission_issues))
    filesystem_items = _items(issue_lines(filesystem_issues))
    metadata_items = _items(issue_lines(metadata_issues))
    skipped_link_items = _items(
        [
            f"{item.get('path', '-')} — {item.get('path_type', 'reparse_point')} / "
            f"{item.get('reason', 'link_not_followed')} / {item.get('reparse_tag_hex') or '태그 없음'}"
            for item in skipped_links
        ],
        empty="없음 (연결 디렉터리로 인해 제외된 범위 없음)",
    )
    root_link_items = _items(
        [
            f"{item.get('path', '-')} — {item.get('path_type', 'link')} / "
            f"탐색 루트로 진입 ({item.get('root_origin') or 'unknown'})"
            for item in root_links
        ]
    )
    legacy_error_items = _items(report.errors) if not structured_issues else ""
    unavailable_scope_items = _items(
        [
            *[str(item.get("path", "-")) for item in structured_issues],
            *[f"탐색 제한: {reason}" for reason in limit_reasons],
        ],
        empty="없음",
    )

    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JVI 취약점 점검 보고서</title>
<style>
:root {{ --navy:#17324d; --blue:#286da8; --line:#cbd5df; --pale:#f2f6f9; --red:#a61b1b; --green:#176b42; --amber:#8a5500; --gray:#56616d; }}
* {{ box-sizing:border-box; }}
html {{ background:#e9eef3; }}
body {{ margin:0; color:#19242f; font:13px/1.48 "Malgun Gothic", "맑은 고딕", "Apple SD Gothic Neo", "Noto Sans KR", Arial, sans-serif; -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
main {{ max-width:1180px; margin:24px auto; padding:28px; background:#fff; box-shadow:0 3px 18px rgba(20,45,70,.12); }}
header {{ display:flex; justify-content:space-between; gap:20px; align-items:flex-start; padding-bottom:18px; border-bottom:3px solid var(--navy); }}
h1 {{ margin:0; color:var(--navy); font-size:27px; line-height:1.2; }}
.subtitle {{ margin-top:6px; color:var(--gray); }}
.print-actions {{ min-width:220px; text-align:right; }}
.print-button {{ border:0; border-radius:5px; padding:10px 15px; background:var(--blue); color:#fff; font:700 13px inherit; cursor:pointer; }}
.print-help {{ display:block; margin-top:7px; color:var(--gray); font-size:11px; }}
.notice {{ margin:16px 0; padding:11px 13px; background:#fff7df; border-left:4px solid #d59416; }}
.metrics {{ display:grid; grid-template-columns:repeat(8,minmax(90px,1fr)); gap:8px; margin:16px 0 22px; }}
.metric {{ min-height:72px; padding:10px; border:1px solid var(--line); border-radius:5px; background:var(--pale); }}
.metric span {{ display:block; color:var(--gray); font-size:11px; }}
.metric strong {{ display:block; color:var(--navy); font-size:24px; line-height:1.25; }}
h2 {{ margin:24px 0 9px; padding-bottom:5px; color:var(--navy); border-bottom:1px solid var(--line); font-size:18px; break-after:avoid-page; page-break-after:avoid; }}
h3 {{ margin:16px 0 7px; color:var(--navy); font-size:14px; break-after:avoid-page; page-break-after:avoid; }}
table {{ width:100%; border-collapse:collapse; table-layout:fixed; }}
thead {{ display:table-header-group; }}
tfoot {{ display:table-footer-group; }}
th, td {{ padding:7px 8px; border:1px solid var(--line); text-align:left; vertical-align:top; overflow-wrap:anywhere; word-break:break-word; }}
th {{ background:#e8eff5; color:#1b3852; font-weight:700; }}
tr {{ break-inside:avoid; page-break-inside:avoid; }}
.row-group {{ break-inside:avoid; page-break-inside:avoid; }}
.overview th, .scope-table th {{ width:22%; }}
.assets-table th:nth-child(1) {{ width:10%; }} .assets-table th:nth-child(2) {{ width:12%; }} .assets-table th:nth-child(3) {{ width:12%; }}
.assets-table th:nth-child(4) {{ width:15%; }} .assets-table th:nth-child(5) {{ width:18%; }} .assets-table th:nth-child(6) {{ width:20%; }} .assets-table th:nth-child(7) {{ width:13%; }}
.findings-table th:nth-child(1) {{ width:9%; }} .findings-table th:nth-child(2) {{ width:14%; }} .findings-table th:nth-child(3) {{ width:12%; }} .findings-table th:nth-child(4) {{ width:11%; }}
.findings-table th:nth-child(5) {{ width:19%; }} .findings-table th:nth-child(6) {{ width:8%; }} .findings-table th:nth-child(7) {{ width:16%; }} .findings-table th:nth-child(8) {{ width:11%; }}
.path-cell, .references-cell {{ word-break:break-all; overflow-wrap:anywhere; }}
.long-cell, .evidence-cell, .version-cell {{ white-space:normal; overflow-wrap:anywhere; word-break:break-word; }}
.evidence-cell ul {{ margin:0; padding-left:17px; }}
.secondary {{ color:var(--gray); font-size:11px; }}
.badge {{ display:inline-block; max-width:100%; padding:2px 5px; border-radius:3px; font-size:10px; font-weight:700; overflow-wrap:anywhere; }}
.status-affected {{ color:#fff; background:var(--red); }}
.status-fixed {{ color:#fff; background:var(--green); }}
.status-not-affected {{ color:#fff; background:var(--gray); }}
.status-not-assessed, .status-unknown, .status-potentially-affected {{ color:#3d2b00; background:#ffd778; }}
.empty {{ text-align:center; color:var(--gray); padding:18px; }}
.print-only {{ display:none; }}
.finding-card {{ margin:0 0 4mm; padding:3mm; border:1px solid var(--line); break-inside:avoid; page-break-inside:avoid; }}
.finding-card-title {{ display:flex; justify-content:space-between; gap:3mm; margin-bottom:2mm; color:var(--navy); font-size:11pt; }}
.finding-card-table {{ margin:0; table-layout:fixed; }}
.finding-card-table th {{ width:28mm; }}
.invalid-link {{ color:var(--red); }}
ul {{ margin:7px 0; padding-left:20px; }}
a {{ color:#145e96; }}
footer {{ margin-top:28px; padding-top:11px; border-top:1px solid var(--line); color:var(--gray); font-size:11px; }}
@media screen and (max-width:850px) {{
  main {{ margin:0; padding:16px; box-shadow:none; }} header {{ display:block; }} .print-actions {{ margin-top:14px; text-align:left; }}
  .metrics {{ grid-template-columns:repeat(2,1fr); }} .table-wrap {{ overflow-x:auto; }} table {{ min-width:850px; }} .overview, .scope-table {{ min-width:0; }}
}}
@page {{ size:A4 portrait; margin:12mm 10mm 14mm; }}
@media print {{
  html, body {{ background:#fff; width:auto; height:auto; }}
  body {{ font-size:9pt; }}
  main {{ max-width:none; margin:0; padding:0; box-shadow:none; }}
  .no-print {{ display:none !important; }}
  header {{ padding-bottom:4mm; }} h1 {{ font-size:19pt; }} h2 {{ margin-top:5mm; font-size:13pt; }}
  .metrics {{ grid-template-columns:repeat(8,1fr); gap:1.2mm; margin:4mm 0 5mm; }}
  .metric {{ min-height:15mm; padding:2mm; }} .metric strong {{ font-size:15pt; }}
  table {{ font-size:7.4pt; table-layout:fixed; }} th, td {{ padding:1.5mm; }}
  .table-wrap {{ overflow:visible !important; }} table {{ min-width:0 !important; }}
  thead {{ display:table-header-group; }} .row-group, tr, td, th {{ break-inside:avoid !important; page-break-inside:avoid !important; }}
  .findings-table-wrap {{ display:none !important; }} .print-only {{ display:block; }}
  #findings-title {{ display:none; }}
  .finding-page {{ display:block; break-before:page !important; page-break-before:always !important; break-inside:avoid !important; page-break-inside:avoid !important; }}
  .finding-card {{ display:block; width:100%; break-inside:avoid !important; page-break-inside:avoid !important; }}
  a {{ color:#000; text-decoration:none; }} section {{ break-inside:auto; page-break-inside:auto; }}
}}
</style>
<script>
function printReport() {{ window.print(); }}
</script>
</head>
<body>
<main>
<header>
  <div><h1>Java Vulnerability Inspector</h1><div class="subtitle">Oracle Java CVE Scanner · 취약점 점검 보고서</div></div>
  <div class="print-actions no-print"><button type="button" class="print-button" onclick="printReport()">PDF로 저장 / 인쇄</button><span class="print-help">브라우저 인쇄 창에서 “PDF로 저장”을 선택할 수 있습니다.</span></div>
</header>
<div class="notice"><strong>평가 한계:</strong> {escape(DISCLAIMER)}</div>
<section aria-labelledby="overview-title"><h2 id="overview-title">점검 개요</h2><table class="overview"><tbody>{overview_rows}</tbody></table></section>
<section aria-label="핵심 지표" class="metrics">{metrics}</section>
<section aria-labelledby="assets-title"><h2 id="assets-title">Java 자산</h2><div class="table-wrap"><table class="assets-table"><thead><tr><th>공급업체</th><th>제품</th><th>배포판</th><th>정확한 버전</th><th>설치 경로</th><th>탐지 근거</th><th>자산 상태</th></tr></thead>{asset_rows}</table></div></section>
<section aria-labelledby="findings-title"><h2 id="findings-title">CVE 판정 상세</h2><div class="table-wrap findings-table-wrap"><table class="findings-table"><thead><tr><th>CVE ID</th><th>유형 / 심각도</th><th>대상 자산</th><th>판정 상태</th><th>판정 근거</th><th>신뢰도</th><th>권고 사항</th><th>공식 참조</th></tr></thead>{finding_html}</table></div><div class="print-findings print-only">{finding_card_html}</div></section>
<section aria-labelledby="scope-title"><h2 id="scope-title">탐색 범위와 제한</h2><table class="scope-table"><tbody>{scope_table}</tbody></table><h3>평가 제한 사항</h3><ul>{limitation_items}</ul></section>
<section aria-labelledby="errors-title"><h2 id="errors-title">탐색 오류 및 미확인 영역</h2>
<h3>실제 접근 권한 오류</h3><ul>{permission_items}</ul>
<h3>파일 시스템 오류</h3><ul>{filesystem_items}</ul>
<h3>Java 메타데이터 읽기 실패</h3><ul>{metadata_items}</ul>
<h3>탐색 제한 도달</h3><ul>{_items(limit_reasons)}</ul>
<h3>검사에서 정상 제외된 연결 디렉터리</h3><ul>{skipped_link_items}</ul>
<h3>탐색 루트로 지정된 연결 경로</h3><ul>{root_link_items}</ul>
<h3>실제 영향 여부를 판단할 수 없는 범위</h3><ul>{unavailable_scope_items}</ul>
{f'<h3>기타 탐색 오류</h3><ul>{legacy_error_items}</ul>' if legacy_error_items else ''}
</section>
<section aria-labelledby="sources-title"><h2 id="sources-title">공식 근거</h2><ul>{source_items}</ul></section>
<footer>JVI DB {escape(report.database_version)} · 생성 시각 {_text(report.completed_at or report.scan_time)}</footer>
</main>
</body>
</html>"""


def render(report: ScanReport, format_name: str) -> str:
    if format_name == "json":
        return json_report(report)
    if format_name == "csv":
        return csv_report(report)
    if format_name == "html":
        return html_report(report)
    raise ValueError(f"unsupported report format: {format_name}")


def write_report(
    report: ScanReport,
    format_name: str,
    output: str | Path,
    *,
    overwrite: bool = True,
) -> Path:
    path = Path(output)
    if path.is_dir():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = path / f"jvi-{stamp}.{format_name}"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w" if overwrite else "x", encoding="utf-8", newline="") as handle:
        handle.write(render(report, format_name))
    return path
