"""Offline JSON, CSV, and self-contained HTML reports."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from html import escape
import io
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import ScanReport, Status


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
    return output.getvalue()


def _safe_link(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"}:
        return "#"
    return escape(url, quote=True)


def html_report(report: ScanReport) -> str:
    counts = {status: 0 for status in Status}
    for finding in report.findings:
        counts[finding.status] += 1
    asset_rows = "".join(
        "<tr>"
        f"<td>{escape(asset.vendor)}</td><td>{escape(asset.product)}</td>"
        f"<td>{escape(asset.distribution)}</td><td>{escape(asset.full_version or 'UNKNOWN')}</td>"
        f"<td>{escape(asset.special_build or '-')}</td><td>{escape(asset.install_path)}</td>"
        "</tr>"
        for asset in report.assets
    ) or '<tr><td colspan="6">탐지된 Java 자산이 없습니다.</td></tr>'
    finding_rows = "".join(
        "<tr>"
        f"<td>{escape(finding.cve_id)}</td>"
        f'<td><span class="badge {finding.status.value.lower()}">{escape(finding.status.value)}</span></td>'
        f"<td>{escape(finding.asset.product)}</td><td>{escape(finding.asset.full_version or 'UNKNOWN')}</td>"
        f"<td>{escape(finding.rationale)}</td><td>{escape(finding.recommendation)}</td>"
        "</tr>"
        for finding in report.findings
    ) or '<tr><td colspan="6">평가 결과가 없습니다.</td></tr>'
    source_items = "".join(
        f'<li><a href="{_safe_link(url)}">{escape(url)}</a></li>' for url in report.sources
    )
    limitation_items = "".join(f"<li>{escape(item)}</li>" for item in report.limitations)
    error_items = "".join(f"<li>{escape(item)}</li>" for item in report.errors)
    env_items = "".join(
        f"<dt>{escape(str(key))}</dt><dd>{escape(str(value))}</dd>"
        for key, value in report.environment.items()
    )
    scope_json = escape(json.dumps(report.scope, ensure_ascii=False))
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>JVI 점검 보고서</title><style>
:root{{--navy:#17243b;--blue:#2463a6;--red:#b42318;--green:#157347;--amber:#a15c00;--gray:#5d6673;}}
*{{box-sizing:border-box}}body{{margin:0;background:#f5f7fa;color:#1d2733;font:14px/1.55 Arial,"Noto Sans KR",sans-serif}}
main{{max-width:1200px;margin:28px auto;padding:0 22px}}header{{background:var(--navy);color:white;padding:26px;border-radius:10px}}
h1{{margin:0 0 6px;font-size:27px}}h2{{margin:28px 0 10px;color:var(--navy)}}.muted{{color:#d7dfeb}}.warning{{background:#fff3cd;border-left:5px solid #d59a00;padding:13px;margin-top:16px}}
.metrics{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:18px 0}}.metric{{background:white;padding:16px;border-radius:8px;box-shadow:0 1px 4px #ccd2da}}.metric b{{display:block;font-size:23px}}
table{{width:100%;border-collapse:collapse;background:white}}th,td{{padding:10px;border:1px solid #dce1e7;text-align:left;vertical-align:top}}th{{background:#edf2f7}}.badge{{font-weight:bold}}
.affected{{color:var(--red)}}.fixed{{color:var(--green)}}.unknown,.potentially_affected{{color:var(--amber)}}.not_affected{{color:var(--gray)}}
dl{{display:grid;grid-template-columns:150px 1fr;background:white;padding:14px}}dt{{font-weight:bold}}dd{{margin:0}}code{{white-space:pre-wrap}}@media(max-width:800px){{.metrics{{grid-template-columns:1fr 1fr}}table{{display:block;overflow:auto}}}}
</style></head><body><main><header><h1>Java Vulnerability Inspector</h1><div class="muted">점검 시각: {escape(report.scan_time)} · DB: {escape(report.database_version)}</div></header>
<div class="warning"><strong>점검 한계:</strong> {DISCLAIMER}</div>
<section class="metrics">
<div class="metric">전체 자산<b>{len(report.assets)}</b></div><div class="metric">영향 확인<b>{counts[Status.AFFECTED]}</b></div>
<div class="metric">수정 확인<b>{counts[Status.FIXED]}</b></div><div class="metric">잠재 영향<b>{counts[Status.POTENTIALLY_AFFECTED]}</b></div>
<div class="metric">판정 불가<b>{counts[Status.UNKNOWN]}</b></div></section>
<h2>점검 환경</h2><dl>{env_items}<dt>점검 범위</dt><dd><code>{scope_json}</code></dd></dl>
<h2>탐지한 Java 제품</h2><table><thead><tr><th>공급업체</th><th>제품</th><th>배포판</th><th>버전</th><th>변형</th><th>경로</th></tr></thead><tbody>{asset_rows}</tbody></table>
<h2>제품별 CVE 판정</h2><table><thead><tr><th>CVE</th><th>판정</th><th>제품</th><th>버전</th><th>근거</th><th>권고</th></tr></thead><tbody>{finding_rows}</tbody></table>
<h2>공식 출처</h2><ul>{source_items}</ul><h2>점검 한계</h2><ul>{limitation_items}</ul>
{f'<h2>탐색 중 오류</h2><ul>{error_items}</ul>' if error_items else ''}
</main></body></html>"""


def render(report: ScanReport, format_name: str) -> str:
    if format_name == "json":
        return json_report(report)
    if format_name == "csv":
        return csv_report(report)
    if format_name == "html":
        return html_report(report)
    raise ValueError(f"unsupported report format: {format_name}")


def write_report(report: ScanReport, format_name: str, output: str | Path) -> Path:
    path = Path(output)
    if path.is_dir():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = path / f"jvi-{stamp}.{format_name}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(report, format_name), encoding="utf-8", newline="")
    return path

