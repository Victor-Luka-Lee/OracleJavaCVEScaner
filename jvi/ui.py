"""Korean Streamlit dashboard. Run with ``python -m jvi ui``."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import threading
import time
from typing import Any

import streamlit as st

from jvi.advisory import load_database
from jvi.discovery import ScanConfig
from jvi.models import ScanReport, Status
from jvi.reporting import DISCLAIMER, html_report
from jvi.workflow import execute_scan


@dataclass
class ScanJob:
    config: ScanConfig
    database: dict[str, Any]
    stop_event: threading.Event = field(default_factory=threading.Event)
    examined: int = 0
    current_path: str = "준비 중"
    report: ScanReport | None = None
    error: str | None = None
    done: bool = False


def _run_job(job: ScanJob) -> None:
    try:
        def progress(count: int, path: str) -> None:
            job.examined = count
            job.current_path = path

        job.report = execute_scan(
            job.config,
            job.database,
            stop_event=job.stop_event,
            progress=progress,
        )
    except Exception as exc:  # surfaced in the local UI without a remote error service
        job.error = f"{exc.__class__.__name__}: {exc}"
    finally:
        job.done = True


def _start_job(config: ScanConfig, database: dict[str, Any]) -> None:
    job = ScanJob(config=config, database=database)
    thread = threading.Thread(target=_run_job, args=(job,), daemon=True, name="jvi-scan")
    st.session_state.job = job
    st.session_state.thread = thread
    thread.start()


def _finding_rows(report: ScanReport) -> list[dict[str, Any]]:
    return [
        {
            "CVE": item.cve_id,
            "판정": item.status.value,
            "공급업체": item.asset.vendor,
            "제품": item.asset.product,
            "버전": item.asset.full_version or "UNKNOWN",
            "변형": item.asset.special_build or "-",
            "경로": item.discovered_path,
            "신뢰도": item.confidence,
            "판정 근거": item.rationale,
            "권고 조치": item.recommendation,
        }
        for item in report.findings
    ]


st.set_page_config(page_title="JVI", page_icon="🛡️", layout="wide")
st.title("🛡️ Java Vulnerability Inspector")
st.caption("Oracle 2026년 11월 CSPU 기반 · 읽기 전용 로컬 점검")
st.warning(DISCLAIMER)

try:
    database = load_database()
except Exception as exc:
    st.error(f"취약점 데이터베이스를 열 수 없습니다: {exc}")
    st.stop()

with st.sidebar:
    st.header("자산 탐색")
    mode_label = st.radio("점검 방식", ["빠른 점검", "사용자 지정 경로", "확장 점검"])
    custom_paths = st.text_area("경로 (한 줄에 하나)", disabled=mode_label != "사용자 지정 경로")
    max_depth = st.slider("최대 깊이", 1, 12, 5)
    max_files = st.number_input("최대 항목 수", min_value=100, max_value=1_000_000, value=50_000, step=1_000)
    timeout = st.number_input("시간 제한(초)", min_value=5, max_value=3600, value=60)
    allow_execution = st.checkbox("메타데이터 없을 때 java -version 실행", value=False)
    st.caption("선택 시에만 발견한 Java 바이너리를 최대 5초 동안 실행합니다.")
    running = "job" in st.session_state and not st.session_state.job.done
    if st.button("점검 시작", type="primary", disabled=running, width="stretch"):
        roots = []
        mode = "quick"
        if mode_label == "사용자 지정 경로":
            roots = [Path(line.strip()) for line in custom_paths.splitlines() if line.strip()]
            if not roots:
                st.error("하나 이상의 경로를 입력하십시오.")
                st.stop()
        elif mode_label == "확장 점검":
            mode = "extended"
        config = ScanConfig(
            roots=roots,
            mode=mode,
            max_depth=max_depth,
            max_files=int(max_files),
            timeout_seconds=float(timeout),
            allow_java_execution=allow_execution,
        )
        _start_job(config, database)
        st.rerun()
    if running and st.button("점검 중단", width="stretch"):
        st.session_state.job.stop_event.set()
        st.info("중단 요청을 보냈습니다.")

if "job" in st.session_state:
    job: ScanJob = st.session_state.job
    if not job.done:
        ratio = min(job.examined / max(job.config.max_files, 1), 0.99)
        st.progress(ratio, text=f"{job.examined:,}개 항목 확인 · {job.current_path}")
        time.sleep(0.35)
        st.rerun()
    if job.error:
        st.error(f"점검 실패: {job.error}")
    elif job.report:
        report = job.report
        rows = _finding_rows(report)
        affected_assets = {f.discovered_path for f in report.findings if f.status == Status.AFFECTED}
        fixed_assets = {f.discovered_path for f in report.findings if f.status == Status.FIXED}
        not_assessed_assets = {f.discovered_path for f in report.findings if f.status == Status.NOT_ASSESSED}
        unknown_assets = {f.discovered_path for f in report.findings if f.status == Status.UNKNOWN}
        cols = st.columns(5)
        cols[0].metric("전체 탐지 자산", len(report.assets))
        cols[1].metric("영향 확인 자산", len(affected_assets))
        cols[2].metric("수정 확인 자산", len(fixed_assets))
        cols[3].metric("미평가 자산", len(not_assessed_assets))
        cols[4].metric("정보 부족 자산", len(unknown_assets))

        st.subheader("CVE별 발견 현황")
        cve_counts: dict[str, int] = {}
        for finding in report.findings:
            if finding.status == Status.AFFECTED:
                cve_counts[finding.cve_id] = cve_counts.get(finding.cve_id, 0) + 1
        st.bar_chart(cve_counts, horizontal=True)

        st.subheader("점검 결과")
        search = st.text_input("검색", placeholder="CVE, 제품, 버전, 경로")
        status_filter = st.multiselect("판정 필터", [status.value for status in Status])
        sort_key = st.selectbox("정렬", ["CVE", "판정", "제품", "버전", "경로"])
        filtered = rows
        if search:
            needle = search.casefold()
            filtered = [row for row in filtered if needle in " ".join(str(v) for v in row.values()).casefold()]
        if status_filter:
            filtered = [row for row in filtered if row["판정"] in status_filter]
        filtered = sorted(filtered, key=lambda row: str(row[sort_key]).casefold())
        st.dataframe(filtered, width="stretch", hide_index=True)

        st.download_button(
            "HTML 보고서 다운로드",
            html_report(report).encode("utf-8"),
            "jvi-report.html",
            "text/html",
            width="stretch",
        )

        st.subheader("취약점 상세")
        selected = st.selectbox("CVE", [item["cve_id"] for item in database["advisories"]])
        advisory = next(item for item in database["advisories"] if item["cve_id"] == selected)
        st.markdown(f"**{advisory['description_ko']}**  \n구성요소: `{advisory['component']}` · CVSS 3.1: `{advisory['cvss_score']}`")
        st.write("영향 버전", advisory["affected_versions"])
        st.write("적용 조건", advisory["applicable_conditions"])
        st.write("권고 조치", advisory["recommendation"])
        for url in advisory["advisory_urls"]:
            st.markdown(f"- [{url}]({url})")
        if report.errors:
            with st.expander(f"탐색 중 접근 오류 {len(report.errors)}건"):
                st.code("\n".join(report.errors))
else:
    st.info("왼쪽에서 점검 범위와 제한을 확인한 뒤 ‘점검 시작’을 누르십시오.")
    st.subheader("검증된 취약점 데이터")
    lines = ["| CVE | 구성요소 | 심각도 | CVSS | 검증 |", "|---|---|---|---:|---|"]
    lines.extend(
        f"| {item['cve_id']} | {item['component']} | {item['severity']} | {item['cvss_score']} | {item['verification_status']} |"
        for item in database["advisories"]
    )
    st.markdown("\n".join(lines))
