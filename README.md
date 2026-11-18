# Java Vulnerability Inspector (JVI)

JVI는 Windows와 Linux에서 Java 런타임을 **읽기 전용으로 탐색**하고, KISA 및 Oracle의 2026년 11월 공식 보안 공지에 명시된 정확한 제품·빌드를 기준으로 CVE 영향을 평가하는 Python 3.11+ 도구입니다. CLI, 한국어 Streamlit 대시보드, JSON/CSV/오프라인 HTML 보고서를 제공합니다.

> **중요:** 버전 기반 취약점 영향 평가이며 실제 취약점 악용 성공 여부를 입증하는 검사가 아닙니다.

## 공식 근거와 데이터 범위

2026-11-18에 다음 공식 페이지를 대조해 데이터베이스를 작성했습니다.

- [KISA Oracle 제품 보안 업데이트 권고](https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&menuNo=205020&nttId=72313)
- [Oracle November 2026 CSPU](https://www.oracle.com/security-alerts/cspunov2026.html)
- [Oracle November 2026 Risk Matrix 텍스트](https://www.oracle.com/security-alerts/cspunov2026verbose.html)

포함 CVE는 `CVE-2026-86144`, `CVE-2026-114938`~`CVE-2026-114942`입니다. KISA의 영향 버전과 해결 버전, Oracle의 제품·구성요소·적용 조건·CVSS를 기록했습니다. 공식 문서에 열거된 빌드만 `AFFECTED`로 평가하며, 근거 없이 이전 버전 전체를 영향 범위로 확장하지 않습니다.

Oracle Java SE, Oracle JavaFX, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition 규칙은 제품별로 분리되어 있습니다. Eclipse Temurin, Amazon Corretto, Azul Zulu, Microsoft Build of OpenJDK, Red Hat OpenJDK 등은 Oracle 해결 버전을 그대로 적용하지 않습니다. 배포판별 공식 수정 근거가 이 MVP 데이터에 없으므로 식별된 자산은 `NOT_ASSESSED`입니다. 공급업체나 세부 빌드를 식별하지 못한 경우는 `UNKNOWN`입니다.

## 빠른 시작

### 표준 venv/pip

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux:   source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
```

### uv

```bash
uv sync --extra dev
uv run pytest
```

## CLI 사용법

```bash
# PATH, JAVA_HOME, 레지스트리/표준 위치 빠른 점검
python -m jvi scan --quick

# 지정 디렉터리(애플리케이션 내장 JRE/JDK 포함) 점검
python -m jvi scan --path "C:\Program Files\Java"
python -m jvi scan --path /usr/lib/jvm

# Program Files 또는 /opt, /usr/local까지 확장
python -m jvi scan --extended --max-depth 7 --max-files 100000 --timeout 120

# 보고서
python -m jvi scan --quick --format json --output reports/scan.json
python -m jvi scan --quick --format csv --output reports/scan.csv
python -m jvi scan --quick --format html --output reports/scan.html

# 상세 탐색 로그
python -m jvi scan --quick --verbose

# 로컬 대시보드
python -m jvi ui
```

`--path`는 반복할 수 있습니다. 기본 점검은 `release`와 로컬 설치/패키지 메타데이터만 읽으며 Java를 실행하지 않습니다. 메타데이터가 없는 런타임에 한해 사용자가 `--allow-java-execution`을 명시하면 `java -version`을 `shell=False`, 5초 제한으로 실행합니다.

주요 안전/범위 옵션:

- `--max-depth N`: 디렉터리 최대 깊이(기본 5)
- `--max-files N`: 확인할 최대 항목 수(기본 50,000)
- `--timeout SECONDS`: 전체 탐색 시간 제한(기본 60초)
- `--follow-symlinks`: 명시한 경우에만 링크 추적. 디렉터리 ID로 순환 방지
- `--no-package-info`: Linux의 `dpkg-query`/`rpm` 읽기 전용 소유 패키지 조회 생략
- `--advisory FILE`: 별도 JSON DB 사용
- `--no-integrity-check`: 동반 `.sha256` 검증을 명시적으로 생략

출력 파일을 지정하지 않으면 `human`, JSON, CSV, HTML 모두 표준 출력에 기록합니다. HTML은 CSS를 문서에 포함하고 외부 스크립트나 외부 폰트를 사용하지 않아 인터넷 없이 열립니다.

## 판정 의미

| 결과 | 의미 |
|---|---|
| `AFFECTED` | 공급업체·제품·변형·정확한 버전/빌드가 공식 영향 목록과 일치 |
| `FIXED` | KISA 해결 버전의 update/build 기준 충족이 명확히 식별됨 |
| `NOT_AFFECTED` | 공식 공지의 대상 제품과 명백히 다른 경우에만 사용 |
| `NOT_ASSESSED` | 자산은 식별됐지만 공식 영향·해결 목록이 해당 버전의 안전 여부를 다루지 않음 |
| `POTENTIALLY_AFFECTED` | Oracle 제품은 확인했으나 SE/JavaFX/GraalVM 변형을 확정하지 못함 |
| `UNKNOWN` | 공급업체, 버전 또는 필수 세부 빌드가 부족해 비교 자체가 불가능 |

`AFFECTED`는 버전 영향 여부입니다. 공격자 입력이 특정 API에 도달하는지, 샌드박스형 클라이언트인지, 사용자 상호작용이 가능한지 등의 **실제 공격 가능성**은 별도 필드로 보고합니다.

Java 8은 update와 build를 독립적으로 비교합니다. KISA 표기의 `8u513 (1.8.0_513-b04)`에서 `8u513`은 업데이트 계열 이름이고 실제 확인 기준은 `b04`입니다. 따라서 `8u513`처럼 build가 없는 자산은 `FIXED`가 아니라 `UNKNOWN`, `1.8.0_513-b03`은 `NOT_ASSESSED`, `1.8.0_513-b04` 이상은 `FIXED`입니다.

## 탐색과 제품 식별

Windows에서는 `PATH`, `JAVA_HOME`, `Program Files`, `Program Files (x86)`, 고정된 JavaSoft 레지스트리 키와 사용자 경로를 확인합니다. Linux에서는 `PATH`, `JAVA_HOME`, `/usr/lib/jvm`, 확장 모드의 `/opt`, `/usr/local`, 그리고 가능할 경우 로컬 패키지 소유자 정보를 확인합니다.

우선순위는 JDK/JRE `release` 파일 → JavaFX 메타데이터 → 패키지 관리자 정보 → 사용자가 승인한 `java -version`입니다. 버전은 Java 8의 update/build/perf 표기와 Java 11/17/21/25/27의 다중 숫자 표기를 정수 튜플로 정규화하며 문자열 사전식 비교를 사용하지 않습니다.

## 프로젝트 구조

```text
jvi/
  advisory.py   공식 JSON 로드, 스키마 및 SHA-256 검증
  discovery.py  제한 기반 자산 탐색, 공급업체/제품 식별
  version.py    Java 버전 정규화와 비교
  engine.py     CVE별 독립 판정
  reporting.py  JSON/CSV/자급식 HTML 보고서
  cli.py        argparse CLI
  ui.py         한국어 Streamlit UI와 백그라운드 중단 처리
data/advisories/oracle_2026_11.json
tests/          가상 release fixture 기반 pytest
```

상세 설계는 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)를 참고하십시오.

## 테스트

```bash
pytest
```

테스트는 실제 취약 Java 설치 없이 가상 `release` 파일과 `Asset` fixture를 사용합니다. Java 8 update/build, 현대 버전 비교, perf 변형, Oracle/OpenJDK 구분, 공식 영향·해결 빌드, 동일 update의 다른 build, 세부 build 누락, 목록에 없는 구버전, 지원 종료 메타데이터, 불명확한 공급업체, 변경 전후 회귀 행렬, 다중 설치, 링크 순환, 권한 오류, Java 미설치, JSON/CSV/HTML 생성 및 DB 무결성 거부를 다룹니다.

## 보안 특성

- 기본 읽기 전용이며 파일 수정/삭제, 자동 업데이트/패치, 악용 페이로드를 수행하지 않음
- 원격 호스트 스캔과 수집 정보 외부 전송 없음
- 네트워크가 필요한 런타임 기능 없음
- 링크 순환, 최대 깊이/항목 수/시간을 제한
- subprocess는 인자 배열과 `shell=False` 사용
- HTML은 모든 수집 문자열을 이스케이프하고 HTTP(S) 링크만 허용
- CSV 수식 주입 문자를 이스케이프
- 취약점 JSON은 동반 SHA-256 파일이 있으면 로드 전에 검증

## 새 CVE 추가

1. KISA/Oracle/해당 배포판의 공식 근거를 확인합니다.
2. `data/advisories/` JSON에 필수 필드와 제품별 `affected_versions`, `fixed_versions`를 추가합니다.
3. `verification_status`는 공식 근거가 모두 있을 때만 `VERIFIED_OFFICIAL`로 둡니다.
4. 정확한 영향·해결 fixture 테스트를 추가합니다.
5. JSON 변경 후 `.sha256`을 갱신하고 전체 `pytest`를 실행합니다.

## 확인된 한계

- JVM을 기본 실행하지 않으므로 `release`가 없는 잘린/특수 런타임은 버전이 `UNKNOWN`일 수 있습니다.
- JavaFX 탐지는 `javafx.properties`가 있는 설치를 우선 지원하며 모듈 JAR 내부 manifest까지 열지는 않습니다.
- 컨테이너 이미지, 원격 호스트, 압축 아카이브 내부는 스캔하지 않습니다.
- Windows Store/MSI 전체 인벤토리와 Linux 컨테이너 패키지 DB는 별도 수집하지 않습니다.
- OpenJDK 벤더별 2026년 11월 공지는 이 검증 데이터 세트에 포함하지 않았으므로 `NOT_ASSESSED`로 두며 수정 여부를 추정하지 않습니다.
- 공식 공지의 버전 판정과 실제 애플리케이션 입력 경로·CPU 특성·샌드박스 조건 검증은 별개입니다.

