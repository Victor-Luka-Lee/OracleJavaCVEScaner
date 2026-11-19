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
python -m pip install -e ".[dev,ui]"
pytest
```

### uv

```bash
uv sync --extra dev --extra ui
uv run pytest
```

Streamlit은 서버용 CLI의 기본 의존성이 아닙니다. CLI만 설치할 때는 `pip install -e .`, 대시보드가 필요할 때만 `pip install -e ".[ui]"`를 사용합니다.

## 원클릭 자동 점검

설치 후 인자 없이 실행하면 사용자 입력 없이 extended 점검, CVE 평가, 보고서 저장, 한국어 요약까지 수행합니다.

```bash
python -m jvi
jvi
```

자동 점검은 `max-depth=7`, `max-files=100000`, `timeout=180초`, 심볼릭 링크 추적 비활성화, Java 실행 비활성화, 패키지 메타데이터 조회 활성화로 고정됩니다. 시스템 전체 디스크를 무제한 탐색하지 않습니다. 제한 또는 접근 오류가 발생하면 보고서와 콘솔에 `일부 점검 미완료`가 표시됩니다.

자동 모드는 다음 우선순위에 따라 보고서 루트를 선택합니다.

1. 실행 파일 위치(모듈 실행 시 현재 디렉터리)의 `reports`
2. Windows: `%LOCALAPPDATA%\JVI\reports`
3. Linux: `$XDG_STATE_HOME/JVI/reports` 또는 `~/.local/state/JVI/reports`

점검마다 로컬 시작 시각을 사용한 `reports/YYYY-MM-DD_HH-MM-SS/` 폴더를 만들고, 그 안에 UTF-8 `JVI_HOSTNAME.html` 한 개만 저장합니다. 같은 초에 여러 점검이 시작되면 폴더에 `_001`, `_002`를 붙입니다. 폴더 생성은 원자적으로 수행되며 기존 폴더나 보고서를 삭제하거나 덮어쓰지 않습니다. PyInstaller 실행 시에는 `_MEIPASS`가 아니라 실행 파일이 있는 디렉터리를 기준으로 합니다.

자동 모드는 JSON, CSV, 별도 로그 파일을 만들지 않습니다. JSON/CSV 출력은 명시적 `scan --format ... --output ...` CLI에서 계속 사용할 수 있습니다. Streamlit UI의 기본 다운로드도 HTML 한 종류입니다.

HTML 상단의 **PDF로 저장 / 인쇄** 버튼은 브라우저의 인쇄 창을 엽니다. 인쇄 대상에서 PDF 저장을 선택할 수 있으며, 런타임에 PDF 라이브러리나 인터넷 연결은 필요하지 않습니다. A4 인쇄 스타일, 반복 표 머리글, 행 분할 방지, 긴 경로·근거의 줄바꿈 규칙을 문서 안에 포함합니다. 자동 점검이 브라우저를 직접 실행하지는 않습니다.

자동 모드 종료 코드는 다음과 같습니다. 기존 `scan` 명령의 종료 동작은 변경하지 않았습니다.

| 코드 | 의미 |
|---:|---|
| 0 | 전체 점검 완료, `AFFECTED` 없음 |
| 1 | 전체 점검 완료, `AFFECTED` 발견 |
| 2 | DB·보고서·예기치 않은 치명적 오류 |
| 3 | 일부 점검 미완료, `AFFECTED` 없음 |
| 4 | 일부 점검 미완료이며 `AFFECTED` 발견 |

Windows Explorer에서 콘솔 프로세스의 시작 주체를 완전히 신뢰성 있게 판별하기 어렵기 때문에 Python 본체는 입력 대기 없이 종료합니다. 더블클릭용 [JVI-OneClick.cmd](JVI-OneClick.cmd)는 같은 폴더의 `JVI.exe`를 우선 실행하고, 아직 exe가 없으면 `python -m jvi`를 실행한 뒤 Enter 입력까지 창을 유지합니다. PowerShell/CMD 및 Linux/SSH에서는 일반 `jvi` 또는 `python -m jvi`를 사용하면 불필요한 대기 없이 종료됩니다. 웹브라우저 실행이나 관리자 권한 상승은 수행하지 않습니다.

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

독립 실행형 서버 CLI에는 Streamlit을 포함하지 않습니다. 해당 바이너리에서 `ui`를 요청하면 지원되지 않는 기능임을 안내하고 종료 코드 2를 반환합니다.

`--path`는 반복할 수 있습니다. 기본 점검은 `release`와 로컬 설치/패키지 메타데이터만 읽으며 Java를 실행하지 않습니다. 메타데이터가 없는 런타임에 한해 사용자가 `--allow-java-execution`을 명시하면 `java -version`을 `shell=False`, 5초 제한으로 실행합니다.

주요 안전/범위 옵션:

- `--max-depth N`: 디렉터리 최대 깊이(기본 5)
- `--max-files N`: 확인할 최대 항목 수(기본 50,000)
- `--timeout SECONDS`: 전체 탐색 시간 제한(기본 60초)
- `--follow-symlinks`: 명시한 경우에만 링크 추적. 디렉터리 ID로 순환 방지
- `--no-package-info`: Linux의 `dpkg-query`/`rpm` 읽기 전용 소유 패키지 조회 생략
- `--advisory FILE`: 별도 JSON DB 사용
- `--no-integrity-check`: 동반 `.sha256` 검증을 명시적으로 생략

출력 파일을 지정하지 않으면 `human`, JSON, CSV, HTML 모두 표준 출력에 기록합니다. HTML은 CSS와 인쇄 버튼용 짧은 JavaScript를 문서에 포함하고 외부 스크립트, CDN, 외부 폰트를 사용하지 않아 인터넷 없이 열립니다. 보고서에서 제공하는 링크는 HTTP(S) 공식 근거만 활성화합니다.

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

Windows 탐색은 Symbolic Link뿐 아니라 Junction과 기타 Reparse Point를 `follow_symlinks=False`에서 따라가지 않습니다. Python 3.12 이상에서는 `Path.is_junction()`을 사용하고, Python 3.11에서는 Windows 파일 속성과 reparse tag를 사용합니다. 자동 발견된 호환성 Junction은 정상 제외 경로로 보고하므로 그 사실만으로 점검 미완료가 되지 않습니다. 반면 일반 디렉터리의 `PermissionError`, 파일 시스템 오류, Java 메타데이터 읽기 실패는 별도로 기록하고 점검 미완료에 반영합니다.

사용자가 `--path`로 지정했거나 `JAVA_HOME`·레지스트리 등으로 탐색 루트가 된 연결 경로는 해당 루트에 한해 진입합니다. 이후 발견되는 연결 디렉터리에는 다시 링크 추적 정책을 적용하며, 파일 ID/디바이스 ID로 중복 대상과 순환 참조를 차단합니다. 폴더 이름을 기준으로 `Windows NT` 같은 디렉터리를 광범위하게 제외하지 않습니다.

우선순위는 JDK/JRE `release` 파일 → JavaFX 메타데이터 → 패키지 관리자 정보 → 사용자가 승인한 `java -version`입니다. 버전은 Java 8의 update/build/perf 표기와 Java 11/17/21/25/27의 다중 숫자 표기를 정수 튜플로 정규화하며 문자열 사전식 비교를 사용하지 않습니다.

## 프로젝트 구조

```text
jvi/
  advisory.py   공식 JSON 로드, 스키마 및 SHA-256 검증
  autorun.py     무인 자동 점검, 보고서 경로 폴백, 종료 코드
  discovery.py  제한 기반 자산 탐색, 공급업체/제품 식별
  version.py    Java 버전 정규화와 비교
  engine.py     CVE별 독립 판정
  reporting.py  JSON/CSV/자급식 HTML 보고서
  workflow.py   CLI/UI/자동 모드 공통 점검 워크플로
  cli.py        argparse CLI
  ui.py         한국어 Streamlit UI와 백그라운드 중단 처리
data/advisories/oracle_2026_11.json
tests/          가상 release fixture 기반 pytest
packaging/      PyInstaller spec, OS별 빌드 스크립트와 배포 안내
scripts/        독립 실행 파일 black-box smoke test
```

상세 설계는 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)를 참고하십시오.

## 독립 실행형 배포

Windows x64와 Linux x86-64는 PyInstaller one-file을 기본으로 제공하며, 임시 실행 파일 정책이 엄격한 환경을 위해 one-folder 패키지도 생성합니다. 두 운영체제는 각각 해당 OS에서 빌드하며 크로스 컴파일하지 않습니다.

```powershell
# Windows x64 / Python 3.12
./packaging/build_windows.ps1 -Python python
```

```bash
# Linux x86-64 / Python 3.12
JVI_PYTHON=python3.12 bash packaging/build_linux.sh
```

빌드 스크립트는 테스트, PyInstaller 6.11.1 빌드, 고립 환경 smoke test, 원본/one-file/one-folder 판정 비교, 압축과 SHA-256 생성을 연속 수행합니다. GitHub Actions는 수동 실행과 `v*` 태그를 지원하며 테스트가 성공한 산출물만 Artifact/태그 릴리스로 전달합니다.

자세한 산출물 경로, glibc 2.28 기준선, `/tmp noexec` 대안, 플랫폼별 검증 상태는 [독립 실행형 빌드 및 배포 매뉴얼](docs/BUILDING.md)을 참고하십시오.

## 테스트

```bash
pytest
```

테스트는 실제 취약 Java 설치 없이 가상 `release` 파일과 `Asset` fixture를 사용합니다. 기존 판정 회귀 테스트와 함께 인자 없는 실행, 기존 CLI 파싱, 자동 범위 제한, Java 미설치/다중 설치, timeout, HTML 단일 자동 출력, 명시적 JSON/CSV 출력, 저장 경로 폴백/권한 실패, DB 오류, Windows Junction·Symbolic Link·Reparse Point·순환 참조, Python 3.11 속성 fallback, Windows/Linux/PyInstaller 경로, 한글 콘솔, 원자적 폴더 충돌 및 동시성, XSS·URL 스킴 방어, A4 인쇄 CSS를 검증합니다.

## 보안 특성

- 기본 읽기 전용이며 파일 수정/삭제, 자동 업데이트/패치, 악용 페이로드를 수행하지 않음
- 원격 호스트 스캔과 수집 정보 외부 전송 없음
- 네트워크가 필요한 런타임 기능 없음
- 링크 순환, 최대 깊이/항목 수/시간을 제한
- subprocess는 인자 배열과 `shell=False` 사용
- HTML은 모든 수집 문자열을 이스케이프하고 HTTP(S) 링크만 허용
- CSV 수식 주입 문자를 이스케이프
- 취약점 JSON은 동반 SHA-256 파일이 반드시 있어야 하며 로드 전에 검증

SHA-256은 파일 내용의 일치 여부를 확인하는 체크섬이며 배포자 신원을 보증하는 전자서명은 아닙니다. 독립 실행 파일은 내장 DB를 사용하고 런타임 다운로드나 자동 업데이트를 수행하지 않습니다.

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
- Windows Authenticode와 Linux 패키지 서명은 아직 적용하지 않았습니다. 제공되는 SHA-256은 코드 서명을 대체하지 않습니다.

