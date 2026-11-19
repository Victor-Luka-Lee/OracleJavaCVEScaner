# JVI 독립 실행형 빌드 및 배포

JVI의 Windows와 Linux 바이너리는 각각 대상 운영체제에서 PyInstaller로 빌드합니다. 크로스 컴파일하지 않으며 Solaris, AIX, HP-UX는 이 릴리스 범위가 아닙니다.

## 고정 빌드 조합

- Python 3.12.x (`GitHub Actions: 3.12.8`)
- PyInstaller 6.11.1
- pip 24.3.1
- Windows: `windows-2022` x64
- Linux: 공식 `manylinux_2_28_x86_64:latest` 컨테이너(Python `cp312`), glibc 2.28 기준

Linux 이미지는 RHEL/Rocky Linux 8과 같은 glibc 2.28 기준선을 사용합니다. Python과 PyInstaller는 고정하지만 manylinux 기반 이미지의 보안 업데이트는 공식 `latest`를 따릅니다. 이것은 배포 호환성의 기준일 뿐 모든 배포판의 실제 실행 검증을 대신하지 않습니다.

## Windows 빌드

64비트 Python 3.12가 설치된 PowerShell에서 실행합니다.

```powershell
./packaging/build_windows.ps1 -Python python
```

스크립트는 별도 `.build-venv-windows`를 만들고 pytest, one-file/one-folder 빌드, PE 형식 확인, `--help`, UI 미포함 안내, fixture 판정 동등성, 인자 없는 실행과 HTML 보고서 검증을 수행합니다. 기존 Streamlit UI 회귀 테스트를 위해 빌드 환경에는 `[ui]` extra를 설치하지만 spec의 명시적 제외 목록 때문에 CLI 바이너리에는 포함되지 않습니다.

산출물:

```text
dist/JVI.exe
dist/JVI-onedir/JVI.exe
dist/JVI-Windows-x64.zip
dist/JVI-Windows-x64-onedir.zip
dist/SHA256SUMS-Windows.txt
```

기본 ZIP에는 `JVI.exe`, `JVI-OneClick.cmd`, `README.txt`가 들어갑니다. Explorer 사용자는 CMD 런처로 결과 창을 유지할 수 있고, 기존 PowerShell/CMD에서는 `JVI.exe`를 직접 실행하면 입력 대기 없이 종료 코드가 전달됩니다.

## Linux 빌드

대상 x86-64 Linux에서 Python 3.12 경로를 지정합니다.

```bash
JVI_PYTHON=/opt/python/cp312-cp312/bin/python bash packaging/build_linux.sh
```

산출물:

```text
dist/jvi
dist/jvi-onedir/jvi
dist/JVI-Linux-x64.tar.gz
dist/JVI-Linux-x64-onedir.tar.gz
dist/JVI-Linux-x64.file.txt
dist/JVI-Linux-x64.ldd.txt
dist/SHA256SUMS-Linux.txt
```

one-file은 실행 시 임시 디렉터리에 구성 요소를 풉니다. `/tmp`가 `noexec`이면 실행 가능한 전용 임시 경로를 관리자가 제공해 `TMPDIR`로 지정하거나, 압축 해제가 필요 없는 one-folder 패키지를 사용하십시오. JVI는 마운트 옵션이나 SELinux 정책을 변경하지 않습니다.

PyInstaller가 설정한 `LD_LIBRARY_PATH`는 `rpm`, `dpkg-query`, `java -version` 같은 시스템 자식 프로세스와 호환되지 않을 수 있습니다. JVI는 frozen POSIX 실행에서 `LD_LIBRARY_PATH_ORIG`를 복원하고, 원래 값이 없으면 번들 값을 제거한 환경 복사본만 자식 프로세스에 전달합니다. 부모 환경과 시스템 설정은 바꾸지 않습니다.

## 내장 데이터와 오프라인 동작

spec 파일은 아래 파일을 `jvi/data/advisories`로 포함합니다.

```text
oracle_2026_11.json
oracle_2026_11.json.sha256
```

런타임은 다운로드나 자동 업데이트를 하지 않습니다. DB 또는 체크섬이 빠졌거나 SHA-256이 일치하지 않으면 종료 코드 2로 실패합니다. `--advisory`와 `--no-integrity-check`는 기존 CLI와 동일하게 사용할 수 있습니다.

SHA-256은 내용 변조/손상을 탐지하는 체크섬입니다. 비밀키로 배포자 신원을 증명하는 코드 서명이나 전자서명은 아닙니다. Windows Authenticode 및 Linux 패키지 서명은 별도 배포 단계입니다.

## GitHub Actions

`.github/workflows/build-release.yml`은 수동 실행과 `v*` 태그 push를 지원합니다. Windows와 Linux를 각 대상 환경에서 별도로 빌드하며, 테스트와 smoke test를 통과한 산출물만 Artifact로 올립니다. 태그 작업에서는 두 빌드가 모두 성공한 뒤 통합 `SHA256SUMS.txt`를 만들고 해당 태그의 GitHub Release에 첨부합니다. 워크플로는 소스나 태그를 자동으로 push하지 않습니다.

Linux만 독립적으로 빌드할 때는 `.github/workflows/build-linux.yml`의 **Build Linux standalone** 워크플로를 사용합니다. `workflow_dispatch` 전용이고 `contents: read` 권한만 사용하며 Secret이 필요하지 않습니다. `/opt/python/cp312-cp312/bin/python`의 Python 3.12와 x86-64를 먼저 확인한 뒤 `packaging/build_linux.sh`를 한 번 호출합니다. 스크립트가 pytest, 두 PyInstaller 형식, ELF/ldd, smoke test, 압축 및 SHA-256을 모두 통과해야 `jvi-linux-x64` Artifact가 업로드됩니다.

```bash
gh workflow run build-linux.yml --ref main
gh run list --workflow build-linux.yml
gh run view RUN_ID --log
gh run download RUN_ID --name jvi-linux-x64
```

Artifact에는 `JVI-Linux-x64.tar.gz`, `JVI-Linux-x64-onedir.tar.gz`, `SHA256SUMS-Linux.txt`, `JVI-Linux-x64.file.txt`, `JVI-Linux-x64.ldd.txt`가 포함됩니다. 워크플로가 실패하면 `if-no-files-found: error` 및 작업 실패 상태를 유지하며 배포 성공으로 처리하지 않습니다.

## smoke test가 확인하는 항목

- PE/ELF 파일 형식과 `--help`
- Streamlit이 CLI 바이너리에 포함되지 않았고 `ui`가 명확히 실패하는지
- PATH와 Python 관련 환경 변수를 제거한 상태의 실행
- 내장 DB 및 SHA-256 검증을 거친 fixture 스캔
- Python 원본, one-file, one-folder의 자산/CVE 판정 동등성
- 공백·한글 경로로 이동한 one-file의 무인 실행
- 날짜/시간 실행 폴더와 HTML 한 개만 생성되는지
- 한국어 출력과 PDF 인쇄 버튼/A4 스타일
- 종료 코드 0, 1, 3, 4를 정상 점검 결과로 허용하고 2만 치명적 실패로 구분

## 플랫폼 검증 상태 기록 원칙

빌드 성공과 실제 OS 실행 검증은 별도입니다. GitHub Actions의 Windows Server 2022와 manylinux 2.28 컨테이너 결과만 자동 검증 완료로 기록합니다. Rocky Linux 8/9, RHEL 8/9, Ubuntu 22.04/24.04, Debian 12의 명칭은 테스트 목표이며, 해당 OS에서 산출물을 실행하지 않았다면 검증 완료로 표시하지 않습니다. SELinux enforcing과 `/tmp noexec` 역시 전용 환경에서 실제 확인하기 전에는 미검증으로 둡니다.
