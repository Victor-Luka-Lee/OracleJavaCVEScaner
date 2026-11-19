Java Vulnerability Inspector (JVI)
==================================

JVI는 로컬 Java 설치를 읽기 전용으로 탐색하고 포함된 공식 공지 DB를
기준으로 CVE 영향을 평가합니다. 인터넷 연결이나 Python 설치가 필요하지
않으며 관리자/root 권한을 자동으로 요청하지 않습니다.

Windows
-------
1. ZIP 전체를 쓰기 가능한 폴더에 풉니다.
2. 터미널에서는 JVI.exe를 실행합니다.
3. Explorer에서는 JVI-OneClick.cmd를 더블클릭하면 결과를 확인할 때까지
   창이 유지됩니다. 점검 자체에는 입력이 필요하지 않습니다.

Linux
-----
1. tar.gz를 풉니다.
2. chmod +x jvi
3. ./jvi

인자 없는 실행은 실행 파일 옆 reports 폴더에 점검별 하위 폴더를 만들고
UTF-8 HTML 보고서 하나를 저장합니다. 쓰기 권한이 없으면 사용자 상태
폴더로 전환합니다. SSH/headless 환경에서도 브라우저를 실행하지 않습니다.

주요 명령
---------
JVI.exe --help                         (Linux: ./jvi --help)
JVI.exe scan --quick
JVI.exe scan --extended
JVI.exe scan --path "C:\Program Files\Java"

서버용 독립 실행 파일에는 Streamlit UI가 포함되지 않습니다. `ui` 명령은
명확한 미지원 메시지와 종료 코드 2를 반환합니다. UI가 필요하면 Python
소스 배포에서 `pip install -e ".[ui]"`를 사용하십시오.

무결성과 신뢰
-------------
내장 JSON DB는 동반 SHA-256 값과 비교됩니다. SHA-256은 파일이 빌드 때의
내용과 같은지 확인하는 체크섬이며, 배포자 신원을 증명하는 전자서명이
아닙니다. 릴리스 압축 파일은 SHA256SUMS.txt로 별도 확인하십시오.

종료 코드
---------
0: 완료/영향 없음, 1: 영향 확인, 2: 치명적 오류,
3: 일부 점검 미완료, 4: 일부 미완료 및 영향 확인

코드 1, 3, 4는 프로그램 기동 실패가 아니라 점검 결과입니다.

Linux one-file이 /tmp noexec 정책 때문에 시작되지 않으면 one-folder 패키지를
사용하십시오. 시스템 설정이나 SELinux 정책을 자동으로 변경하지 않습니다.
