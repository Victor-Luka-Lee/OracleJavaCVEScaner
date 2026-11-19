#!/usr/bin/env bash
set -euo pipefail

report_failure() {
  status=$?
  trap - ERR
  echo "Linux build failed at line ${BASH_LINENO[0]} (exit $status)." >&2
  exit "$status"
}
trap report_failure ERR

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${JVI_PYTHON:-python3.12}"
dist_root="$project_root/dist"
build_root="$project_root/build"
venv_root="$project_root/.build-venv-linux"
package_root="$build_root/packages-linux"

echo "[1/9] Python, 아키텍처 및 glibc 확인"
python_version="$($python_bin -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
[[ "$python_version" == 3.12.* ]] || { echo "검증된 Python 3.12.x가 필요합니다: $python_version" >&2; exit 2; }
[[ "$(uname -m)" == "x86_64" ]] || { echo "Linux x86-64 빌드만 지원합니다." >&2; exit 2; }
ldd --version 2>&1 | sed -n '1p'

echo "[2/9] 격리된 빌드 환경 준비"
"$python_bin" -m venv --clear "$venv_root"
venv_python="$venv_root/bin/python"
export PYTHONUTF8=1

echo "[3/9] 고정 의존성 설치"
"$venv_python" -m pip install --disable-pip-version-check "pip==24.3.1"
"$venv_python" -m pip install --disable-pip-version-check -e "$project_root[build,ui]"

echo "[4/9] pytest 실행"
mkdir -p "$dist_root" "$build_root"
"$venv_python" -m pytest --basetemp "$build_root/pytest-linux"

rm -f "$dist_root/jvi"
rm -rf "$dist_root/jvi-onedir"
export JVI_PROJECT_ROOT="$project_root"

echo "[5/9] PyInstaller one-file 빌드"
export JVI_BUILD_MODE=onefile
"$venv_python" -m PyInstaller --noconfirm --clean \
  --distpath "$dist_root" \
  --workpath "$build_root/pyinstaller-linux-onefile" \
  "$project_root/packaging/jvi_cli.spec"
test -x "$dist_root/jvi"

echo "[6/9] PyInstaller one-folder 빌드"
export JVI_BUILD_MODE=onedir
"$venv_python" -m PyInstaller --noconfirm --clean \
  --distpath "$dist_root" \
  --workpath "$build_root/pyinstaller-linux-onedir" \
  "$project_root/packaging/jvi_cli.spec"
test -x "$dist_root/jvi-onedir/jvi"

echo "[7/9] ELF, 동적 라이브러리 및 smoke test"
file "$dist_root/jvi" | tee "$dist_root/JVI-Linux-x64.file.txt"
grep -Eq 'ELF 64-bit.*x86-64' "$dist_root/JVI-Linux-x64.file.txt" || {
  echo "one-file 산출물이 Linux x86-64 ELF가 아닙니다." >&2
  exit 2
}
ldd "$dist_root/jvi" | tee "$dist_root/JVI-Linux-x64.ldd.txt"
if grep -q 'not found' "$dist_root/JVI-Linux-x64.ldd.txt"; then
  echo "해결되지 않은 공유 라이브러리 의존성이 있습니다." >&2
  exit 2
fi
"$venv_python" "$project_root/scripts/smoke_test.py" "$dist_root/jvi" \
  --peer "$dist_root/jvi-onedir/jvi" \
  --project-root "$project_root" \
  --expected-format elf \
  --one-click \
  --relocate-onefile

echo "[8/9] 배포 tar.gz 생성"
rm -rf "$package_root"
mkdir -p "$package_root/onefile" "$package_root/onedir"
cp "$dist_root/jvi" "$package_root/onefile/jvi"
cp "$project_root/packaging/README.txt" "$package_root/onefile/README.txt"
cp -a "$dist_root/jvi-onedir/." "$package_root/onedir/"
cp "$project_root/packaging/README.txt" "$package_root/onedir/README.txt"
chmod 0755 "$package_root/onefile/jvi" "$package_root/onedir/jvi"

onefile_archive="$dist_root/JVI-Linux-x64.tar.gz"
onedir_archive="$dist_root/JVI-Linux-x64-onedir.tar.gz"
rm -f "$onefile_archive" "$onedir_archive"
tar -czf "$onefile_archive" -C "$package_root/onefile" .
tar -czf "$onedir_archive" -C "$package_root/onedir" .

echo "[9/9] SHA-256 및 결과 요약"
(
  cd "$dist_root"
  sha256sum "$(basename "$onefile_archive")" "$(basename "$onedir_archive")" > SHA256SUMS-Linux.txt
  sha256sum --check SHA256SUMS-Linux.txt
)
echo "PyInstaller: $($venv_python -m PyInstaller --version)"
echo "One-file: $dist_root/jvi"
echo "One-folder: $dist_root/jvi-onedir"
echo "Release: $onefile_archive"
echo "Fallback: $onedir_archive"
echo "Checksums: $dist_root/SHA256SUMS-Linux.txt"
