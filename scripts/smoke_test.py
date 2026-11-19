"""Black-box smoke tests for PyInstaller JVI artifacts.

The script intentionally uses only the Python standard library.  It validates
the frozen executable with an empty PATH/Python environment, compares fixture
assessment results with the source CLI, and optionally performs a no-argument
one-click run.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Iterable


NORMAL_SCAN_CODES = {0, 1, 3, 4}


def _isolated_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV", "CONDA_PREFIX"):
        environment.pop(name, None)
    environment["PATH"] = ""
    environment["PYTHONUTF8"] = "1"
    return environment


def _run(
    command: Iterable[str | Path],
    *,
    cwd: Path,
    accepted: set[int],
    timeout: float = 240,
    isolated: bool = True,
) -> subprocess.CompletedProcess[str]:
    rendered = [str(item) for item in command]
    result = subprocess.run(
        rendered,
        cwd=cwd,
        env=_isolated_environment() if isolated else os.environ.copy(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
    )
    if result.returncode not in accepted:
        raise RuntimeError(
            f"command failed ({result.returncode}): {rendered}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _check_binary_format(executable: Path, expected: str) -> None:
    signature = executable.read_bytes()[:4]
    wanted = expected
    if wanted == "auto":
        wanted = "pe" if os.name == "nt" else "elf"
    if wanted == "pe" and not signature.startswith(b"MZ"):
        raise RuntimeError(f"not a Windows PE executable: {executable}")
    if wanted == "elf" and signature != b"\x7fELF":
        raise RuntimeError(f"not a Linux ELF executable: {executable}")


def _assessment_signature(payload: dict[str, object]) -> dict[str, object]:
    assets = payload.get("assets", [])
    findings = payload.get("findings", [])
    return {
        "database_version": payload.get("database_version"),
        "assets": sorted(
            (
                item.get("vendor"),
                item.get("product"),
                item.get("distribution"),
                item.get("full_version"),
                item.get("update_number"),
                item.get("build_number"),
                item.get("special_build"),
            )
            for item in assets
        ),
        "findings": sorted(
            (
                item.get("cve_id"),
                item.get("status"),
                (item.get("asset") or {}).get("vendor"),
                (item.get("asset") or {}).get("product"),
                (item.get("asset") or {}).get("full_version"),
                item.get("rationale"),
                item.get("confidence"),
                item.get("recommendation"),
            )
            for item in findings
        ),
    }


def _scan_fixture(command: list[str], project_root: Path, fixture_root: Path, output: Path) -> dict[str, object]:
    result = _run(
        [
            *command,
            "scan",
            "--path",
            fixture_root,
            "--max-depth",
            "5",
            "--max-files",
            "1000",
            "--timeout",
            "30",
            "--no-package-info",
            "--format",
            "json",
            "--output",
            output,
        ],
        cwd=project_root,
        accepted={0},
    )
    if "보고서 저장" not in result.stdout:
        raise RuntimeError("Korean CLI output was not emitted as UTF-8")
    return json.loads(output.read_text(encoding="utf-8"))


def _check_one_click(executable: Path, project_root: Path, *, relocate: bool) -> int:
    temporary: tempfile.TemporaryDirectory[str] | None = None
    run_executable = executable
    try:
        if relocate:
            temporary = tempfile.TemporaryDirectory(prefix="jvi-smoke-")
            unicode_directory = Path(temporary.name) / "JVI 공백 경로"
            unicode_directory.mkdir()
            run_executable = unicode_directory / executable.name
            shutil.copy2(executable, run_executable)
        report_root = run_executable.parent / "reports"
        before = set(report_root.iterdir()) if report_root.is_dir() else set()
        result = _run(
            [run_executable],
            cwd=project_root,
            accepted=NORMAL_SCAN_CODES,
            timeout=300,
        )
        if "[1/5] 시스템 환경" not in result.stdout or "[5/5]" not in result.stdout:
            raise RuntimeError("one-click Korean progress output is incomplete")
        after = set(report_root.iterdir()) if report_root.is_dir() else set()
        created = sorted(path for path in after - before if path.is_dir())
        if len(created) != 1:
            raise RuntimeError(f"expected one new report directory, got {created}")
        files = [path for path in created[0].rglob("*") if path.is_file()]
        if len(files) != 1 or files[0].suffix.lower() != ".html":
            raise RuntimeError(f"automatic mode must create one HTML only: {files}")
        html = files[0].read_text(encoding="utf-8")
        for marker in ("PDF로 저장 / 인쇄", "window.print()", "@page"):
            if marker not in html:
                raise RuntimeError(f"HTML report is missing print marker: {marker}")
        for directory in created:
            shutil.rmtree(directory)
        if report_root.is_dir() and not any(report_root.iterdir()):
            report_root.rmdir()
        return result.returncode
    finally:
        if temporary is not None:
            temporary.cleanup()


def _check_executable(executable: Path, project_root: Path, expected_format: str) -> None:
    if not executable.is_file():
        raise FileNotFoundError(executable)
    _check_binary_format(executable, expected_format)
    help_result = _run([executable, "--help"], cwd=project_root, accepted={0}, timeout=30)
    if "Java Vulnerability Inspector" not in help_result.stdout:
        raise RuntimeError("--help output is missing the application name")
    ui_result = _run([executable, "ui"], cwd=project_root, accepted={2}, timeout=30)
    if "Streamlit" not in (ui_result.stdout + ui_result.stderr):
        raise RuntimeError("server CLI did not explain that Streamlit UI is unavailable")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    parser.add_argument("--peer", type=Path)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--fixture-root", type=Path, default=Path("tests/fixtures/java_homes"))
    parser.add_argument("--expected-format", choices=["auto", "pe", "elf"], default="auto")
    parser.add_argument("--one-click", action="store_true")
    parser.add_argument("--relocate-onefile", action="store_true")
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    executable = args.executable.resolve()
    peer = args.peer.resolve() if args.peer else None
    fixture_root = (project_root / args.fixture_root).resolve() if not args.fixture_root.is_absolute() else args.fixture_root

    _check_executable(executable, project_root, args.expected_format)
    if peer:
        _check_executable(peer, project_root, args.expected_format)

    with tempfile.TemporaryDirectory(prefix="jvi-assessment-") as temporary:
        temporary_path = Path(temporary)
        source = _scan_fixture(
            [sys.executable, "-m", "jvi"],
            project_root,
            fixture_root,
            temporary_path / "source.json",
        )
        frozen = _scan_fixture(
            [str(executable)],
            project_root,
            fixture_root,
            temporary_path / "frozen.json",
        )
        expected = _assessment_signature(source)
        if _assessment_signature(frozen) != expected:
            raise RuntimeError("frozen and source CVE assessment results differ")
        if peer:
            peer_payload = _scan_fixture(
                [str(peer)],
                project_root,
                fixture_root,
                temporary_path / "peer.json",
            )
            if _assessment_signature(peer_payload) != expected:
                raise RuntimeError("one-file and one-folder assessment results differ")

    one_click_code: int | None = None
    if args.one_click:
        one_click_code = _check_one_click(
            executable,
            project_root,
            relocate=args.relocate_onefile,
        )

    print(f"smoke test passed: {executable}")
    if peer:
        print(f"peer comparison passed: {peer}")
    if one_click_code is not None:
        print(f"one-click exit code: {one_click_code} (valid assessment result)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
