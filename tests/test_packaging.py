from __future__ import annotations

import ast
from pathlib import Path
import runpy
import tomllib

from jvi import cli


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_cli_dependencies_keep_streamlit_optional():
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["dependencies"] == []
    assert any(item.startswith("streamlit") for item in project["project"]["optional-dependencies"]["ui"])
    assert "pyinstaller==6.11.1" in project["project"]["optional-dependencies"]["build"]


def test_pyinstaller_entry_propagates_cli_exit_code(monkeypatch):
    monkeypatch.setattr(cli, "main", lambda: 4)
    namespace = runpy.run_path(str(PROJECT_ROOT / "packaging" / "jvi_entry.py"))
    assert namespace["run"]() == 4


def test_spec_is_valid_python_and_bundles_only_required_database_files():
    source = (PROJECT_ROOT / "packaging" / "jvi_cli.spec").read_text(encoding="utf-8")
    ast.parse(source)
    assert "oracle_2026_11.json" in source
    assert "oracle_2026_11.json.sha256" in source
    assert 'excludes=["streamlit"' in source
    assert "upx=False" in source
    assert "console=True" in source


def test_build_automation_and_release_workflow_exist():
    required = [
        "packaging/build_windows.ps1",
        "packaging/build_linux.sh",
        "scripts/smoke_test.py",
        ".github/workflows/build-release.yml",
        "docs/BUILDING.md",
    ]
    assert all((PROJECT_ROOT / item).is_file() for item in required)
    workflow = (PROJECT_ROOT / ".github/workflows/build-release.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch" in workflow
    assert 'tags:' in workflow
    assert "JVI-Windows-x64.zip" in workflow
    assert "JVI-Linux-x64-onedir.tar.gz" in workflow


def test_windows_launcher_prefers_exe_and_preserves_exit_code():
    launcher = (PROJECT_ROOT / "JVI-OneClick.cmd").read_text(encoding="utf-8")
    assert 'if exist "%~dp0JVI.exe"' in launcher
    assert '"%~dp0JVI.exe"' in launcher
    assert "exit /b %JVI_EXIT%" in launcher
