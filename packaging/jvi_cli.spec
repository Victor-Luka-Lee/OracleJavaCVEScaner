# -*- mode: python ; coding: utf-8 -*-
"""Shared PyInstaller spec for JVI one-file and one-folder CLI builds."""

import os
from pathlib import Path


project_root = Path(os.environ.get("JVI_PROJECT_ROOT", Path.cwd())).resolve()
build_mode = os.environ.get("JVI_BUILD_MODE", "onefile").lower()
if build_mode not in {"onefile", "onedir"}:
    raise ValueError("JVI_BUILD_MODE must be 'onefile' or 'onedir'")

target_name = "JVI" if os.name == "nt" else "jvi"
advisory_directory = project_root / "data" / "advisories"
datas = [
    (str(advisory_directory / "oracle_2026_11.json"), "jvi/data/advisories"),
    (str(advisory_directory / "oracle_2026_11.json.sha256"), "jvi/data/advisories"),
]

a = Analysis(
    [str(project_root / "packaging" / "jvi_entry.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["streamlit", "altair", "pandas", "pyarrow", "watchdog"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

if build_mode == "onefile":
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name=target_name,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=True,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name=target_name,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=True,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        name=f"{target_name}-onedir",
    )
