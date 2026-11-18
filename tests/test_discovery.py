from __future__ import annotations

import os
from pathlib import Path

import pytest

from jvi.discovery import ScanConfig, discover, identify_home


def _write_release(home: Path, implementor: str, version: str, runtime_name: str = "OpenJDK Runtime Environment") -> None:
    home.mkdir(parents=True)
    (home / "release").write_text(
        f'IMPLEMENTOR="{implementor}"\nJAVA_VERSION="{version}"\nJAVA_RUNTIME_NAME="{runtime_name}"\n',
        encoding="utf-8",
    )


def test_oracle_and_openjdk_are_distinguished(fixture_homes):
    oracle = identify_home(fixture_homes / "oracle-17", collect_package_info=False)
    temurin = identify_home(fixture_homes / "temurin-21", collect_package_info=False)
    assert (oracle.vendor, oracle.product) == ("Oracle", "Oracle Java SE")
    assert (temurin.vendor, temurin.product, temurin.distribution) == (
        "Eclipse Adoptium",
        "OpenJDK",
        "Eclipse Temurin",
    )


def test_multiple_java_installations(tmp_path):
    _write_release(tmp_path / "app-a" / "jre", "Oracle Corporation", "17.0.21.0.3", "Java(TM) SE Runtime Environment")
    _write_release(tmp_path / "app-b" / "jdk", "Amazon.com Inc.", "21.0.13")
    result = discover(ScanConfig(roots=[tmp_path], max_depth=4, collect_package_info=False))
    assert len(result.assets) == 2
    assert {asset.vendor for asset in result.assets} == {"Oracle", "Amazon"}


def test_symlink_cycle_is_bounded(tmp_path, monkeypatch):
    home = tmp_path / "tree" / "jdk"
    _write_release(home, "Oracle Corporation", "17.0.21.0.3", "Java(TM) SE Runtime Environment")
    cycle = home / "cycle"
    try:
        cycle.symlink_to(tmp_path / "tree", target_is_directory=True)
    except OSError:
        # Windows commonly disallows symlink creation without Developer Mode.
        # Model a followed link back to an already visited directory so the
        # cycle detector is still exercised on such hosts.
        root = tmp_path / "tree"
        original = os.scandir

        class CycleEntry:
            name = "cycle"
            path = str(root)

            @staticmethod
            def is_dir(*, follow_symlinks=True):
                return True

            @staticmethod
            def is_symlink():
                return True

        class ScanEntries:
            def __init__(self, entries):
                self.entries = entries

            def __enter__(self):
                return iter(self.entries)

            def __exit__(self, *_):
                return False

        def with_cycle(path):
            if Path(path) == home:
                with original(path) as iterator:
                    return ScanEntries([*iterator, CycleEntry()])
            return original(path)

        monkeypatch.setattr("jvi.discovery.os.scandir", with_cycle)
    result = discover(
        ScanConfig(
            roots=[tmp_path / "tree"],
            max_depth=20,
            max_files=1_000,
            follow_symlinks=True,
            collect_package_info=False,
        )
    )
    assert len(result.assets) == 1
    assert result.examined_entries < 100


def test_permission_error_is_recorded_and_scan_continues(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    denied = tmp_path / "denied"
    _write_release(allowed, "Oracle Corporation", "21.0.13.0.3", "Java(TM) SE Runtime Environment")
    denied.mkdir()
    original = os.scandir

    def guarded(path):
        if Path(path) == denied:
            raise PermissionError("fixture denied")
        return original(path)

    monkeypatch.setattr("jvi.discovery.os.scandir", guarded)
    result = discover(ScanConfig(roots=[tmp_path], max_depth=2, collect_package_info=False))
    assert len(result.assets) == 1
    assert any("PermissionError" in error for error in result.errors)


def test_java_absent_returns_empty_result(tmp_path):
    (tmp_path / "ordinary.txt").write_text("not java", encoding="utf-8")
    result = discover(ScanConfig(roots=[tmp_path], max_depth=2, collect_package_info=False))
    assert result.assets == []

