from __future__ import annotations

import os
from pathlib import Path

import pytest

from jvi import discovery
from jvi.discovery import (
    PathLinkInfo,
    ScanConfig,
    _path_link_info,
    _system_subprocess_environment,
    discover,
    identify_home,
)


MOUNT_POINT_TAG = 0xA0000003
SYMLINK_TAG = 0xA000000C


def test_frozen_posix_child_environment_restores_system_loader_paths():
    environment = _system_subprocess_environment(
        frozen=True,
        platform_name="posix",
        environ={
            "PATH": "/usr/bin",
            "LD_LIBRARY_PATH": "/tmp/_MEI/lib",
            "LD_LIBRARY_PATH_ORIG": "/usr/local/lib",
            "LIBPATH": "/tmp/_MEI/lib",
        },
    )
    assert environment["LD_LIBRARY_PATH"] == "/usr/local/lib"
    assert "LIBPATH" not in environment
    assert environment["PATH"] == "/usr/bin"


def test_non_frozen_child_environment_is_unchanged():
    source = {"LD_LIBRARY_PATH": "/custom/lib"}
    assert _system_subprocess_environment(
        frozen=False,
        platform_name="posix",
        environ=source,
    ) == source


def _write_release(home: Path, implementor: str, version: str, runtime_name: str = "OpenJDK Runtime Environment") -> None:
    home.mkdir(parents=True)
    (home / "release").write_text(
        f'IMPLEMENTOR="{implementor}"\nJAVA_VERSION="{version}"\nJAVA_RUNTIME_NAME="{runtime_name}"\n',
        encoding="utf-8",
    )


def _mock_link(monkeypatch, target: Path, info: PathLinkInfo):
    original = discovery._path_link_info

    def classify(value, **kwargs):
        path = value if isinstance(value, Path) else Path(value.path)
        if path == target:
            return info
        return original(value, **kwargs)

    monkeypatch.setattr(discovery, "_path_link_info", classify)


def test_python311_attribute_fallback_detects_windows_junction():
    class Result:
        st_file_attributes = 0x400
        st_reparse_tag = MOUNT_POINT_TAG

    class Entry:
        path = r"C:\Program Files\Windows NT\보조프로그램"

        @staticmethod
        def stat(*, follow_symlinks):
            assert follow_symlinks is False
            return Result()

        @staticmethod
        def is_symlink():
            return False

    info = _path_link_info(Entry(), platform_name="nt")
    assert info.is_junction is True
    assert info.is_reparse_point is True
    assert info.path_type == "junction"


def test_python312_is_junction_fallback_is_used_for_unknown_reparse_tag(monkeypatch):
    class Result:
        st_file_attributes = 0x400
        st_reparse_tag = 0x9000001A

    class Entry:
        path = r"C:\virtual-junction"

        @staticmethod
        def stat(*, follow_symlinks):
            return Result()

        @staticmethod
        def is_symlink():
            return False

    monkeypatch.setattr(Path, "is_junction", lambda self: True, raising=False)
    assert _path_link_info(Entry(), platform_name="nt").is_junction is True


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
    assert result.issues[0].category == "permission"
    assert result.issues[0].path == str(denied)
    assert result.incomplete is True


def test_discovered_junction_is_normally_skipped_without_incomplete(tmp_path, monkeypatch):
    allowed = tmp_path / "Java" / "jdk"
    compatibility_junction = tmp_path / "Windows NT" / "보조프로그램"
    _write_release(allowed, "Oracle Corporation", "21.0.13.0.3", "Java(TM) SE Runtime Environment")
    compatibility_junction.mkdir(parents=True)
    _mock_link(
        monkeypatch,
        compatibility_junction,
        PathLinkInfo(is_junction=True, is_reparse_point=True, reparse_tag=MOUNT_POINT_TAG),
    )

    result = discover(ScanConfig(roots=[tmp_path], max_depth=4, collect_package_info=False))

    assert len(result.assets) == 1
    assert result.errors == []
    assert result.incomplete is False
    assert any(
        item.path == str(compatibility_junction)
        and item.path_type == "junction"
        and item.reason == "link_not_followed"
        for item in result.skipped_paths
    )


def test_symbolic_link_is_skipped_when_following_is_disabled(tmp_path, monkeypatch):
    link = tmp_path / "linked-java"
    link.mkdir()
    _mock_link(
        monkeypatch,
        link,
        PathLinkInfo(is_symlink=True, is_reparse_point=True, reparse_tag=SYMLINK_TAG),
    )
    result = discover(
        ScanConfig(roots=[tmp_path], max_depth=2, follow_symlinks=False, collect_package_info=False)
    )
    assert any(item.path == str(link) and item.path_type == "symbolic_link" for item in result.skipped_paths)
    assert result.incomplete is False


def test_explicit_java_root_junction_is_traversed_once(tmp_path, monkeypatch):
    linked_home = tmp_path / "linked-jdk"
    _write_release(linked_home, "Oracle Corporation", "17.0.21.0.3", "Java(TM) SE Runtime Environment")
    _mock_link(
        monkeypatch,
        linked_home,
        PathLinkInfo(is_junction=True, is_reparse_point=True, reparse_tag=MOUNT_POINT_TAG),
    )
    result = discover(
        ScanConfig(
            roots=[linked_home],
            max_depth=2,
            follow_symlinks=False,
            collect_package_info=False,
        )
    )
    assert len(result.assets) == 1
    assert result.assets[0].install_path == str(linked_home)
    assert result.root_links[0].root_origin == "user_supplied"
    assert result.root_links[0].reason == "root_link_traversed"
    assert result.incomplete is False


def test_junction_cycle_is_stopped_by_directory_identity(tmp_path, monkeypatch):
    root = tmp_path / "tree"
    home = root / "jdk"
    _write_release(home, "Oracle Corporation", "17.0.21.0.3", "Java(TM) SE Runtime Environment")
    original_scandir = os.scandir

    class CycleEntry:
        name = "cycle-junction"
        path = str(root)

        @staticmethod
        def is_dir(*, follow_symlinks=True):
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
            with original_scandir(path) as iterator:
                return ScanEntries([*iterator, CycleEntry()])
        return original_scandir(path)

    original_link_info = discovery._path_link_info

    def classify(value, **kwargs):
        if isinstance(value, CycleEntry):
            return PathLinkInfo(is_junction=True, is_reparse_point=True, reparse_tag=MOUNT_POINT_TAG)
        return original_link_info(value, **kwargs)

    monkeypatch.setattr(discovery.os, "scandir", with_cycle)
    monkeypatch.setattr(discovery, "_path_link_info", classify)
    result = discover(
        ScanConfig(
            roots=[root],
            max_depth=20,
            max_files=1_000,
            follow_symlinks=True,
            collect_package_info=False,
        )
    )
    assert len(result.assets) == 1
    assert result.examined_entries < 100
    assert any(item.reason == "duplicate_target" for item in result.skipped_paths)


def test_java_absent_returns_empty_result(tmp_path):
    (tmp_path / "ordinary.txt").write_text("not java", encoding="utf-8")
    result = discover(ScanConfig(roots=[tmp_path], max_depth=2, collect_package_info=False))
    assert result.assets == []


def test_timeout_marks_scan_incomplete(tmp_path, monkeypatch):
    (tmp_path / "directory").mkdir()
    ticks = iter([0.0, 1.0])
    monkeypatch.setattr("jvi.discovery.time.monotonic", lambda: next(ticks, 1.0))
    result = discover(
        ScanConfig(
            roots=[tmp_path],
            max_depth=7,
            timeout_seconds=0.5,
            collect_package_info=False,
        )
    )
    assert result.stopped is True
    assert result.incomplete is True
    assert "timeout" in result.limit_reasons

