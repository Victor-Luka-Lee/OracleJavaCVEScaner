"""Bounded, read-only Java discovery for Windows and Linux."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import platform
import re
import shutil
import stat as stat_module
import subprocess
import sys
import threading
import time
from typing import Callable, Iterable, Mapping

from .models import Asset
from .version import JavaVersion, try_parse


ProgressCallback = Callable[[int, str], None]
MetadataErrorCallback = Callable[[Path, OSError], None]

_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_IO_REPARSE_TAG_MOUNT_POINT = getattr(stat_module, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)
_IO_REPARSE_TAG_SYMLINK = getattr(stat_module, "IO_REPARSE_TAG_SYMLINK", 0xA000000C)


@dataclass(slots=True)
class ScanConfig:
    roots: list[Path] = field(default_factory=list)
    mode: str = "quick"
    max_depth: int = 5
    max_files: int = 50_000
    timeout_seconds: float = 60.0
    follow_symlinks: bool = False
    allow_java_execution: bool = False
    collect_package_info: bool = True


@dataclass(slots=True)
class DiscoveryResult:
    assets: list[Asset]
    errors: list[str]
    examined_entries: int
    stopped: bool
    incomplete: bool
    limit_reasons: list[str]
    roots: list[str]
    issues: list[DiscoveryIssue] = field(default_factory=list)
    skipped_paths: list[SkippedPath] = field(default_factory=list)
    root_links: list[SkippedPath] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class DiscoveryIssue:
    category: str
    path: str
    operation: str
    error_type: str
    message: str

    def summary(self) -> str:
        labels = {
            "permission": "접근 권한 오류",
            "filesystem": "파일 시스템 오류",
            "java_metadata": "Java 메타데이터 읽기 실패",
        }
        label = labels.get(self.category, self.category)
        return f"[{label}] {self.operation}: {self.path} ({self.error_type})"

    def to_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "path": self.path,
            "operation": self.operation,
            "error_type": self.error_type,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class SkippedPath:
    path: str
    path_type: str
    reason: str
    reparse_tag: int | None = None
    root_origin: str | None = None

    def to_dict(self) -> dict[str, str | int | None]:
        return {
            "path": self.path,
            "path_type": self.path_type,
            "reason": self.reason,
            "reparse_tag": self.reparse_tag,
            "reparse_tag_hex": f"0x{self.reparse_tag:08X}" if self.reparse_tag is not None else None,
            "root_origin": self.root_origin,
        }


@dataclass(frozen=True, slots=True)
class PathLinkInfo:
    is_symlink: bool = False
    is_junction: bool = False
    is_reparse_point: bool = False
    reparse_tag: int | None = None

    @property
    def is_link_like(self) -> bool:
        return self.is_symlink or self.is_junction or self.is_reparse_point

    @property
    def path_type(self) -> str:
        if self.is_junction:
            return "junction"
        if self.is_symlink:
            return "symbolic_link"
        if self.is_reparse_point:
            return "reparse_point"
        return "directory"


def _entry_path(value: Path | os.DirEntry[str]) -> Path:
    return value if isinstance(value, Path) else Path(value.path)


def _path_link_info(
    value: Path | os.DirEntry[str],
    *,
    platform_name: str | None = None,
) -> PathLinkInfo:
    """Classify links without following their targets.

    Python 3.12 provides Path.is_junction(). Python 3.11 still exposes the
    Windows file attributes and reparse tag through lstat/stat_result, which
    is sufficient to identify mount-point junctions and symbolic links.
    """
    path = _entry_path(value)
    if isinstance(value, Path):
        result = value.lstat()
        is_symlink = value.is_symlink()
    else:
        stat_method = getattr(value, "stat", None)
        result = stat_method(follow_symlinks=False) if callable(stat_method) else path.lstat()
        is_symlink = value.is_symlink()
    attributes = int(getattr(result, "st_file_attributes", 0) or 0)
    reparse_tag = getattr(result, "st_reparse_tag", None)
    is_reparse = bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
    is_junction = reparse_tag == _IO_REPARSE_TAG_MOUNT_POINT
    if reparse_tag == _IO_REPARSE_TAG_SYMLINK:
        is_symlink = True

    system_name = os.name if platform_name is None else platform_name
    junction_check = getattr(path, "is_junction", None)
    if system_name == "nt" and is_reparse and not is_junction and callable(junction_check):
        try:
            is_junction = bool(junction_check())
        except OSError:
            # lstat above already supplied the non-following attributes. A
            # failed convenience check must not turn a known reparse point
            # into a target access attempt.
            pass
    return PathLinkInfo(
        is_symlink=is_symlink,
        is_junction=is_junction,
        is_reparse_point=is_reparse,
        reparse_tag=reparse_tag,
    )


def _system_subprocess_environment(
    *,
    frozen: bool | None = None,
    platform_name: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Restore system loader paths before invoking package-manager commands.

    PyInstaller adjusts loader variables for its bundled libraries. Passing
    those values to rpm/dpkg can make the system executable load incompatible
    bundled libraries, so frozen POSIX builds restore the original values.
    """
    environment = dict(os.environ if environ is None else environ)
    is_frozen = getattr(sys, "frozen", False) if frozen is None else frozen
    system_name = os.name if platform_name is None else platform_name
    if is_frozen and system_name != "nt":
        for variable in ("LD_LIBRARY_PATH", "LIBPATH", "DYLD_LIBRARY_PATH"):
            original = f"{variable}_ORIG"
            if original in environment:
                environment[variable] = environment[original]
            else:
                environment.pop(variable, None)
    return environment


def _clean_property(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return value.replace(r"\"", '"')


def parse_release(
    path: Path,
    *,
    on_error: MetadataErrorCallback | None = None,
) -> dict[str, str]:
    properties: dict[str, str] = {}
    try:
        if path.stat().st_size > 1_048_576:
            return properties
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        if on_error:
            on_error(path, exc)
        return properties
    for line in text.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            properties[key] = _clean_property(value)
    return properties


def _canonical_vendor(implementor: str, combined: str) -> str:
    text = f"{implementor} {combined}".lower()
    if "oracle" in text:
        return "Oracle"
    if "eclipse" in text or "adoptium" in text or "temurin" in text:
        return "Eclipse Adoptium"
    if "amazon" in text or "corretto" in text:
        return "Amazon"
    if "azul" in text or "zulu" in text:
        return "Azul"
    if "microsoft" in text:
        return "Microsoft"
    if "red hat" in text:
        return "Red Hat"
    if "graalvm community" in text:
        return "GraalVM Community"
    if "openjdk" in text:
        return "OpenJDK"
    return "Unknown"


def _product_and_distribution(vendor: str, properties: dict[str, str], home: Path) -> tuple[str, str]:
    combined = " ".join(properties.values()) + " " + str(home)
    lower = combined.lower()
    if "graalvm" in lower:
        if vendor == "Oracle":
            if "enterprise" in lower or properties.get("GRAALVM_EDITION", "").lower() == "ee":
                return "Oracle GraalVM Enterprise Edition", "Oracle GraalVM Enterprise Edition"
            return "Oracle GraalVM for JDK", "Oracle GraalVM for JDK"
        return "GraalVM Community", "GraalVM Community"
    if vendor == "Oracle":
        return "Oracle Java SE", "Oracle JDK/JRE"
    distributions = {
        "Eclipse Adoptium": "Eclipse Temurin",
        "Amazon": "Amazon Corretto",
        "Azul": "Azul Zulu",
        "Microsoft": "Microsoft Build of OpenJDK",
        "Red Hat": "Red Hat OpenJDK",
        "OpenJDK": "OpenJDK",
        "GraalVM Community": "GraalVM Community",
        "Unknown": "Unknown OpenJDK/JVM",
    }
    return "OpenJDK", distributions[vendor]


def _select_version(properties: dict[str, str]) -> str | None:
    candidates = [
        properties.get("JAVA_RUNTIME_VERSION"),
        properties.get("FULL_VERSION"),
        properties.get("JAVA_VERSION"),
    ]
    parsed = [(value, try_parse(value)) for value in candidates if value]
    parsed = [(value, version) for value, version in parsed if version]
    if not parsed:
        return next((value for value in candidates if value), None)
    # Prefer the representation carrying the most version/build detail.
    return max(parsed, key=lambda pair: (len(pair[1].numbers), pair[1].build is not None, len(pair[0])))[0]


def _package_owner(java_binary: Path) -> str | None:
    if os.name == "nt":
        return None
    commands: list[list[str]] = []
    if shutil.which("dpkg-query"):
        commands.append(["dpkg-query", "-S", str(java_binary)])
    if shutil.which("rpm"):
        commands.append(["rpm", "-qf", str(java_binary)])
    for command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
                shell=False,
                env=_system_subprocess_environment(),
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0][:500]
    return None


def _java_binary(home: Path) -> Path:
    return home / "bin" / ("java.exe" if os.name == "nt" else "java")


def _version_from_execution(binary: Path) -> tuple[str | None, str | None]:
    try:
        result = subprocess.run(
            [str(binary), "-version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            shell=False,
            env=_system_subprocess_environment(),
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    output = (result.stderr + "\n" + result.stdout).strip()[:4096]
    match = re.search(r'(?:java|openjdk) version\s+"([^"]+)"', output, re.IGNORECASE)
    return (match.group(1) if match else None), output


def identify_home(
    home: Path,
    *,
    allow_execution: bool = False,
    collect_package_info: bool = True,
    on_metadata_error: MetadataErrorCallback | None = None,
) -> Asset:
    properties = parse_release(home / "release", on_error=on_metadata_error)
    evidence: list[str] = []
    if properties:
        evidence.append(f"release metadata: {home / 'release'}")
    version_text = _select_version(properties)
    execution_output: str | None = None
    binary = _java_binary(home)
    if not version_text and allow_execution and binary.is_file():
        version_text, execution_output = _version_from_execution(binary)
        if execution_output:
            evidence.append("user-approved java -version output")

    combined = " ".join(properties.values())
    if execution_output:
        combined += " " + execution_output
    vendor = _canonical_vendor(properties.get("IMPLEMENTOR", ""), combined)
    product, distribution = _product_and_distribution(vendor, properties, home)
    parsed = try_parse(version_text)
    special = parsed.variant if parsed else None
    if not special and re.search(r"(?:^|[-_ ])perf(?:$|[-_ ])", combined + " " + str(home), re.IGNORECASE):
        special = "perf"
    metadata = dict(properties)
    if collect_package_info and binary.exists():
        package = _package_owner(binary)
        if package:
            metadata["PACKAGE_OWNER"] = package
            evidence.append("local package manager ownership metadata")
    if not evidence:
        evidence.append(f"Java binary path only: {binary}")
    return Asset(
        product=product,
        vendor=vendor,
        distribution=distribution,
        java_major=parsed.major if parsed else None,
        full_version=version_text,
        update_number=parsed.update if parsed else None,
        build_number=parsed.build if parsed else None,
        special_build=special,
        install_path=str(home),
        evidence=evidence,
        metadata=metadata,
    )


def identify_javafx(
    home: Path,
    vendor: str,
    *,
    on_metadata_error: MetadataErrorCallback | None = None,
) -> Asset | None:
    candidates = [home / "lib" / "javafx.properties", home / "javafx.properties"]
    for path in candidates:
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")[:65536]
        except OSError as exc:
            if on_metadata_error:
                on_metadata_error(path, exc)
            continue
        match = re.search(r"^(?:javafx\.version|version)\s*=\s*([^\s#]+)", text, re.MULTILINE)
        version_text = match.group(1).strip('"\'') if match else None
        parsed = try_parse(version_text)
        return Asset(
            product="Oracle JavaFX" if vendor == "Oracle" else "OpenJFX",
            vendor=vendor,
            distribution="Oracle JavaFX" if vendor == "Oracle" else "OpenJFX",
            java_major=parsed.major if parsed else None,
            full_version=version_text,
            update_number=parsed.update if parsed else None,
            build_number=parsed.build if parsed else None,
            special_build=parsed.variant if parsed else None,
            install_path=str(home),
            evidence=[f"JavaFX metadata: {path}"],
            metadata={},
        )
    return None


def _registry_roots() -> list[Path]:
    if os.name != "nt":
        return []
    try:
        import winreg
    except ImportError:
        return []
    roots: list[Path] = []
    key_paths = [
        r"SOFTWARE\JavaSoft\Java Runtime Environment",
        r"SOFTWARE\JavaSoft\JDK",
        r"SOFTWARE\JavaSoft\Java Development Kit",
        r"SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment",
        r"SOFTWARE\WOW6432Node\JavaSoft\JDK",
    ]
    for key_path in key_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                count, _, _ = winreg.QueryInfoKey(key)
                for index in range(count):
                    version_key = winreg.EnumKey(key, index)
                    try:
                        with winreg.OpenKey(key, version_key) as child:
                            value, _ = winreg.QueryValueEx(child, "JavaHome")
                            roots.append(Path(value))
                    except OSError:
                        continue
        except OSError:
            continue
    return roots


def default_roots(mode: str = "quick") -> list[Path]:
    roots: list[Path] = []
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        roots.append(Path(java_home))
    for item in os.environ.get("PATH", "").split(os.pathsep):
        if not item:
            continue
        directory = Path(item)
        binary = directory / ("java.exe" if os.name == "nt" else "java")
        if binary.is_file():
            roots.append(directory.parent if directory.name.lower() == "bin" else directory)
    roots.extend(_registry_roots())
    if os.name == "nt":
        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(env_name)
            if not base:
                continue
            base_path = Path(base)
            for child in ("Java", "Eclipse Adoptium", "Amazon Corretto", "Microsoft", "Zulu"):
                roots.append(base_path / child)
            if mode == "extended":
                roots.append(base_path)
    else:
        roots.append(Path("/usr/lib/jvm"))
        if mode == "extended":
            roots.extend([Path("/opt"), Path("/usr/local")])
    return _deduplicate_paths(path for path in roots if path.exists())


def _deduplicate_paths(paths: Iterable[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        try:
            key = os.path.normcase(str(path.resolve(strict=False)))
        except OSError:
            key = os.path.normcase(str(path.absolute()))
        if key not in seen:
            seen.add(key)
            result.append(path)
    return result


def _directory_priority(path: Path) -> tuple[int, str]:
    """Visit likely Java locations first without excluding any directory."""
    name = path.name.casefold()
    exact = {
        "java",
        "jdk",
        "jre",
        "jvm",
        "eclipse adoptium",
        "amazon corretto",
        "zulu",
        "microsoft",
    }
    if name in exact:
        return (0, name)
    if any(token in name for token in ("java", "jdk", "jre", "jvm", "temurin", "corretto")):
        return (1, name)
    return (2, name)


def discover(
    config: ScanConfig,
    *,
    stop_event: threading.Event | None = None,
    progress: ProgressCallback | None = None,
) -> DiscoveryResult:
    stop_event = stop_event or threading.Event()
    user_supplied_roots = bool(config.roots)
    roots = _deduplicate_paths(config.roots or default_roots(config.mode))
    start = time.monotonic()
    examined = 0
    errors: list[str] = []
    issues: list[DiscoveryIssue] = []
    skipped_paths: list[SkippedPath] = []
    root_links: list[SkippedPath] = []
    assets: list[Asset] = []
    homes_seen: set[str] = set()
    dirs_seen: set[tuple[int, int] | str] = set()
    stopped = False
    limit_reasons: set[str] = set()

    def limit_reason() -> str | None:
        if stop_event.is_set():
            return "stop_requested"
        if examined >= config.max_files:
            return "max_files"
        if time.monotonic() - start >= config.timeout_seconds:
            return "timeout"
        return None

    def record_issue(
        path: Path | str,
        operation: str,
        exc: OSError,
        *,
        category: str | None = None,
    ) -> None:
        resolved_category = category or ("permission" if isinstance(exc, PermissionError) else "filesystem")
        issue = DiscoveryIssue(
            category=resolved_category,
            path=str(path),
            operation=operation,
            error_type=exc.__class__.__name__,
            message=str(exc)[:500],
        )
        issues.append(issue)
        errors.append(issue.summary())

    def metadata_error(path: Path, exc: OSError) -> None:
        record_issue(path, "메타데이터 읽기", exc, category="java_metadata")

    def path_key(path: Path) -> str:
        try:
            return os.path.normcase(str(path.resolve(strict=False)))
        except OSError:
            return os.path.normcase(str(path.absolute()))

    root_origin = "user_supplied" if user_supplied_roots else "automatic_root"
    stack: list[tuple[Path, int, bool, PathLinkInfo | None]] = [
        (root, 0, True, None) for root in reversed(roots)
    ]
    while stack:
        reason = limit_reason()
        if reason:
            limit_reasons.add(reason)
            stopped = True
            break
        directory, depth, is_root, known_link_info = stack.pop()
        if known_link_info is None:
            try:
                link_info = _path_link_info(directory)
            except OSError as exc:
                record_issue(directory, "경로 속성 확인", exc)
                continue
        else:
            link_info = known_link_info
        if link_info.is_link_like and not config.follow_symlinks and not is_root:
            skipped_paths.append(
                SkippedPath(
                    path=str(directory),
                    path_type=link_info.path_type,
                    reason="link_not_followed",
                    reparse_tag=link_info.reparse_tag,
                )
            )
            continue
        if link_info.is_link_like and is_root:
            # A root is an explicit scan boundary (user path, JAVA_HOME,
            # registry or a high-confidence default). Traverse that one root,
            # while discovered links still obey follow_symlinks=False.
            root_links.append(
                SkippedPath(
                    path=str(directory),
                    path_type=link_info.path_type,
                    reason="root_link_traversed",
                    reparse_tag=link_info.reparse_tag,
                    root_origin=root_origin,
                )
            )
        try:
            follow_for_identity = config.follow_symlinks or link_info.is_link_like
            stat = directory.stat(follow_symlinks=follow_for_identity)
            identity: tuple[int, int] | str = (
                (stat.st_dev, stat.st_ino)
                if stat.st_ino
                else path_key(directory)
            )
            if identity in dirs_seen:
                skipped_paths.append(
                    SkippedPath(
                        path=str(directory),
                        path_type=link_info.path_type,
                        reason="duplicate_target" if link_info.is_link_like else "duplicate_directory",
                        reparse_tag=link_info.reparse_tag,
                        root_origin=root_origin if is_root else None,
                    )
                )
                continue
            dirs_seen.add(identity)
        except OSError as exc:
            record_issue(directory, "디렉터리 식별", exc)
            continue

        release_path = directory / "release"
        try:
            has_release = release_path.is_file()
        except OSError as exc:
            record_issue(release_path, "Java release 파일 확인", exc, category="java_metadata")
            has_release = False
        if has_release:
            key = path_key(directory)
            if key not in homes_seen:
                try:
                    asset = identify_home(
                        directory,
                        allow_execution=config.allow_java_execution,
                        collect_package_info=config.collect_package_info,
                        on_metadata_error=metadata_error,
                    )
                    assets.append(asset)
                    javafx = identify_javafx(
                        directory,
                        asset.vendor,
                        on_metadata_error=metadata_error,
                    )
                    if javafx:
                        assets.append(javafx)
                    homes_seen.add(key)
                except OSError as exc:
                    record_issue(directory, "Java 설치 정보 식별", exc, category="java_metadata")

        if progress:
            progress(examined, str(directory))
        if depth >= config.max_depth:
            limit_reasons.add("max_depth")
            continue
        try:
            with os.scandir(directory) as iterator:
                entries = list(iterator)
        except OSError as exc:
            record_issue(directory, "디렉터리 열기", exc)
            continue
        child_directories: list[tuple[Path, PathLinkInfo]] = []
        for entry in entries:
            examined += 1
            reason = limit_reason()
            if reason:
                limit_reasons.add(reason)
                stopped = True
                break
            try:
                entry_link = _path_link_info(entry)
                if entry_link.is_link_like and not config.follow_symlinks:
                    skipped_paths.append(
                        SkippedPath(
                            path=entry.path,
                            path_type=entry_link.path_type,
                            reason="link_not_followed",
                            reparse_tag=entry_link.reparse_tag,
                        )
                    )
                    continue
                if entry.is_dir(follow_symlinks=config.follow_symlinks):
                    child_directories.append((Path(entry.path), entry_link))
                elif entry.name.lower() in {"java", "java.exe"} and directory.name.lower() == "bin":
                    home = directory.parent
                    key = path_key(home)
                    if key not in homes_seen and not (home / "release").is_file():
                        assets.append(
                            identify_home(
                                home,
                                allow_execution=config.allow_java_execution,
                                collect_package_info=config.collect_package_info,
                                on_metadata_error=metadata_error,
                            )
                        )
                        homes_seen.add(key)
            except OSError as exc:
                record_issue(entry.path, "디렉터리 항목 검사", exc)
        for child, child_link in reversed(
            sorted(child_directories, key=lambda item: _directory_priority(item[0]))
        ):
            stack.append((child, depth + 1, False, child_link))
        if stopped:
            break

    unique: dict[tuple[str, str, str | None, str | None, str], Asset] = {}
    for asset in assets:
        key = (asset.vendor, asset.product, asset.full_version, asset.special_build, os.path.normcase(asset.install_path))
        unique[key] = asset
    return DiscoveryResult(
        assets=list(unique.values()),
        errors=errors,
        examined_entries=examined,
        stopped=stopped,
        incomplete=bool(limit_reasons or issues),
        limit_reasons=sorted(limit_reasons),
        roots=[str(root) for root in roots],
        issues=issues,
        skipped_paths=skipped_paths,
        root_links=root_links,
    )


def environment_summary() -> dict[str, str]:
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "hostname": platform.node(),
    }
