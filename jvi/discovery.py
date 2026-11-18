"""Bounded, read-only Java discovery for Windows and Linux."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import threading
import time
from typing import Callable, Iterable

from .models import Asset
from .version import JavaVersion, try_parse


ProgressCallback = Callable[[int, str], None]


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
    roots: list[str]


def _clean_property(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return value.replace(r"\"", '"')


def parse_release(path: Path) -> dict[str, str]:
    properties: dict[str, str] = {}
    try:
        if path.stat().st_size > 1_048_576:
            return properties
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
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
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    output = (result.stderr + "\n" + result.stdout).strip()[:4096]
    match = re.search(r'(?:java|openjdk) version\s+"([^"]+)"', output, re.IGNORECASE)
    return (match.group(1) if match else None), output


def identify_home(home: Path, *, allow_execution: bool = False, collect_package_info: bool = True) -> Asset:
    properties = parse_release(home / "release")
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


def identify_javafx(home: Path, vendor: str) -> Asset | None:
    candidates = [home / "lib" / "javafx.properties", home / "javafx.properties"]
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:65536]
        except OSError:
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


def discover(
    config: ScanConfig,
    *,
    stop_event: threading.Event | None = None,
    progress: ProgressCallback | None = None,
) -> DiscoveryResult:
    stop_event = stop_event or threading.Event()
    roots = _deduplicate_paths(config.roots or default_roots(config.mode))
    start = time.monotonic()
    examined = 0
    errors: list[str] = []
    assets: list[Asset] = []
    homes_seen: set[str] = set()
    dirs_seen: set[tuple[int, int] | str] = set()
    stopped = False

    def limits_hit() -> bool:
        return (
            stop_event.is_set()
            or examined >= config.max_files
            or time.monotonic() - start >= config.timeout_seconds
        )

    stack: list[tuple[Path, int]] = [(root, 0) for root in reversed(roots)]
    while stack:
        if limits_hit():
            stopped = True
            break
        directory, depth = stack.pop()
        try:
            stat = directory.stat(follow_symlinks=config.follow_symlinks)
            identity: tuple[int, int] | str = (
                (stat.st_dev, stat.st_ino)
                if stat.st_ino
                else os.path.normcase(str(directory.resolve(strict=False)))
            )
            if identity in dirs_seen:
                continue
            dirs_seen.add(identity)
        except OSError as exc:
            errors.append(f"접근 실패: {directory} ({exc.__class__.__name__})")
            continue

        if (directory / "release").is_file():
            key = os.path.normcase(str(directory.resolve(strict=False)))
            if key not in homes_seen:
                try:
                    asset = identify_home(
                        directory,
                        allow_execution=config.allow_java_execution,
                        collect_package_info=config.collect_package_info,
                    )
                    assets.append(asset)
                    javafx = identify_javafx(directory, asset.vendor)
                    if javafx:
                        assets.append(javafx)
                    homes_seen.add(key)
                except OSError as exc:
                    errors.append(f"Java 메타데이터 읽기 실패: {directory} ({exc.__class__.__name__})")

        if progress:
            progress(examined, str(directory))
        if depth >= config.max_depth:
            continue
        try:
            with os.scandir(directory) as iterator:
                entries = list(iterator)
        except OSError as exc:
            errors.append(f"디렉터리 열기 실패: {directory} ({exc.__class__.__name__})")
            continue
        for entry in entries:
            examined += 1
            if limits_hit():
                stopped = True
                break
            try:
                if entry.is_dir(follow_symlinks=config.follow_symlinks):
                    if entry.is_symlink() and not config.follow_symlinks:
                        continue
                    stack.append((Path(entry.path), depth + 1))
                elif entry.name.lower() in {"java", "java.exe"} and directory.name.lower() == "bin":
                    home = directory.parent
                    key = os.path.normcase(str(home.resolve(strict=False)))
                    if key not in homes_seen and not (home / "release").is_file():
                        assets.append(
                            identify_home(
                                home,
                                allow_execution=config.allow_java_execution,
                                collect_package_info=config.collect_package_info,
                            )
                        )
                        homes_seen.add(key)
            except OSError as exc:
                errors.append(f"항목 검사 실패: {entry.path} ({exc.__class__.__name__})")
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
        roots=[str(root) for root in roots],
    )


def environment_summary() -> dict[str, str]:
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "hostname": platform.node(),
    }
