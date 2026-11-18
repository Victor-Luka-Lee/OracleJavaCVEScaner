"""Oracle/OpenJDK version parsing without lexical string comparisons."""

from __future__ import annotations

from dataclasses import dataclass
from functools import total_ordering
import re


class VersionParseError(ValueError):
    pass


@total_ordering
@dataclass(frozen=True, slots=True)
class JavaVersion:
    raw: str
    major: int
    numbers: tuple[int, ...]
    update: int | None = None
    build: int | None = None
    package_build: int | None = None
    variant: str | None = None

    @classmethod
    def parse(cls, value: str) -> "JavaVersion":
        if not value or not value.strip():
            raise VersionParseError("empty Java version")
        raw = value.strip().strip('"\'')
        lowered = raw.lower()
        variant = "perf" if re.search(r"(?:^|[-_.])perf(?:$|[-_.+])", lowered) else None

        legacy = re.fullmatch(
            r"(?:1\.)?8(?:\.0)?(?:[._-]?u?|u)(\d+)(?:[-+_.]?b?(\d+))?(?:[-+_.].*)?",
            lowered,
        )
        if legacy:
            update = int(legacy.group(1))
            build = int(legacy.group(2)) if legacy.group(2) else None
            return cls(raw, 8, (8, update, build or 0), update, build, None, variant)

        # release files may use 1.8.0_511-b33, which is clearer to parse separately.
        legacy_long = re.fullmatch(
            r"1\.8\.0_(\d+)(?:[-+_.]?b?(\d+))?(?:[-+_.].*)?", lowered
        )
        if legacy_long:
            update = int(legacy_long.group(1))
            build = int(legacy_long.group(2)) if legacy_long.group(2) else None
            return cls(raw, 8, (8, update, build or 0), update, build, None, variant)

        match = re.match(r"^(\d+(?:\.\d+){0,5})(?:\+([0-9]+))?(?:[-+].*)?$", lowered)
        if not match:
            raise VersionParseError(f"unsupported Java version: {value!r}")
        numbers = tuple(int(part) for part in match.group(1).split("."))
        major = numbers[0]
        if major == 1 and len(numbers) > 1:
            major = numbers[1]
        if major < 2:
            raise VersionParseError(f"invalid Java major version: {major}")
        package_build = int(match.group(2)) if match.group(2) else None
        update = numbers[2] if len(numbers) >= 3 else None
        build = numbers[-1] if len(numbers) >= 4 else package_build
        return cls(raw, major, numbers, update, build, package_build, variant)

    def _ordering_key(self) -> tuple[int, ...]:
        if self.major == 8:
            return (8, self.update or 0, self.build or 0, self.package_build or 0)
        padded = self.numbers + (0,) * (6 - len(self.numbers))
        return padded + (self.package_build or 0,)

    def same_release(self, other: "JavaVersion") -> bool:
        """Exact advisory release match, including the perf/non-perf distinction."""
        if self.major != other.major or self.variant != other.variant:
            return False
        if self.major == 8:
            if self.update != other.update:
                return False
            return other.build is None or self.build == other.build
        left = self.numbers + (0,) * (6 - len(self.numbers))
        right = other.numbers + (0,) * (6 - len(other.numbers))
        return left == right

    def same_line(self, other: "JavaVersion") -> bool:
        return self.major == other.major

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, JavaVersion):
            return NotImplemented
        return self._ordering_key() < other._ordering_key()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, JavaVersion):
            return False
        return self._ordering_key() == other._ordering_key() and self.variant == other.variant


def try_parse(value: str | None) -> JavaVersion | None:
    if not value:
        return None
    try:
        return JavaVersion.parse(value)
    except VersionParseError:
        return None

