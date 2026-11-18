from __future__ import annotations

from pathlib import Path

import pytest

from jvi.advisory import load_database
from jvi.models import Asset
from jvi.version import JavaVersion


@pytest.fixture(scope="session")
def database():
    return load_database()


def make_asset(
    version: str | None,
    *,
    vendor: str = "Oracle",
    product: str = "Oracle Java SE",
    distribution: str = "Oracle JDK/JRE",
    path: str = "/virtual/java",
    special_build: str | None = None,
    metadata: dict[str, str] | None = None,
) -> Asset:
    parsed = JavaVersion.parse(version) if version else None
    return Asset(
        product=product,
        vendor=vendor,
        distribution=distribution,
        java_major=parsed.major if parsed else None,
        full_version=version,
        update_number=parsed.update if parsed else None,
        build_number=parsed.build if parsed else None,
        special_build=special_build if special_build is not None else (parsed.variant if parsed else None),
        install_path=path,
        evidence=["pytest virtual asset"],
        metadata=metadata or {},
    )


@pytest.fixture
def asset_factory():
    return make_asset


@pytest.fixture(scope="session")
def fixture_homes() -> Path:
    return Path(__file__).parent / "fixtures" / "java_homes"

