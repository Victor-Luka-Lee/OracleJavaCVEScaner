"""Before/after regression matrix for conservative classification changes."""

import pytest

from jvi.engine import evaluate_asset
from jvi.models import Status


def _status(asset, database, cve):
    return next(item.status for item in evaluate_asset(asset, database) if item.cve_id == cve)


@pytest.mark.parametrize(
    ("version", "vendor", "cve", "legacy_status", "expected_status"),
    [
        # The legacy engine accepted the update label 8u513 without proof of b04.
        ("8u513", "Oracle", "CVE-2026-86144", Status.FIXED, Status.UNKNOWN),
        # An unlisted old build was formerly declared NOT_AFFECTED.
        ("1.8.0_401-b10", "Oracle", "CVE-2026-114939", Status.NOT_AFFECTED, Status.NOT_ASSESSED),
        # Exact official impact evidence remains stable.
        ("17.0.21.0.3", "Oracle", "CVE-2026-114938", Status.AFFECTED, Status.AFFECTED),
        # A non-Oracle distribution stays independent, now distinguishing
        # missing vendor advisory coverage from missing asset identity.
        ("21.0.13.0.3", "Eclipse Adoptium", "CVE-2026-114940", Status.UNKNOWN, Status.NOT_ASSESSED),
    ],
)
def test_before_after_classification_matrix(
    database, asset_factory, version, vendor, cve, legacy_status, expected_status
):
    product = "Oracle Java SE" if vendor == "Oracle" else "OpenJDK"
    asset = asset_factory(version, vendor=vendor, product=product)
    current = _status(asset, database, cve)
    assert current == expected_status
    if legacy_status != expected_status:
        assert current != legacy_status
