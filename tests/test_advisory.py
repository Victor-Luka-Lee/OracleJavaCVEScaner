import json

import pytest

from jvi.advisory import AdvisoryDataError, load_database


def test_database_contains_only_requested_verified_cves(database):
    assert {item["cve_id"] for item in database["advisories"]} == {
        "CVE-2026-86144",
        "CVE-2026-114938",
        "CVE-2026-114939",
        "CVE-2026-114940",
        "CVE-2026-114941",
        "CVE-2026-114942",
    }
    assert all(item["verification_status"] == "VERIFIED_OFFICIAL" for item in database["advisories"])


def test_integrity_mismatch_is_rejected(tmp_path, database):
    path = tmp_path / "advisory.json"
    path.write_text(json.dumps(database), encoding="utf-8")
    path.with_suffix(".json.sha256").write_text("0" * 64, encoding="ascii")
    with pytest.raises(AdvisoryDataError, match="SHA-256 mismatch"):
        load_database(path)
