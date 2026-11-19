import json

import pytest

from jvi.advisory import AdvisoryDataError, default_advisory_path, load_database


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


def test_missing_checksum_is_rejected(tmp_path, database):
    path = tmp_path / "advisory.json"
    path.write_text(json.dumps(database), encoding="utf-8")
    with pytest.raises(AdvisoryDataError, match="cannot read advisory SHA-256"):
        load_database(path)


def test_frozen_database_path_uses_bundle_not_executable_directory(tmp_path, monkeypatch):
    bundled = tmp_path / "jvi" / "data" / "advisories" / "oracle_2026_11.json"
    bundled.parent.mkdir(parents=True)
    bundled.write_text("{}", encoding="utf-8")
    monkeypatch.setattr("jvi.advisory.sys.frozen", True, raising=False)
    monkeypatch.setattr("jvi.advisory.sys._MEIPASS", str(tmp_path), raising=False)
    assert default_advisory_path() == bundled
