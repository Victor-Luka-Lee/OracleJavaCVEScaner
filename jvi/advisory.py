"""Load and integrity-check the bundled, official-source advisory database."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class AdvisoryDataError(ValueError):
    pass


_SOURCE_ADVISORY = Path(__file__).resolve().parent.parent / "data" / "advisories" / "oracle_2026_11.json"
_PACKAGED_ADVISORY = Path(__file__).resolve().parent / "data" / "advisories" / "oracle_2026_11.json"
DEFAULT_ADVISORY = _SOURCE_ADVISORY if _SOURCE_ADVISORY.exists() else _PACKAGED_ADVISORY

REQUIRED_FIELDS = {
    "cve_id",
    "vendor",
    "product",
    "component",
    "affected_versions",
    "fixed_versions",
    "affected_builds",
    "applicable_conditions",
    "severity",
    "cvss_score",
    "advisory_urls",
    "published_date",
    "updated_date",
    "evidence_source",
    "verification_status",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_database(path: str | Path = DEFAULT_ADVISORY, *, verify_integrity: bool = True) -> dict[str, Any]:
    data_path = Path(path)
    try:
        raw = data_path.read_bytes()
    except OSError as exc:
        raise AdvisoryDataError(f"cannot read advisory database: {exc}") from exc

    if verify_integrity:
        checksum_path = data_path.with_suffix(data_path.suffix + ".sha256")
        if checksum_path.exists():
            expected = checksum_path.read_text(encoding="ascii").strip().split()[0].lower()
            actual = hashlib.sha256(raw).hexdigest()
            if expected != actual:
                raise AdvisoryDataError(
                    f"advisory database SHA-256 mismatch: expected {expected}, got {actual}"
                )

    try:
        database = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdvisoryDataError(f"invalid advisory JSON: {exc}") from exc

    if not isinstance(database.get("advisories"), list) or not database.get("database_version"):
        raise AdvisoryDataError("database_version and advisories are required")
    seen: set[str] = set()
    for item in database["advisories"]:
        missing = REQUIRED_FIELDS - set(item)
        if missing:
            raise AdvisoryDataError(f"{item.get('cve_id', '<unknown>')} missing fields: {sorted(missing)}")
        if item["cve_id"] in seen:
            raise AdvisoryDataError(f"duplicate CVE: {item['cve_id']}")
        seen.add(item["cve_id"])
        if item["verification_status"] != "VERIFIED_OFFICIAL":
            raise AdvisoryDataError(f"unverified advisory entry: {item['cve_id']}")
    return database
