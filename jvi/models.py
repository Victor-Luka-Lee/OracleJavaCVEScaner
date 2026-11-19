"""Typed domain models shared by the scanner, evaluator, and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Status(StrEnum):
    AFFECTED = "AFFECTED"
    FIXED = "FIXED"
    NOT_AFFECTED = "NOT_AFFECTED"
    NOT_ASSESSED = "NOT_ASSESSED"
    POTENTIALLY_AFFECTED = "POTENTIALLY_AFFECTED"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class Asset:
    product: str
    vendor: str
    distribution: str
    java_major: int | None
    full_version: str | None
    update_number: int | None
    build_number: int | None
    special_build: str | None
    install_path: str
    evidence: list[str]
    detected_at: str = field(default_factory=utc_now)
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    cve_id: str
    status: Status
    rationale: str
    asset: Asset
    discovered_path: str
    database_version: str
    recommendation: str
    confidence: str
    exploitability: str
    advisory_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass(slots=True)
class ScanReport:
    scan_time: str
    environment: dict[str, str]
    scope: dict[str, Any]
    assets: list[Asset]
    findings: list[Finding]
    database_version: str
    sources: list[str]
    limitations: list[str]
    errors: list[str] = field(default_factory=list)
    started_at: str | None = None
    completed_at: str | None = None
    advisories: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_time": self.scan_time,
            "environment": self.environment,
            "scope": self.scope,
            "assets": [asset.to_dict() for asset in self.assets],
            "findings": [finding.to_dict() for finding in self.findings],
            "database_version": self.database_version,
            "sources": self.sources,
            "limitations": self.limitations,
            "errors": self.errors,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "advisories": self.advisories,
        }

