"""Evidence-conservative CVE assessment engine."""

from __future__ import annotations

from typing import Any, Iterable

from .models import Asset, Finding, Status
from .version import JavaVersion, try_parse


OPENJDK_VENDORS = {
    "Eclipse Adoptium",
    "Amazon",
    "Azul",
    "Microsoft",
    "Red Hat",
    "OpenJDK",
    "GraalVM Community",
    "Unknown",
}


def _rules_for_product(rules: list[dict[str, Any]], product: str) -> list[str]:
    versions: list[str] = []
    for rule in rules:
        if rule.get("product") == product:
            versions.extend(str(value) for value in rule.get("versions", []))
    return versions


def _asset_version(asset: Asset) -> JavaVersion | None:
    value = asset.full_version
    if value and asset.special_build == "perf" and "perf" not in value.lower():
        value = value + "-perf"
    return try_parse(value)


def _matches_affected(version: JavaVersion, candidates: Iterable[str]) -> str | None:
    for candidate in candidates:
        parsed = try_parse(candidate)
        if parsed and version.same_release(parsed):
            return candidate
    return None


def _matches_fixed(version: JavaVersion, candidates: Iterable[str]) -> str | None:
    for candidate in candidates:
        fixed = try_parse(candidate)
        if not fixed or not version.same_line(fixed):
            continue
        # KISA calls these solution versions. A later numeric release on the same
        # feature line is treated as carrying the cumulative fix; no earlier
        # release is inferred to be affected.
        if version >= fixed:
            return candidate
    return None


def evaluate_asset(asset: Asset, database: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    db_version = str(database["database_version"])
    asset_version = _asset_version(asset)

    for advisory in database["advisories"]:
        products = set(advisory["product"])
        base = {
            "cve_id": advisory["cve_id"],
            "asset": asset,
            "discovered_path": asset.install_path,
            "database_version": db_version,
            "recommendation": advisory.get("recommendation", "공식 보안 공지를 확인하십시오."),
            "exploitability": advisory.get("exploitability", "실제 공격 가능성은 별도 검증이 필요합니다."),
            "advisory_urls": advisory["advisory_urls"],
        }

        if asset.vendor != "Oracle":
            rationale = (
                f"{asset.vendor} 배포판에는 Oracle 해결 빌드를 직접 적용하지 않습니다. "
                "해당 배포판의 공식 보안 공지가 데이터베이스에 없어 판정할 수 없습니다."
            )
            findings.append(Finding(status=Status.UNKNOWN, rationale=rationale, confidence="LOW", **base))
            continue

        if asset.product not in products:
            if asset.product in {"Oracle Java", "Oracle JDK/JRE"}:
                findings.append(
                    Finding(
                        status=Status.POTENTIALLY_AFFECTED,
                        rationale="Oracle 제품은 확인했지만 Java SE/JavaFX/GraalVM 변형을 확정하지 못했습니다.",
                        confidence="LOW",
                        **base,
                    )
                )
            else:
                findings.append(
                    Finding(
                        status=Status.NOT_AFFECTED,
                        rationale=f"공식 공지의 대상 제품({', '.join(sorted(products))})과 탐지 제품이 다릅니다.",
                        confidence="HIGH",
                        **base,
                    )
                )
            continue

        if asset_version is None:
            findings.append(
                Finding(
                    status=Status.UNKNOWN,
                    rationale="제품은 대상이지만 신뢰할 수 있는 버전 정보를 확보하지 못했습니다.",
                    confidence="LOW",
                    **base,
                )
            )
            continue

        affected_versions = _rules_for_product(advisory["affected_versions"], asset.product)
        fixed_versions = _rules_for_product(advisory["fixed_versions"], asset.product)
        affected = _matches_affected(asset_version, affected_versions)
        if affected:
            findings.append(
                Finding(
                    status=Status.AFFECTED,
                    rationale=(
                        f"탐지 버전 {asset.full_version}이 공식 공지의 영향 빌드 {affected}와 일치합니다. "
                        "이 결과는 버전 영향 평가이며 실행 경로의 실제 악용 가능성과는 별개입니다."
                    ),
                    confidence="HIGH",
                    **base,
                )
            )
            continue

        fixed = _matches_fixed(asset_version, fixed_versions)
        if fixed:
            findings.append(
                Finding(
                    status=Status.FIXED,
                    rationale=f"탐지 버전 {asset.full_version}이 KISA 해결 버전 {fixed} 이상인 동일 Java 계열입니다.",
                    confidence="HIGH",
                    **base,
                )
            )
            continue

        findings.append(
            Finding(
                status=Status.NOT_AFFECTED,
                rationale=(
                    f"탐지 버전 {asset.full_version}은 이 CVE에 대해 공식 문서가 열거한 영향 빌드와 일치하지 않습니다. "
                    "이 판정은 다른 CVE나 지원 종료 위험을 의미하지 않습니다."
                ),
                confidence="HIGH",
                **base,
            )
        )
    return findings


def evaluate_assets(assets: Iterable[Asset], database: dict[str, Any]) -> list[Finding]:
    return [finding for asset in assets for finding in evaluate_asset(asset, database)]

