"""Evidence-conservative CVE assessment engine.

``NOT_AFFECTED`` is reserved for a proven product mismatch. An unlisted
version is not evidence of safety: it is ``NOT_ASSESSED`` when the asset is
otherwise known, and ``UNKNOWN`` when version/build evidence is incomplete.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Literal

from .models import Asset, Finding, Status
from .version import JavaVersion, try_parse


@dataclass(frozen=True, slots=True)
class VersionEvidence:
    outcome: Literal["match", "incomplete", "insufficient", "none"]
    reference: str | None = None


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


def _affected_evidence(version: JavaVersion, candidates: Iterable[str]) -> VersionEvidence:
    for candidate in candidates:
        parsed = try_parse(candidate)
        if parsed and version.same_release(parsed):
            return VersionEvidence("match", candidate)
    for candidate in candidates:
        parsed = try_parse(candidate)
        if not parsed or version.major != parsed.major:
            continue
        if version.major == 8:
            if version.update == parsed.update and version.build is None and parsed.build is not None:
                return VersionEvidence("incomplete", candidate)
        elif (
            len(version.numbers) < len(parsed.numbers)
            and version.numbers == parsed.numbers[: len(version.numbers)]
        ):
            return VersionEvidence("incomplete", candidate)
    return VersionEvidence("none")


def _canonical_fixed_candidates(candidates: Iterable[str]) -> list[tuple[str, JavaVersion]]:
    """Prefer the most precise alias for each Java 8 update.

    KISA writes ``8u513 (1.8.0_513-b04)``. The first token is a release label,
    not independent proof that an asset with an unknown build contains b04.
    """
    parsed = [(candidate, try_parse(candidate)) for candidate in candidates]
    valid = [(candidate, version) for candidate, version in parsed if version is not None]
    result: list[tuple[str, JavaVersion]] = []
    java8_groups: dict[tuple[int | None, str | None], list[tuple[str, JavaVersion]]] = {}
    for candidate, version in valid:
        if version.major == 8:
            java8_groups.setdefault((version.update, version.variant), []).append((candidate, version))
        else:
            result.append((candidate, version))
    for aliases in java8_groups.values():
        precise = [item for item in aliases if item[1].build is not None]
        result.extend(precise or aliases)
    return result


def _fixed_evidence(version: JavaVersion, candidates: Iterable[str]) -> VersionEvidence:
    incomplete: str | None = None
    insufficient: str | None = None
    for candidate, fixed in _canonical_fixed_candidates(candidates):
        if not version.same_line(fixed):
            continue
        if version.major == 8:
            if version.update is None or fixed.update is None:
                incomplete = candidate
                continue
            if version.update > fixed.update:
                return VersionEvidence("match", candidate)
            if version.update < fixed.update:
                insufficient = candidate
                continue
            # Same update: the build is a separate ordering dimension.
            if fixed.build is not None and version.build is None:
                incomplete = candidate
                continue
            if fixed.build is None:
                incomplete = candidate
                continue
            if version.build is not None and version.build >= fixed.build:
                return VersionEvidence("match", candidate)
            insufficient = candidate
            continue

        if (
            len(version.numbers) < len(fixed.numbers)
            and version.numbers == fixed.numbers[: len(version.numbers)]
        ):
            incomplete = candidate
            continue
        if version >= fixed:
            return VersionEvidence("match", candidate)
        insufficient = candidate
    if incomplete:
        return VersionEvidence("incomplete", incomplete)
    if insufficient:
        return VersionEvidence("insufficient", insufficient)
    return VersionEvidence("none")


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

        if asset.vendor == "Unknown":
            findings.append(
                Finding(
                    status=Status.UNKNOWN,
                    rationale="공급업체를 신뢰할 수 있는 메타데이터로 식별하지 못해 Oracle 규칙 적용 여부를 결정할 수 없습니다.",
                    confidence="LOW",
                    **base,
                )
            )
            continue

        if asset.vendor != "Oracle":
            if asset_version is None:
                findings.append(
                    Finding(
                        status=Status.UNKNOWN,
                        rationale=(
                            f"{asset.vendor} 배포판은 식별했지만 버전 또는 빌드 정보가 없어 "
                            "해당 배포판 공지와 비교할 수 없습니다."
                        ),
                        confidence="LOW",
                        **base,
                    )
                )
                continue
            rationale = (
                f"{asset.vendor} 배포판에는 Oracle 영향·해결 빌드를 직접 적용하지 않습니다. "
                "이 데이터베이스에 해당 배포판의 공식 공지가 없어 안전 여부를 평가하지 않았습니다."
            )
            findings.append(Finding(status=Status.NOT_ASSESSED, rationale=rationale, confidence="LOW", **base))
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
        affected = _affected_evidence(asset_version, affected_versions)
        if affected.outcome == "match":
            findings.append(
                Finding(
                    status=Status.AFFECTED,
                    rationale=(
                        f"탐지 버전 {asset.full_version}이 공식 공지의 영향 빌드 {affected.reference}와 일치합니다. "
                        "이 결과는 버전 영향 평가이며 실행 경로의 실제 악용 가능성과는 별개입니다."
                    ),
                    confidence="HIGH",
                    **base,
                )
            )
            continue
        if affected.outcome == "incomplete":
            findings.append(
                Finding(
                    status=Status.UNKNOWN,
                    rationale=(
                        f"탐지 버전 {asset.full_version}은 공식 영향 빌드 {affected.reference}와 같은 버전 계열이지만 "
                        "세부 빌드 번호가 없어 일치 여부를 확인할 수 없습니다."
                    ),
                    confidence="LOW",
                    **base,
                )
            )
            continue

        fixed = _fixed_evidence(asset_version, fixed_versions)
        if fixed.outcome == "match":
            findings.append(
                Finding(
                    status=Status.FIXED,
                    rationale=(
                        f"탐지 버전 {asset.full_version}이 KISA 해결 빌드 {fixed.reference}의 "
                        "업데이트·빌드 기준을 충족하는 동일 Java 계열입니다."
                    ),
                    confidence="HIGH",
                    **base,
                )
            )
            continue
        if fixed.outcome == "incomplete":
            findings.append(
                Finding(
                    status=Status.UNKNOWN,
                    rationale=(
                        f"탐지 버전 {asset.full_version}은 해결 버전 {fixed.reference}과 비교할 세부 빌드가 부족합니다. "
                        "수정 적용을 증명할 수 없어 FIXED로 판정하지 않습니다."
                    ),
                    confidence="LOW",
                    **base,
                )
            )
            continue

        support_status = asset.metadata.get("SUPPORT_STATUS", "").upper()
        if support_status in {"EOL", "EOS", "END_OF_LIFE", "END_OF_SUPPORT"}:
            rationale = (
                f"자산 메타데이터가 지원 종료({support_status})를 나타내며, 이 공지는 해당 버전의 안전 여부를 평가하지 않습니다."
            )
        elif fixed.outcome == "insufficient":
            rationale = (
                f"탐지 버전 {asset.full_version}은 해결 빌드 {fixed.reference}의 업데이트·빌드 기준을 충족하지 않지만, "
                "공식 영향 목록에도 정확히 일치하지 않습니다. 안전 또는 취약으로 추정하지 않습니다."
            )
        else:
            rationale = (
                f"탐지 버전 {asset.full_version}은 이 CVE의 공식 영향 목록 및 해결 빌드에 명시되지 않았습니다. "
                "목록에 없다는 사실만으로 취약점 비대상이라고 판단하지 않습니다."
            )

        findings.append(
            Finding(
                status=Status.NOT_ASSESSED,
                rationale=rationale,
                confidence="MEDIUM",
                **base,
            )
        )
    return findings


def evaluate_assets(assets: Iterable[Asset], database: dict[str, Any]) -> list[Finding]:
    return [finding for asset in assets for finding in evaluate_asset(asset, database)]

