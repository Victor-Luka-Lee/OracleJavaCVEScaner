from jvi.engine import evaluate_asset, evaluate_assets
from jvi.models import Status


def _statuses(findings):
    return {finding.cve_id: finding.status for finding in findings}


def test_each_cve_matches_only_its_official_version_scope(database, asset_factory):
    statuses = _statuses(evaluate_asset(asset_factory("17.0.21.0.3"), database))
    assert statuses["CVE-2026-114938"] == Status.AFFECTED
    assert statuses["CVE-2026-114939"] == Status.AFFECTED
    assert statuses["CVE-2026-114940"] == Status.AFFECTED
    assert statuses["CVE-2026-114941"] == Status.NOT_ASSESSED
    assert statuses["CVE-2026-114942"] == Status.NOT_ASSESSED
    assert statuses["CVE-2026-86144"] == Status.NOT_ASSESSED


def test_java8_perf_rule_does_not_match_standard_build(database, asset_factory):
    standard = _statuses(evaluate_asset(asset_factory("1.8.0_511-b33"), database))
    perf = _statuses(evaluate_asset(asset_factory("8u511b33-perf"), database))
    assert standard["CVE-2026-114938"] == Status.NOT_ASSESSED
    assert perf["CVE-2026-114938"] == Status.AFFECTED
    assert standard["CVE-2026-86144"] == Status.AFFECTED


def test_fixed_version_is_confirmed(database, asset_factory):
    statuses = _statuses(evaluate_asset(asset_factory("21.0.13.1+4"), database))
    for cve in [
        "CVE-2026-114938",
        "CVE-2026-114939",
        "CVE-2026-114940",
        "CVE-2026-114941",
        "CVE-2026-114942",
    ]:
        assert statuses[cve] == Status.FIXED


def test_java8_solution_build_is_fixed(database, asset_factory):
    statuses = _statuses(evaluate_asset(asset_factory("1.8.0_513-b04"), database))
    assert statuses["CVE-2026-86144"] == Status.FIXED
    assert statuses["CVE-2026-114938"] == Status.FIXED
    assert statuses["CVE-2026-114939"] == Status.FIXED
    assert statuses["CVE-2026-114940"] == Status.FIXED


def test_java8_same_update_compares_build_independently(database, asset_factory):
    below = _statuses(evaluate_asset(asset_factory("1.8.0_513-b03"), database))
    above = _statuses(evaluate_asset(asset_factory("1.8.0_513-b05"), database))
    for cve in ["CVE-2026-86144", "CVE-2026-114938", "CVE-2026-114939", "CVE-2026-114940"]:
        assert below[cve] == Status.NOT_ASSESSED
        assert above[cve] == Status.FIXED


def test_java8_missing_build_cannot_prove_affected_or_fixed(database, asset_factory):
    solution_without_build = _statuses(evaluate_asset(asset_factory("8u513"), database))
    affected_update_without_build = _statuses(evaluate_asset(asset_factory("8u511"), database))
    assert solution_without_build["CVE-2026-86144"] == Status.UNKNOWN
    assert solution_without_build["CVE-2026-114939"] == Status.UNKNOWN
    assert affected_update_without_build["CVE-2026-86144"] == Status.UNKNOWN
    assert affected_update_without_build["CVE-2026-114939"] == Status.UNKNOWN


def test_modern_java_missing_detail_is_unknown(database, asset_factory):
    statuses = _statuses(evaluate_asset(asset_factory("21.0.13"), database))
    assert statuses["CVE-2026-114941"] == Status.UNKNOWN
    assert statuses["CVE-2026-114942"] == Status.UNKNOWN


def test_unlisted_older_version_is_not_assessed(database, asset_factory):
    statuses = _statuses(evaluate_asset(asset_factory("1.8.0_401-b10"), database))
    assert set(statuses.values()) == {Status.NOT_ASSESSED}
    assert all("안전" in finding.rationale or "명시되지" in finding.rationale for finding in evaluate_asset(asset_factory("1.8.0_401-b10"), database))


def test_end_of_support_asset_is_not_assessed(database, asset_factory):
    asset = asset_factory("15.0.2", metadata={"SUPPORT_STATUS": "EOL"})
    findings = evaluate_asset(asset, database)
    assert {finding.status for finding in findings} == {Status.NOT_ASSESSED}
    assert all("지원 종료" in finding.rationale for finding in findings)


def test_ambiguous_vendor_is_unknown(database, asset_factory):
    asset = asset_factory("21.0.13.0.3", vendor="Unknown", distribution="Unknown OpenJDK/JVM")
    findings = evaluate_asset(asset, database)
    assert {finding.status for finding in findings} == {Status.UNKNOWN}
    assert all("공급업체" in finding.rationale for finding in findings)


def test_proven_product_mismatch_remains_not_affected(database, asset_factory):
    asset = asset_factory(
        "21.3.20.0.3",
        product="Oracle GraalVM Enterprise Edition",
        distribution="Oracle GraalVM Enterprise Edition",
    )
    statuses = _statuses(evaluate_asset(asset, database))
    assert statuses["CVE-2026-114941"] == Status.NOT_AFFECTED
    assert statuses["CVE-2026-114942"] == Status.NOT_AFFECTED


def test_missing_version_is_unknown(database, asset_factory):
    findings = evaluate_asset(asset_factory(None), database)
    assert {finding.status for finding in findings} == {Status.UNKNOWN}


def test_openjdk_vendor_requires_its_own_advisory(database, asset_factory):
    asset = asset_factory(
        "21.0.13.0.3",
        vendor="Eclipse Adoptium",
        product="OpenJDK",
        distribution="Eclipse Temurin",
    )
    findings = evaluate_asset(asset, database)
    assert {finding.status for finding in findings} == {Status.NOT_ASSESSED}
    assert all("배포판" in finding.rationale for finding in findings)


def test_openjdk_without_version_is_unknown(database, asset_factory):
    asset = asset_factory(
        None,
        vendor="Eclipse Adoptium",
        product="OpenJDK",
        distribution="Eclipse Temurin",
    )
    findings = evaluate_asset(asset, database)
    assert {finding.status for finding in findings} == {Status.UNKNOWN}
    assert all("버전 또는 빌드" in finding.rationale for finding in findings)


def test_multiple_versions_are_evaluated_independently(database, asset_factory):
    affected = asset_factory("21.0.13.0.3", path="/virtual/affected")
    fixed = asset_factory("21.0.13.1", path="/virtual/fixed")
    findings = evaluate_assets([affected, fixed], database)
    by_path = {}
    for finding in findings:
        by_path.setdefault(finding.discovered_path, set()).add(finding.status)
    assert Status.AFFECTED in by_path["/virtual/affected"]
    assert Status.FIXED in by_path["/virtual/fixed"]

