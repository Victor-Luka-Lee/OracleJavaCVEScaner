from jvi.engine import evaluate_asset, evaluate_assets
from jvi.models import Status


def _statuses(findings):
    return {finding.cve_id: finding.status for finding in findings}


def test_each_cve_matches_only_its_official_version_scope(database, asset_factory):
    statuses = _statuses(evaluate_asset(asset_factory("17.0.21.0.3"), database))
    assert statuses["CVE-2026-114938"] == Status.AFFECTED
    assert statuses["CVE-2026-114939"] == Status.AFFECTED
    assert statuses["CVE-2026-114940"] == Status.AFFECTED
    assert statuses["CVE-2026-114941"] == Status.NOT_AFFECTED
    assert statuses["CVE-2026-114942"] == Status.NOT_AFFECTED
    assert statuses["CVE-2026-86144"] == Status.NOT_AFFECTED


def test_java8_perf_rule_does_not_match_standard_build(database, asset_factory):
    standard = _statuses(evaluate_asset(asset_factory("1.8.0_511-b33"), database))
    perf = _statuses(evaluate_asset(asset_factory("8u511b33-perf"), database))
    assert standard["CVE-2026-114938"] == Status.NOT_AFFECTED
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
    assert {finding.status for finding in findings} == {Status.UNKNOWN}
    assert all("배포판" in finding.rationale for finding in findings)


def test_multiple_versions_are_evaluated_independently(database, asset_factory):
    affected = asset_factory("21.0.13.0.3", path="/virtual/affected")
    fixed = asset_factory("21.0.13.1", path="/virtual/fixed")
    findings = evaluate_assets([affected, fixed], database)
    by_path = {}
    for finding in findings:
        by_path.setdefault(finding.discovered_path, set()).add(finding.status)
    assert Status.AFFECTED in by_path["/virtual/affected"]
    assert Status.FIXED in by_path["/virtual/fixed"]

