from jvi.version import JavaVersion, VersionParseError


def test_java8_update_and_build_parsing():
    dotted = JavaVersion.parse("1.8.0_511-b33")
    compact = JavaVersion.parse("8u511b33")
    assert dotted.major == 8
    assert dotted.update == 511
    assert dotted.build == 33
    assert dotted.same_release(compact)


def test_java8_solution_label_and_concrete_build_are_distinct():
    label = JavaVersion.parse("8u513")
    concrete = JavaVersion.parse("1.8.0_513-b04")
    assert label.update == concrete.update == 513
    assert label.build is None
    assert concrete.build == 4
    assert concrete > label


def test_modern_versions_compare_numerically():
    assert JavaVersion.parse("11.0.33.1") > JavaVersion.parse("11.0.33.0.3")
    assert JavaVersion.parse("17.0.21.1") > JavaVersion.parse("17.0.21.0.3")
    assert JavaVersion.parse("21.0.13.1") > JavaVersion.parse("21.0.13.0.3")
    assert JavaVersion.parse("25.0.5.1") > JavaVersion.parse("25.0.5.0.3")
    assert JavaVersion.parse("27.0.1.1") > JavaVersion.parse("27.0.1.0.3")
    assert JavaVersion.parse("21.0.13.1+4") > JavaVersion.parse("21.0.13.1")


def test_perf_build_is_distinct():
    standard = JavaVersion.parse("8u511b33")
    perf = JavaVersion.parse("8u511b33-perf")
    assert perf.variant == "perf"
    assert not perf.same_release(standard)
    assert standard != perf


def test_invalid_version_is_not_guessed():
    try:
        JavaVersion.parse("Java-ish latest")
    except VersionParseError:
        pass
    else:
        raise AssertionError("unsupported version must not be guessed")

