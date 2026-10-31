import pytest

from suveren.checks import Status
from suveren.vulns import Library, detect, in_range, known_issues, vuln_check


def names(libs):
    return {(x.name, x.version) for x in libs}


def test_versions_from_urls():
    urls = [
        "https://code.jquery.com/jquery-3.4.1.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js",
        "https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.24.0/moment.min.js",
        "https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js",
        "https://site.ru/js/jquery-ui-1.12.1.custom.min.js",
    ]
    assert names(detect(urls, {})) == {
        ("jquery", "3.4.1"),
        ("bootstrap", "3.3.7"),
        ("lodash", "4.17.15"),
        ("moment", "2.24.0"),
        ("angularjs", "1.8.2"),
        ("jquery-ui", "1.12.1"),  # and not jQuery 1.12.1
    }


def test_versions_from_banners_and_no_guessing():
    heads = {
        "https://site.ru/bundle.js": "/*! jQuery v1.12.4 | (c) jQuery Foundation */\n...",
        "https://site.ru/vendor.js": "/*!\n * Bootstrap v4.1.1 (https://getbootstrap.com/)\n",
        "https://site.ru/app.js": "// uses jquery and bootstrap, version unknown",
    }
    assert names(detect(list(heads), heads)) == {("jquery", "1.12.4"), ("bootstrap", "4.1.1")}
    # A file named after a library but without a version says nothing.
    assert detect(["https://site.ru/js/jquery.min.js", "https://site.ru/bootstrap.js"], {}) == []


def test_ranges():
    assert in_range("3.4.1", [[None, "3.5.0"]])
    assert not in_range("3.5.0", [[None, "3.5.0"]])
    assert in_range("4.3.0", [[None, "3.4.1"], ["4.3.0", "4.3.1"]])
    assert not in_range("4.2.1", [[None, "3.4.1"], ["4.3.0", "4.3.1"]])
    assert in_range("1.12", [["1.2", "3.5.0"]])


@pytest.mark.parametrize(
    ("version", "ids"),
    [
        ("2.10.6", {"CVE-2016-4055", "CVE-2017-18214"}),
        ("2.11.2", {"CVE-2017-18214"}),
        ("2.19.2", {"CVE-2017-18214", "CVE-2022-31129"}),
        ("2.19.3", {"CVE-2022-31129"}),
        ("2.29.4", set()),
    ],
)
def test_moment_before_2_18_is_not_called_safe(version, ids):
    """moment.js 2.10-2.17 had no entry and got "no known vulnerabilities"."""
    vulns, _ = known_issues(Library("moment", version, "x"))
    assert {v["id"] for v in vulns} == ids


def test_known_issues_and_check():
    vulns, eol = known_issues(Library("jquery", "3.4.1", "x"))
    assert {v["id"] for v in vulns} == {"CVE-2020-11022", "CVE-2020-11023"}
    assert eol is None
    assert known_issues(Library("jquery", "3.7.1", "x")) == ([], None)
    _, eol = known_issues(Library("angularjs", "1.8.2", "x"))
    assert eol and "2022" in eol["summary"]
    check = vuln_check([Library("jquery", "3.4.1", "code.jquery.com/jquery-3.4.1.min.js"),
                        Library("bootstrap", "5.3.3", "x")])  # fmt: skip
    assert check.status is Status.WARN and check.id == "SUV-WEB-010"
    assert "CVE-2020-11022" in check.details and "Bootstrap 5.3.3" in check.details
    assert vuln_check([Library("jquery", "3.7.1", "x")]).status is Status.OK
    # A clean answer is only as fresh as the built-in list: its date is shown.
    [where] = [e.value for e in vuln_check([]).evidence if e.what == "Источник"]
    assert where.startswith("встроенная база Suveren по NVD, сверена ")
    assert vuln_check([]).status is Status.OK


def test_plugins_and_lookalike_projects_are_not_the_library():
    urls = [
        "https://site.ru/js/ui-bootstrap-2.5.0.min.js",  # angular-ui-bootstrap
        "https://site.ru/js/restangular-1.6.1.min.js",
        "https://site.ru/js/angular-moment-1.3.0.min.js",
        "https://cdn.jsdelivr.net/npm/@fullcalendar/moment@6.1.8/index.global.min.js",
        "https://site.ru/js/form.js",
        "https://site.ru/js/datepicker.js",
        "https://site.ru/js/tz.js",
    ]
    heads = {
        "https://site.ru/js/form.js": (
            "/*!\n * jQuery Form Plugin\n * Requires jQuery v1.7.2 or later\n"
        ),
        "https://site.ru/js/datepicker.js": "/*!\n * Datepicker for Bootstrap v1.9.0\n",
        "https://site.ru/js/tz.js": "//! moment-timezone.js\n//! version : 0.5.34\n",
    }
    assert detect(urls, heads) == []


def test_real_banners_still_found():
    heads = {
        "a": "/*!\n * jQuery JavaScript Library v3.4.1\n",
        "b": "/*!\n  * Bootstrap v4.1.1 (https://getbootstrap.com/)\n",
        "c": "//! moment.js\n//! version : 2.24.0\n",
        "d": "/**\n * @license AngularJS v1.8.2\n",
        "e": "/*! jQuery UI - v1.12.1 - 2016-09-14\n",
    }
    assert names(detect(list(heads), heads)) == {
        ("jquery", "3.4.1"),
        ("bootstrap", "4.1.1"),
        ("moment", "2.24.0"),
        ("angularjs", "1.8.2"),
        ("jquery-ui", "1.12.1"),
    }
