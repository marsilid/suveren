import asyncio
import json
from pathlib import Path

import httpx
import pytest

from suveren import vulns
from suveren.checks import Status
from suveren.vulns import (
    RETIRE_NAMES,
    RETIRE_URL,
    Library,
    Vuln,
    VulnDb,
    bundled,
    detect,
    known_issues,
    load_database,
    parse_retire,
    version_tuple,
    vuln_check,
)


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


def test_versions_and_ranges():
    assert version_tuple("1.12") == (1, 12, 0)
    assert version_tuple("3.0.0-beta1") == version_tuple("3.0.0") == (3, 0, 0)
    assert version_tuple("1.9.0b1") == (1, 9, 0)
    assert version_tuple("junk") == (0, 0, 0)
    v = Vuln("jquery", "1.2.1", "1.9.0", "medium", ("CVE-1",), "")
    assert v.affects("1.8.3") and v.affects("1.2.1")
    assert not v.affects("1.9.0") and not v.affects("1.2.0")
    # "below 3.0.0-beta1": every 2.x release, not 3.0.0 itself.
    pre = Vuln("jquery", None, "3.0.0-beta1", "medium", (), "")
    assert pre.affects("2.2.4") and not pre.affects("3.0.0")
    assert Vuln("x", None, None, "low", (), "").affects("99.0")


@pytest.mark.parametrize(
    ("version", "ids"),
    [
        ("2.10.6", {"CVE-2016-4055", "CVE-2017-18214", "retire.js #22"}),
        ("2.11.2", {"CVE-2017-18214", "retire.js #22"}),
        ("2.19.2", {"CVE-2017-18214", "CVE-2022-31129"}),
        ("2.19.3", {"CVE-2022-31129"}),
        ("2.29.4", set()),  # CVE-2026-17495 is server-side only
    ],
)
def test_moment_before_2_18_is_not_called_safe(version, ids):
    """moment.js 2.10-2.17 had no entry and got "no known vulnerabilities"."""
    assert {v.label for v in known_issues(Library("moment", version, "x"))} == ids


def test_server_only_flaws_are_left_out():
    labels = {v.label for v in known_issues(Library("moment", "2.29.1", "x"))}
    assert "CVE-2022-24785" not in labels and labels == {"CVE-2022-31129"}


def test_known_issues_and_check():
    issues = known_issues(Library("jquery", "3.4.1", "x"))
    assert {v.label for v in issues} == {"CVE-2020-11022", "CVE-2020-11023"}
    assert known_issues(Library("jquery", "3.7.1", "x")) == []
    angular = known_issues(Library("angularjs", "1.8.2", "x"))
    assert any(v.eol for v in angular) and angular[0].severity == "high"
    check = vuln_check([Library("jquery", "3.4.1", "code.jquery.com/jquery-3.4.1.min.js"),
                        Library("bootstrap", "5.3.3", "x")])  # fmt: skip
    assert check.status is Status.WARN and check.id == "SUV-WEB-010"
    assert "CVE-2020-11022" in check.details and "Bootstrap 5.3.3" in check.details
    assert "2 известные уязвимости, самая опасная — средняя" in check.details
    assert "retire.js" in check.recommendation
    assert vuln_check([Library("jquery", "3.7.1", "x")]).status is Status.OK
    # A clean answer is only as fresh as the database: its copy and date are shown.
    [where] = [e.value for e in vuln_check([]).evidence if e.what == "Источник"]
    assert where.startswith("база retire.js, встроенная копия от ")
    assert vuln_check([]).status is Status.OK


def test_many_issues_are_summed_up_and_eol_said_once():
    check = vuln_check([Library("angularjs", "1.5.8", "x")])
    assert "и ещё" in check.details and check.details.count("не поддерживается") == 1
    eol_only = VulnDb(
        {"jquery": [Vuln("jquery", None, "2.999.999", "low", (), "End-of-Life")]}, "s"
    )
    text = vuln_check([Library("jquery", "2.2.4", "x")], eol_only).details
    assert "известн" not in text and "не поддерживается" in text


def _retire(**libs):
    base = {k: {"vulnerabilities": []} for names in RETIRE_NAMES.values() for k in names}
    return {**base, **libs}


def test_parse_retire_reads_identifiers_and_widgets():
    data = _retire(
        **{
            "jquery-ui-dialog": {
                "vulnerabilities": [
                    {"below": "1.12.0", "severity": "MEDIUM",
                     "identifiers": {"CVE": ["CVE-2016-7103"], "githubID": "GHSA-hpcf"}},
                ]
            },
            "jquery": {"vulnerabilities": [{"below": "1.6.3", "identifiers": {"summary": "x"}}]},
        }
    )  # fmt: skip
    vulns = parse_retire(data)
    [dialog] = vulns["jquery-ui"]
    assert dialog.ids == ("CVE-2016-7103", "GHSA-hpcf") and dialog.severity == "medium"
    assert vulns["jquery"][0].label == "без номера" and vulns["jquery"][0].severity == "medium"


@pytest.mark.parametrize("data", [{}, {"jquery": {}}, _retire()])
def test_parse_retire_rejects_what_is_not_the_database(data):
    with pytest.raises((KeyError, ValueError)):
        parse_retire(data)


def test_bundled_copy_is_a_real_retire_snapshot():
    raw = json.loads((Path(vulns.__file__).parent / "data" / "retire.json").read_text("utf-8"))
    assert raw["_suveren"]["url"] == RETIRE_URL
    assert bundled().vulns["jquery"]


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_database_is_downloaded_cached_and_dated(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    fresh = _retire(
        jquery={"vulnerabilities": [{"below": "9.0.0", "severity": "high",
                                     "identifiers": {"CVE": ["CVE-2099-1"]}}]}
    )  # fmt: skip
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json=fresh)

    async def go():
        async with _client(handler) as c:
            return await load_database(c), await load_database(c)

    db, again = asyncio.run(go())
    assert calls == [RETIRE_URL]
    assert db.source.startswith(
        "база retire.js, https://github.com/RetireJS/retire.js, выгрузка от "
    )
    check = vuln_check([Library("jquery", "3.7.1", "x")], db)
    assert check.status is Status.WARN and "CVE-2099-1" in check.details
    assert again.source == db.source


@pytest.mark.parametrize(
    "response",
    [httpx.Response(503), httpx.Response(200, text="{}"), httpx.Response(200, text="not json")],
)
def test_database_falls_back_to_the_built_in_copy(tmp_path, monkeypatch, response):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))

    async def go():
        async with _client(lambda request: response) as c:
            return await load_database(c)

    db = asyncio.run(go())
    assert db.source.endswith("(свежая база не скачалась)")
    assert db.vulns == bundled().vulns


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
