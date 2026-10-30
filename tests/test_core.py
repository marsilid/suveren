"""The core: scan plans (profiles, --checks), narrowing, SARIF and CI exit codes."""

from test_view import sample_report
from typer.testing import CliRunner

from suveren.catalog import MAIL, WEB
from suveren.checks import GROUP_152, Check, Status
from suveren.cli import FailOn, app, failing_checks
from suveren.crawl import DEFAULT_PAGES
from suveren.plan import DEEP_PAGES, SCAN_MODULES, Profile, make_plan
from suveren.sarif import to_sarif
from suveren.scan import narrow

runner = CliRunner()


def test_profiles():
    standard = make_plan()
    assert standard.modules == frozenset(SCAN_MODULES) - {"cutoff", "formleaks"}
    assert not standard.browser and standard.pages == DEFAULT_PAGES and standard.only is None
    assert make_plan(Profile.quick).modules == frozenset()
    deep = make_plan(Profile.deep, pages=2)
    assert deep.browser and deep.pages == DEEP_PAGES
    assert make_plan(skip={"mail", "subdomains"}).modules == frozenset(
        {"compliance", "blocklist", "security"}
    )


def test_checks_choose_modules_and_skip_wins():
    plan = make_plan(checks="dkim,SUV-WEB-004")
    assert plan.modules == frozenset({"mail", "security"})
    assert plan.only == frozenset({"SUV-MAIL-004", "SUV-WEB-004"})
    # A chosen check runs even in the quick profile; --no-mail still switches it off.
    assert make_plan(Profile.quick, checks="dkim").modules == frozenset({"mail"})
    assert make_plan(checks="dkim", skip={"mail"}).modules == frozenset()
    kwargs = plan.kwargs()
    assert kwargs["mail"] and kwargs["security"] and not kwargs["compliance"]


def test_narrow_keeps_why_a_chosen_check_is_missing():
    verdict = Check(MAIL, "Можно ли подделать письмо от имени @a.ru", Status.UNKNOWN, "DNS.")
    csp = Check(WEB, "Политика безопасности контента (CSP)", Status.WARN)
    hsts = Check(WEB, "Принудительный HTTPS (HSTS)", Status.UNKNOWN)
    kept = narrow([verdict, csp, hsts], {"SUV-MAIL-003", "SUV-WEB-004"})
    # DMARC is missing because DNS failed: the verdict says so. HSTS is not chosen.
    assert [c.id for c in kept] == ["SUV-MAIL-001", "SUV-WEB-004"]


def test_sarif_has_rules_results_and_levels():
    report = sample_report()
    report.checks[0].law = "152-ФЗ, ст. 18.1"
    sarif = to_sarif(report)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "Suveren"
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    results = {r["ruleId"]: r for r in run["results"]}
    # The failed policy is an error; the passed HTTPS check is left out.
    assert results["SUV-PD-001"]["level"] == "error"
    assert "SUV-PD-008" not in results
    assert rules["SUV-PD-001"]["helpUri"].startswith("https://www.consultant.ru/")
    # Foreign mail (Google) is a dependency finding with its own rule.
    assert results["SUV-DEP-MAIL"]["level"] == "error"
    assert "pd" in rules["SUV-PD-001"]["properties"]["tags"]
    for r in run["results"]:
        assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"]
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
            "https://example.ru/"
        )


def test_fail_on():
    report = sample_report()
    report.checks.append(Check(GROUP_152, "Уведомление о cookies", Status.WARN))
    report.checks.append(Check(GROUP_152, "Содержание политики", Status.UNKNOWN))
    assert failing_checks(report, None) == []
    assert [c.id for c in failing_checks(report, FailOn.fail)] == ["SUV-PD-001"]
    assert [c.id for c in failing_checks(report, FailOn.warn)] == ["SUV-PD-001", "SUV-PD-005"]


def test_scan_cli_passes_the_plan_and_exits_4(monkeypatch, tmp_path):
    calls = {}

    async def fake_run_scan(host, **kwargs):
        calls.update(kwargs)
        return sample_report()

    monkeypatch.setattr("suveren.cli.run_scan", fake_run_scan)
    sarif = tmp_path / "r.sarif"
    result = runner.invoke(
        app,
        ["scan", "example.ru", "--no-report", "--checks", "pd", "--sarif", str(sarif)],
    )
    assert result.exit_code == 0, result.output
    assert calls["compliance"] and not calls["mail"] and not calls["subdomains"]
    assert not calls["formleaks"]  # "pd" holds SUV-PD-012, but its experiment needs a flag
    assert "SUV-PD-001" in calls["only"]
    assert sarif.exists()
    result = runner.invoke(app, ["scan", "example.ru", "--no-report", "--fail-on", "fail"])
    assert result.exit_code == 4
    assert "SUV-PD-001" in result.output
    result = runner.invoke(app, ["scan", "example.ru", "--checks", "nmap"])
    assert result.exit_code == 2


def test_checks_command():
    result = runner.invoke(app, ["checks"])
    assert result.exit_code == 0
    assert "SUV-MAIL-002" in result.output and "SUV-LAW-001" in result.output
    one = runner.invoke(app, ["checks", "SUV-WEB-007"])
    assert "Флаги cookies" in one.output and "Модуль:  security" in one.output
    assert runner.invoke(app, ["checks", "nope"]).exit_code == 2
