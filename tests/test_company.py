from datetime import date

from suveren.checks import Status
from suveren.company import CompanyReport, build_checks, render_age
from suveren.registries import EgrulRecord, RknOperator
from suveren.report import render_company_html
from suveren.sanctions import Entry, Hit

TODAY = date(2026, 10, 6)


def record(**kwargs):
    defaults = {
        "name_full": 'ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "РОМАШКА"',
        "name_short": 'ООО "РОМАШКА"',
        "inn": "7707083893",
        "ogrn": "1027700132195",
        "kpp": None,
        "registered": date(2015, 1, 1),
        "terminated": None,
        "head": "ГЕНЕРАЛЬНЫЙ ДИРЕКТОР: Иванов Иван Иванович",
        "region": "Г.Москва",
        "individual": False,
    }
    defaults.update(kwargs)
    return EgrulRecord(**defaults)


def statuses(report, sanctions_ok=True):
    return {c.title: c.status for c in build_checks(report, sanctions_ok=sanctions_ok, today=TODAY)}


def test_clean_company_all_ok():
    report = CompanyReport(query="7707083893", inn="7707083893", egrul=record())
    report.operator = RknOperator("77-1", "ООО Ромашка", "7707083893", "", date(2016, 1, 1), None)
    report.sanctions_sources = ["us", "eu", "uk"]
    result = statuses(report)
    assert set(result.values()) == {Status.OK}
    assert "Руководитель в санкционных списках" in result


def test_terminated_and_young():
    report = CompanyReport(
        query="x",
        inn="7707083893",
        egrul=record(registered=date(2026, 5, 1), terminated=date(2026, 9, 1)),
    )
    result = statuses(report)
    assert result["ЕГРЮЛ / ЕГРИП"] is Status.FAIL
    assert result["Возраст компании"] is Status.WARN
    assert result["Реестр операторов персональных данных"] is Status.WARN


def test_not_found():
    report = CompanyReport(query="7707083893", inn="7707083893")
    assert statuses(report)["ЕГРЮЛ / ЕГРИП"] is Status.FAIL


def test_sanctions_states():
    entry = Entry("us", "1", "entity", ["ROMASHKA"], ["7707083893"], "RUSSIA-EO14024")
    report = CompanyReport(query="x", inn="7707083893", egrul=record())
    report.company_hits = [Hit(entry, "id", "7707083893")]
    assert statuses(report)["Санкционные списки"] is Status.FAIL
    report.company_hits = [Hit(entry, "partial", "РОМАШКА")]
    assert statuses(report)["Санкционные списки"] is Status.WARN
    assert statuses(report, sanctions_ok=False)["Санкционные списки"] is Status.UNKNOWN
    assert "Санкционные списки" not in statuses(report, sanctions_ok=None)


def test_site_without_inn_warns():
    report = CompanyReport(query="example.ru", domain="example.ru")
    assert statuses(report)["Сайт и компания"] is Status.WARN


def test_site_whois_match_and_mismatch():
    report = CompanyReport(
        query="example.ru", domain="example.ru", inn="7707083893", egrul=record()
    )
    report.whois_org = 'LLC "Romashka"'
    assert statuses(report)["Сайт и компания"] is Status.OK
    report.whois_org = "OOO Vasilek"
    assert statuses(report)["Сайт и компания"] is Status.WARN


def test_render_age():
    assert render_age(date(2025, 10, 6), TODAY) == "12 мес."
    assert render_age(date(2005, 1, 1), TODAY) == "21 год"
    assert render_age(date(2003, 1, 1), TODAY) == "23 года"
    assert render_age(date(2001, 1, 1), TODAY) == "25 лет"


def test_company_html_renders():
    entry = Entry("eu", "EU.1", "entity", ["Romashka"], [], "RUS")
    report = CompanyReport(query="7707083893", inn="7707083893", egrul=record())
    report.company_hits = [Hit(entry, "name", "РОМАШКА")]
    report.checks = build_checks(report, sanctions_ok=True, today=TODAY)
    html = render_company_html(report)
    assert "РОМАШКА" in html
    assert "совпадение по названию" in html


def test_managing_company_is_screened_as_an_organisation():
    rec = record(head='Управляющая организация: ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "УК ВК"')
    assert rec.head_is_org
    report = CompanyReport(query="x", inn="7707083893", egrul=rec)
    entry = Entry("eu", "1", "entity", ["UK VK"], [], "RUS")
    report.person_hits = [Hit(entry, "name", "УК ВК")]
    result = statuses(report)
    assert result["Управляющая организация в санкционных списках"] is Status.FAIL
    assert "Руководитель в санкционных списках" not in result


def test_person_head_is_not_an_organisation():
    assert not record().head_is_org


def test_unreadable_site_is_unknown_not_a_violation():
    report = CompanyReport(query="example.ru", domain="example.ru", site_problem="защита от ботов")
    assert statuses(report)["Сайт и компания"] is Status.UNKNOWN


def test_nothing_to_screen_is_not_ok():
    report = CompanyReport(query="example.ru", domain="example.ru", site_problem="защита от ботов")
    assert statuses(report)["Санкционные списки"] is Status.UNKNOWN
