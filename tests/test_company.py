from datetime import date

from suveren.checks import Status
from suveren.company import CompanyReport, build_checks, pick_record, render_age
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
    report.sanctions_sources = ["us", "eu", "uk"]
    report.company_hits = [Hit(entry, "id", "7707083893")]
    assert statuses(report)["Санкционные списки"] is Status.FAIL
    report.company_hits = [Hit(entry, "partial", "РОМАШКА")]
    assert statuses(report)["Санкционные списки"] is Status.WARN
    assert statuses(report, sanctions_ok=False)["Санкционные списки"] is Status.UNKNOWN
    assert "Санкционные списки" not in statuses(report, sanctions_ok=None)


def test_sanctions_with_a_list_missing_are_not_checked():
    # "Не найдена в списках: США" read as clean while the EU and UK lists had not loaded.
    report = CompanyReport(query="x", inn="7707083893", egrul=record())
    report.sanctions_sources = ["us"]
    check = next(c for c in build_checks(report, sanctions_ok=True, today=TODAY)
                 if c.title == "Санкционные списки")  # fmt: skip
    assert check.status is Status.UNKNOWN and "Не загрузились: ЕС" in check.details
    # A hit in the lists that did load is still a hit.
    entry = Entry("us", "1", "entity", ["ROMASHKA"], ["7707083893"], "RUSSIA-EO14024")
    report.company_hits = [Hit(entry, "id", "7707083893")]
    assert statuses(report)["Санкционные списки"] is Status.FAIL


def sanctions_check(report):
    return next(c for c in build_checks(report, sanctions_ok=True, today=TODAY)
                if c.title == "Санкционные списки")  # fmt: skip


def test_an_outdated_copy_of_the_lists_is_not_clean():
    # A copy kept because the refresh failed was accepted at any age, the check stayed OK.
    report = CompanyReport(query="x", inn="7707083893", egrul=record())
    report.sanctions_sources = ["us", "eu", "uk"]
    report.sanctions_stale = {"eu": 40}
    check = sanctions_check(report)
    assert check.status is Status.UNKNOWN
    assert "список) — 40 дн." in check.details and "--refresh" in check.recommendation


def test_without_egrul_only_the_ids_were_screened():
    # Most entries have no ИНН: a clean answer by ИНН alone is not a clean answer.
    report = CompanyReport(query="7707083893", inn="7707083893", egrul_error="нет связи")
    report.sanctions_sources = ["us", "eu", "uk"]
    check = sanctions_check(report)
    assert check.status is Status.UNKNOWN and "ЕГРЮЛ не дал запись" in check.details
    report.egrul_error = None
    assert "в ЕГРЮЛ её нет" in sanctions_check(report).details


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
    # By name only, with no ИНН to compare: a lead to check, not a verdict.
    assert result["Управляющая организация в санкционных списках"] is Status.WARN
    assert "Руководитель в санкционных списках" not in result


def test_person_head_is_not_an_organisation():
    assert not record().head_is_org


def test_unreadable_site_is_unknown_not_a_violation():
    report = CompanyReport(query="example.ru", domain="example.ru", site_problem="защита от ботов")
    assert statuses(report)["Сайт и компания"] is Status.UNKNOWN


def test_nothing_to_screen_is_not_ok():
    report = CompanyReport(query="example.ru", domain="example.ru", site_problem="защита от ботов")
    assert statuses(report)["Санкционные списки"] is Status.UNKNOWN


def test_sanctions_levels_by_name_and_ids():
    """ИНН/ОГРН match: FAIL. Same name, nothing to compare: WARN. Same name, the entry
    has its own ИНН: another organisation, OK with a note (an «Арсенал» with its own
    ИНН was "in the sanctions lists" because an LLC ARSENAL with another one is)."""
    report = CompanyReport(query="x", inn="7812345675", egrul=record())
    report.sanctions_sources = ["us", "eu", "uk"]
    listed = Entry("us", "1", "entity", ["LLC ARSENAL"], ["2465316804"], "RUSSIA-EO14024")
    bare = Entry("eu", "2", "entity", ["Арсенал"], [], "RUS")

    def check():
        return next(c for c in build_checks(report, sanctions_ok=True, today=TODAY)
                    if c.title == "Санкционные списки")  # fmt: skip

    report.company_hits = [Hit(listed, "other", "ООО «Арсенал»")]
    assert check().status is Status.OK and "другими ИНН/ОГРН (1)" in check().details
    report.company_hits = [Hit(bare, "name", "ООО «Арсенал»")]
    assert check().status is Status.WARN and "Реквизитов" in check().details
    report.company_hits = [Hit(listed, "id", "2465316804")]
    assert check().status is Status.FAIL


def test_a_sanctioned_sole_trader_is_found():
    """A sole trader is a person in the lists: its ИНН was searched among companies only,
    and its name was screened with "ИНДИВИДУАЛЬНЫЙ ПРЕДПРИНИМАТЕЛЬ" read as the surname."""
    from suveren.sanctions import SanctionsIndex, screen_company, screen_person

    person = Entry("eu", "7", "person", ["Mikhail Timofeevich VYDUMKIN"], ["770000000082"], "RUS")
    index = SanctionsIndex([person])
    rec = record(
        name_full="ИНДИВИДУАЛЬНЫЙ ПРЕДПРИНИМАТЕЛЬ Выдумкин Михаил Тимофеевич",
        name_short=None,
        inn="770000000082",
        ogrn="304770000000001",
        head=None,
        individual=True,
    )
    assert rec.person_name == "Выдумкин Михаил Тимофеевич"
    hits = screen_company(index, ["770000000082"], [rec.name_full], persons=True)
    assert [(h.entry.ref, h.how) for h in hits] == [("7", "id")]
    assert screen_company(index, ["770000000082"], [rec.name_full]) == []  # a company: no
    assert screen_person(index, rec.person_name)

    report = CompanyReport(query="770000000082", inn="770000000082", egrul=rec)
    report.sanctions_sources = ["us", "eu", "uk"]
    report.company_hits = hits
    assert statuses(report)["Санкционные списки"] is Status.FAIL
    # The same person by ИНН: not "may be a namesake" next to it.
    report.person_hits = screen_person(index, rec.person_name)
    checks = {c.title: c for c in build_checks(report, sanctions_ok=True, today=TODAY)}
    assert checks["Руководитель в санкционных списках"].status is Status.FAIL
    assert "тёзка" not in checks["Руководитель в санкционных списках"].recommendation
    assert checks["Санкционные списки"].details.startswith("Предприниматель")


def test_pick_record_prefers_the_active_row_and_no_stranger():
    # A sole trader who closed and registered again: the first row was the closed one.
    closed = record(ogrn="304770000000011", terminated=date(2020, 1, 1))
    active = record(ogrn="320770000000022", registered=date(2020, 3, 1))
    assert pick_record([closed, active], "7707083893") is active
    # Without a row of this ИНН, another company was taken in its place.
    stranger = record(inn="7702070139", ogrn="1027739609391")
    assert pick_record([stranger], "7707083893") is None


def test_a_clean_screening_says_owners_were_not_screened():
    report = CompanyReport(query="x", inn="7707083893", egrul=record())
    report.sanctions_sources = ["us", "eu", "uk"]
    check = sanctions_check(report)
    assert check.status is Status.OK and "Учредители и владельцы не сверялись" in check.details


def _sources(check):
    return [e.value for e in check.evidence if e.what == "Источник"]


def test_every_company_check_names_its_register_and_date():
    report = CompanyReport(query="7707083893", inn="7707083893", egrul=record())
    report.operator = RknOperator("77-1", "ООО Ромашка", "7707083893", "", date(2016, 1, 1), None)
    report.sanctions_sources = ["us", "eu"]
    report.sources = {
        "egrul": "ЕГРЮЛ (egrul.nalog.ru), запрос от 06.10.2026",
        "rkn": "Реестр операторов ПДн Роскомнадзора (pd.rkn.gov.ru), запрос от 06.10.2026",
        "sanctions:us": "США (OFAC SDN), выгрузка от 05.10.2026",
        "sanctions:eu": "ЕС (сводный санкционный список), выгрузка от 01.10.2026",
    }
    report.checks = build_checks(report, sanctions_ok=True, today=TODAY)
    by_id = {c.id: c for c in report.checks}
    assert _sources(by_id["SUV-CO-001"]) == [report.sources["egrul"]]
    assert _sources(by_id["SUV-CO-006"]) == [report.sources["rkn"]]
    # Each list carries its own date: a copy kept after a failed refresh shows its age.
    assert _sources(by_id["SUV-CO-003"]) == [
        "США (OFAC SDN), выгрузка от 05.10.2026",
        "ЕС (сводный санкционный список), выгрузка от 01.10.2026",
    ]
    assert report.sources["egrul"] in _sources(by_id["SUV-CO-004"])
    html = render_company_html(report)
    assert "Источники: США (OFAC SDN), выгрузка от 05.10.2026; ЕС" in html


def test_a_register_that_did_not_answer_names_no_source():
    report = CompanyReport(query="7707083893", inn="7707083893", egrul_error="таймаут")
    checks = build_checks(report, sanctions_ok=None, today=TODAY)
    assert all(not _sources(c) for c in checks)
