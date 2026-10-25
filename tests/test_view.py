from io import StringIO

from rich.console import Console

from suveren.advice import first_sentence, priorities
from suveren.analyze import analyze
from suveren.checks import GROUP_152, Check, Status
from suveren.cli import batch_row, read_targets
from suveren.collect import Facts, HostInfo, NetInfo, page_problem
from suveren.compliance import ComplianceInput, PolicyInfo, evaluate, find_legal_link
from suveren.models import Category, Severity
from suveren.page import parse_page
from suveren.report import write_batch_html
from suveren.view import print_scan

RICH_PAGE = (
    "<html><body>"
    + "".join(f'<a href="/p{i}">Раздел {i}</a>' for i in range(20))
    + ("<p>" + "Текст страницы. " * 80 + "</p></body></html>")
)


def sample_report():
    facts = Facts(
        host="example.ru",
        domain="example.ru",
        mx=[HostInfo("aspmx.l.google.com", NetInfo("5.5.5.5", 15169, "GOOGLE", "US"))],
        html=RICH_PAGE + '<script src="https://www.googletagmanager.com/gtag/js"></script>',
        final_url="https://example.ru/",
        page_status=200,
    )
    report = analyze(facts)
    report.checks = [
        Check(
            GROUP_152, "Политика обработки персональных данных", Status.FAIL, "Нет.", "Опубликуйте."
        ),
        Check(GROUP_152, "Защищённое соединение", Status.OK, "Сайт работает по HTTPS."),
    ]
    return report


def test_first_sentence_skips_abbreviations():
    text = "Опубликуйте политику (152-ФЗ, ст. 18.1 ч. 2). Второе предложение."
    assert first_sentence(text) == "Опубликуйте политику (152-ФЗ, ст. 18.1 ч. 2)."
    assert first_sentence("Без точки") == "Без точки"


def test_priorities_order():
    actions = priorities(sample_report())
    assert actions[0].severity == Severity.HIGH
    assert {a.reason for a in actions} >= {
        "Политика обработки персональных данных",
    }
    assert any(a.reason.startswith("Почта") for a in actions)


def test_print_scan_renders():
    out = StringIO()
    console = Console(file=out, width=110, color_system=None)
    print_scan(console, sample_report(), details=True)
    text = out.getvalue()
    assert "Независимость" in text
    assert "Google Workspace" in text
    assert "Защищённое соединение" in text and "Сайт работает по HTTPS." in text
    assert "SUV-PD-008" in text  # check IDs on the right
    assert "Персональные данные (152-ФЗ)" in text and "✗ 1" in text  # counts in the rule
    assert "ЧТО СДЕЛАТЬ" not in text  # no shouting headers


def test_footer_lists_files_and_first_steps():
    from suveren.view import header, print_footer

    out = StringIO()
    console = Console(file=out, width=110, color_system=None)
    console.print(header("1.1.0", "example.ru", "профиль deep"))
    print_footer(console, sample_report(), [("отчёт", "reports/example.ru.html")])
    text = out.getvalue()
    assert text.startswith("suveren 1.1.0   example.ru   профиль deep")
    assert "отчёт" in text and "reports/example.ru.html" in text
    assert "Что сделать первым" in text and "1  " in text


def test_page_problem_detection():
    assert page_problem(200, RICH_PAGE) is None
    assert "403" in page_problem(403, "<p>Доступ ограничен</p>")
    assert "не робот" in page_problem(200, "<div>Подтвердите, что вы не робот. captcha</div>")
    assert "скриптами" in page_problem(200, '<div id="root"></div><script src="/app.js"></script>')
    # A browser that passed a challenge: the 403 of the first response no longer matters.
    assert page_problem(403, RICH_PAGE, rendered=True) is None


def test_unverifiable_page_turns_html_checks_unknown():
    data = ComplianceInput(
        final_url="https://example.ru/",
        page=parse_page("<div id='root'></div>"),
        deps=[],
        page_problem="страница собирается скриптами",
    )
    checks = {c.title: c for c in evaluate(data, "<div id='root'></div>")}
    assert checks["Политика обработки персональных данных"].status is Status.UNKNOWN
    assert checks["Трансграничная передача данных"].status is Status.UNKNOWN
    assert checks["Защищённое соединение"].status is Status.OK


def test_indirect_policy_is_warning():
    data = ComplianceInput(
        final_url="https://example.ru/",
        page=parse_page(RICH_PAGE),
        deps=[],
        policy=PolicyInfo(
            url="https://example.ru/docs/usage/", fetched=True, indirect_label="Соглашение"
        ),
    )
    checks = {c.title: c for c in evaluate(data, RICH_PAGE)}
    check = checks["Политика обработки персональных данных"]
    assert check.status is Status.WARN
    assert "Соглашение" in check.details


def test_find_legal_link():
    page = parse_page('<a href="/news">Новости</a><a href="/docs/usage/">Соглашение</a>')
    assert find_legal_link(page.links, "https://example.ru/") == (
        "https://example.ru/docs/usage/",
        "Соглашение",
    )


def test_read_targets(tmp_path):
    path = tmp_path / "sites.txt"
    path.write_text(
        "# список\nexample.ru\nhttps://www.example.com/page\n\nexample.ru  # дубль\n"
        "not a domain!!\n",
        encoding="utf-8",
    )
    hosts, skipped = read_targets(path)
    assert hosts == ["example.ru", "www.example.com"]
    # A typo is skipped with its line number instead of stopping the whole list.
    assert skipped == ["строка 6: «not a domain!!» — это не доменное имя"]


def test_batch_outputs(tmp_path):
    report = sample_report()
    row = batch_row(report)
    assert row["domain"] == "example.ru"
    assert row["pd_fail"] == 1
    assert isinstance(row["fines_max"], int)
    # Old columns keep their places in summary.csv; new ones are appended.
    assert list(row)[-5:] == [
        "top_risks",
        "fines_max",
        "overall_grade",
        "overall_score",
        "overall_incomplete",
    ]
    assert list(row)[1:3] == ["grade", "score"]  # independence keeps its place
    index = write_batch_html([report], [("bad.ru", "NXDOMAIN")], tmp_path / "index.html")
    html = index.read_text(encoding="utf-8")
    assert 'href="example.ru.html"' in html
    assert "bad.ru" in html
    assert "Общая оценка" in html and "Независимость" in html


def test_builder_detection():
    facts = Facts(
        host="example.ru",
        domain="example.ru",
        html=RICH_PAGE + '<link href="https://static.tildacdn.com/css/tilda-grid.css">',
    )
    deps = analyze(facts).dependencies
    tilda = next(d for d in deps if d.service == "Tilda")
    assert tilda.category is Category.BUILDER
    assert tilda.foreign


def test_challenge_page_with_a_few_links_is_detected():
    stub = "<p>Спортмастер 8-800-777-777-1 Пожалуйста, пройдите проверку.</p>" + "".join(
        f'<a href="tel:{i}">{i}</a>' for i in range(4)
    )
    assert page_problem(401, stub, rendered=True) is not None
    assert page_problem(200, stub, rendered=True) is not None


def test_priorities_say_one_thing_once():
    from suveren.advice import priorities
    from suveren.catalog import BY_ID

    report = sample_report()
    for check_id in ("SUV-MAIL-001", "SUV-MAIL-002", "SUV-MAIL-003", "SUV-ATK-001"):
        spec = BY_ID[check_id]
        title = "Можно ли подделать письмо от имени @example.ru" if spec.pattern else spec.title
        report.checks.append(Check(spec.group, title, Status.FAIL, "", f"Совет {check_id}."))
    mail = [a for a in priorities(report) if a.action.startswith("Совет SUV-")]
    assert [a.action for a in mail] == ["Совет SUV-MAIL-001."]  # the verdict, not the scenario


def test_report_tiles_and_table_of_contents():
    from suveren.catalog import BY_ID
    from suveren.report import navigation, render_html, summary_tiles

    report = sample_report()
    whole = BY_ID["SUV-CUT-001"]
    page = BY_ID["SUV-CUT-002"]
    report.checks += [
        Check(whole.group, whole.title, Status.FAIL),
        Check(page.group, page.title, Status.OK),
    ]
    tiles = {t["label"]: t for t in summary_tiles(report)}
    assert tiles["Проблемы"]["value"] == "2" and tiles["Проблемы"]["tone"] == "fail"
    # The page works without foreign scripts, but foreign DNS or hosting take it all down.
    assert tiles["Без иностранных сервисов"]["value"] == "сайт не откроется"
    nav = navigation(report, has_plan=True)
    assert [n["title"] for n in nav][:2] == ["Что сделать", "Зависимости"]
    assert any(n["title"] == "Персональные данные" and n["fail"] == 1 for n in nav)
    html = render_html(report)
    assert 'class="toc"' in html and 'class="tiles"' in html
    for anchor in ("todo", "risks", "plan", "services"):
        assert f'id="{anchor}"' in html


def test_report_links_are_short_and_reasons_lead_to_checks():
    from suveren.catalog import BY_ID
    from suveren.report import linkify, render_html

    html = str(linkify("рекомендации РКН: https://www.garant.ru/doc/1/). <b>"))
    assert '<a href="https://www.garant.ru/doc/1/"' in html and ">garant.ru</a>)." in html
    assert "&lt;b&gt;" in html  # the rest stays escaped
    assert "http://" in str(linkify("по адресу http://.")) and "<a" not in str(linkify("http://."))

    report = sample_report()
    spec = BY_ID["SUV-PD-002"]
    report.checks.append(Check(spec.group, spec.title, Status.FAIL, "", "Сделайте так."))
    page = render_html(report)
    assert f'id="{spec.id}"' in page and f'<a href="#{spec.id}">{spec.title}</a>' in page


def test_overall_grade_counts_each_problem_once():
    from suveren.advice import overall_score
    from suveren.catalog import BY_ID

    report = sample_report()
    before = overall_score(report)
    for check_id in ("SUV-MAIL-001", "SUV-MAIL-002", "SUV-MAIL-003"):
        spec = BY_ID[check_id]
        title = "Можно ли подделать письмо от имени @example.ru" if spec.pattern else spec.title
        report.checks.append(Check(spec.group, title, Status.FAIL, "", "Совет."))
    # Three checks, one problem (the mail records): one penalty, not three.
    assert before - overall_score(report) == 10
    data = report.to_dict()
    assert data["overall_score"] == overall_score(report) and data["overall_grade"] in "ABCDF"
    html = __import__("suveren.report", fromlist=["render_html"]).render_html(report)
    assert "Общая оценка" in html and "Независимость" in html


def test_overall_grade_says_what_it_covers():
    from suveren.advice import overall_scope
    from suveren.models import Report
    from suveren.report import render_html

    empty = Report(target="empty.ru")
    # Nothing but dependencies was checked (--quick): the grade must not claim laws or mail.
    assert overall_scope(empty) == "проверены только иностранные зависимости"
    html = render_html(empty)
    assert "проверены только иностранные зависимости" in html and "Сервисов не найдено" in html
    assert overall_scope(sample_report()) == "проверено: законы, зависимости"


def test_agencies_under_gov_ru_have_their_own_domain():
    from suveren.utils import registrable_domain

    # nalog.gov.ru's mail is its own, not gov.ru's.
    assert registrable_domain("www.nalog.gov.ru") == "nalog.gov.ru"


def test_small_page_without_scripts_is_not_a_script_shell():
    assert page_problem(200, "<h1>Example</h1><p>Short page.</p><a href='/x'>More</a>") is None
    assert page_problem(200, '<div id="root"></div><script src="/app.js"></script>') is not None


def test_missing_policy_is_a_problem_only_when_the_browser_saw_the_page():
    def policy(rendered):
        data = ComplianceInput(
            final_url="https://example.ru/", page=parse_page(RICH_PAGE), deps=[], rendered=rendered
        )
        return {c.title: c for c in evaluate(data, RICH_PAGE)}[
            "Политика обработки персональных данных"
        ]

    # Without a browser a footer added by scripts is unseen (mos.ru): a warning to recheck.
    assert policy(False).status is Status.WARN and "--browser" in policy(False).details
    # RICH_PAGE collects nothing: the duty to publish the policy on the site is for an
    # operator collecting data through it (152-ФЗ, ст. 18.1 ч. 2).
    assert policy(True).status is Status.WARN and "не обязательно" in policy(True).details
    form = '<form><input type="tel" name="phone"><button>Позвоните мне</button></form>'
    html = RICH_PAGE.replace("</body>", form + "</body>")
    data = ComplianceInput(
        final_url="https://example.ru/", page=parse_page(html), deps=[], rendered=True
    )
    checks = {c.title: c for c in evaluate(data, html)}
    assert checks["Политика обработки персональных данных"].status is Status.FAIL


def test_overall_scope_warns_when_much_was_not_checked():
    from suveren.advice import overall_scope
    from suveren.catalog import BY_ID

    report = sample_report()
    for check_id in ("SUV-PD-003", "SUV-PD-006", "SUV-LAW-001"):
        spec = BY_ID[check_id]
        report.checks.append(Check(spec.group, spec.title, Status.UNKNOWN, "Не проверено."))
    assert "не удалось проверить 3 из 5" in overall_scope(report)


def test_templates_use_only_defined_colours():
    # An undefined variable falls back silently: the script graph had white boxes with
    # light text in the dark theme because --card did not exist.
    import re
    from pathlib import Path

    folder = Path(__file__).parent.parent / "src" / "suveren" / "templates"
    css = (folder / "base.html.j2").read_text(encoding="utf-8")
    defined = set(re.findall(r"(--[\w-]+)\s*:", css))
    for template in folder.glob("*.j2"):
        used = set(re.findall(r"var\((--[\w-]+)", template.read_text(encoding="utf-8")))
        assert used <= defined, f"{template.name}: {sorted(used - defined)}"


def test_a_section_that_did_not_run_counts_as_all_its_checks():
    from suveren.advice import overall_scope
    from suveren.catalog import BY_ID
    from suveren.models import Report

    # gosuslugi.ru once: the page did not load, so 152-ФЗ and web security were one line
    # each, and the overall grade looked like an A.
    report = Report(target="example.ru")
    for check_id in ("SUV-PD-000", "SUV-WEB-000"):
        spec = BY_ID[check_id]
        report.checks.append(Check(spec.group, spec.title, Status.UNKNOWN, "Не проверено."))
    mail = BY_ID["SUV-MAIL-002"]
    report.checks.append(Check(mail.group, mail.title, Status.OK, "SPF в порядке."))
    scope = overall_scope(report)
    ran = scope.split(";")[0]
    assert "законы" not in ran and "безопасность" not in ran
    assert "оценка не выше B" in scope
    assert (
        "оценка неполная, не проверены: 152-ФЗ на страницах сайта, заголовки безопасности" in scope
    )
    from suveren.advice import incomplete

    assert (
        incomplete(report)[0] == "не проверены: 152-ФЗ на страницах сайта, заголовки безопасности"
    )
    assert report.to_dict()["overall_incomplete"] == incomplete(report)


def test_unanswered_site_dns_makes_the_grade_incomplete():
    from suveren.advice import incomplete

    # sravni.ru: four services vanished with the DNS answers, not from the site.
    report = sample_report()
    report.facts["dns_unanswered"] = ["ns", "web"]
    assert incomplete(report) == ["не проверены: DNS-серверы, IP-адреса и хостинг сайта"]
    assert report.to_dict()["overall_incomplete"] == incomplete(report)


def test_a_full_report_is_not_incomplete():
    from suveren.advice import incomplete

    assert incomplete(sample_report()) == []
    assert sample_report().to_dict()["overall_incomplete"] == []


def test_services_table_gives_the_same_risk_as_the_dependency_card():
    from suveren.models import Dependency, Finding, Report
    from suveren.report import render_html

    # skyeng.ru: DNS partly in Russia, so the card said "средний" and the table "высокий".
    report = Report(target="example.ru")
    report.dependencies = [
        Dependency(Category.DNS, "EdgeCenter", "RU", "NS ns1.edgedns.ru"),
        Dependency(Category.DNS, "EDGEAM", "AM", "NS ns2.edgedns.world", Severity.HIGH),
    ]
    report.findings = [
        Finding(Category.DNS, "DNS-серверы: EDGEAM", Severity.MEDIUM, "Часть в России.", "Да.")
    ]
    services = render_html(report).split('id="services"')[1]
    assert "sev-medium" in services and "sev-high" not in services


def test_a_needs_the_checks_to_have_run():
    from suveren.advice import overall_grade, overall_score
    from suveren.catalog import BY_ID
    from suveren.models import Report

    # A clean site behind a bot wall: nothing failed because little was seen.
    report = Report(target="example.ru")
    for check_id in ("SUV-PD-001", "SUV-PD-003", "SUV-PD-006", "SUV-WEB-001"):
        spec = BY_ID[check_id]
        report.checks.append(Check(spec.group, spec.title, Status.UNKNOWN, "Не проверено."))
    for check_id in ("SUV-MAIL-002", "SUV-MAIL-003"):
        spec = BY_ID[check_id]
        report.checks.append(Check(spec.group, spec.title, Status.OK, "В порядке."))
    assert overall_score(report) == 89 and overall_grade(report) == "B"
