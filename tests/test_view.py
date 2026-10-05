from io import StringIO

from rich.console import Console

from suveren.analyze import analyze
from suveren.checks import GROUP_152, Check, Status
from suveren.cli import batch_row, read_targets
from suveren.collect import Facts, HostInfo, NetInfo, page_problem
from suveren.compliance import ComplianceInput, PolicyInfo, evaluate, find_legal_link
from suveren.models import Category, Severity
from suveren.page import parse_page
from suveren.report import write_batch_html
from suveren.view import first_sentence, print_scan, priorities

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
    assert "ЧТО СДЕЛАТЬ В ПЕРВУЮ ОЧЕРЕДЬ" in text
    assert "Google Workspace" in text
    assert "Защищённое соединение — сайт работает по HTTPS." in text


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
        "# список\nexample.ru\nhttps://www.example.com/page\n\nexample.ru  # дубль\n",
        encoding="utf-8",
    )
    assert read_targets(path) == ["example.ru", "www.example.com"]


def test_batch_outputs(tmp_path):
    report = sample_report()
    row = batch_row(report)
    assert row["domain"] == "example.ru"
    assert row["pd_fail"] == 1
    index = write_batch_html([report], [("bad.ru", "NXDOMAIN")], tmp_path / "index.html")
    html = index.read_text(encoding="utf-8")
    assert 'href="example.ru.html"' in html
    assert "bad.ru" in html


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
