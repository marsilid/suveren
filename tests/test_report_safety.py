"""Scanned content reaches the HTML report: it must stay text, never markup or code.

A site under audit controls its policy link, the quotes taken from its pages, the
hosts its scripts come from. The report is opened by the site's owner or an auditor,
so markup in any of these would run in their browser (a stored XSS in a security tool).
"""

from test_view import sample_report

from suveren.checks import GROUP_152, Check, Status
from suveren.models import Category, Dependency
from suveren.report import render_html, web_url

PAYLOAD = '<script>alert("x")</script><img src=x onerror=alert(1)>'


def test_scanned_text_and_links_cannot_inject_code():
    report = sample_report()
    report.checks.append(
        Check(
            GROUP_152,
            "Политика обработки персональных данных",
            Status.OK,
            f"Политика опубликована: «{PAYLOAD}» https://x.ru/{PAYLOAD}",
            f"Совет {PAYLOAD}",
            link="javascript:alert(document.cookie)",
        )
    )
    report.dependencies.append(
        Dependency(Category.ANALYTICS, f"Сервис {PAYLOAD}", "US", f"src={PAYLOAD}")
    )
    report.notes.append(f"Заметка {PAYLOAD}")
    html = render_html(report)
    assert "<script>alert" not in html
    assert "onerror=alert" not in html.replace("onerror=alert(1)&gt;", "")
    assert "<img src=x" not in html
    assert 'href="javascript:' not in html.lower()
    assert "&lt;script&gt;" in html  # shown as text, not dropped


def test_only_web_addresses_become_links():
    assert web_url("https://example.ru/privacy") == "https://example.ru/privacy"
    assert web_url(" HTTP://example.ru/ ") == "HTTP://example.ru/"
    for bad in ("javascript:alert(1)", " JavaScript:alert(1)", "data:text/html,x", "", None):
        assert web_url(bad) is None
