import asyncio

from suveren.checks import Status
from suveren.cutoff import HostInfo
from suveren.dataflow import flow, flow_check, run_dataflow


def hosts(*items):
    return {i.host: i for i in items}


def test_flow_groups_by_country_foreign_first():
    rows = flow(
        hosts(
            HostInfo("mc.yandex.ru", "Яндекс Метрика", "RU"),
            HostInfo("www.googletagmanager.com", "Google Analytics", "US"),
            HostInfo("connect.facebook.net", "Meta Pixel", "US"),
            HostInfo("cdn.example.nl", "Leaseweb", "NL", via_network=True),
            HostInfo("x.unknown.io", None, None),
        )
    )
    assert [r["country"] for r in rows] == ["US", "NL", "RU", "??"]
    assert rows[0]["services"] == ["Google Analytics", "Meta Pixel"]
    assert rows[-1]["name"] == "страна не определена" and not rows[-1]["foreign"]
    check = flow_check(rows)
    assert check.id == "SUV-PD-010" and check.status is Status.WARN
    assert "США — Google Analytics, Meta Pixel" in check.details
    assert "2 страны" in check.recommendation and check.law == "152-ФЗ, ст. 12"


def test_flow_inside_russia_only_or_nothing_is_ok():
    russian = flow(hosts(HostInfo("mc.yandex.ru", "Яндекс Метрика", "RU")))
    assert flow_check(russian).status is Status.OK
    assert "1 стороннему сервису:" in flow_check(russian).details
    assert flow_check([]).status is Status.OK


def test_run_dataflow_uses_the_service_base_without_network():
    class NoNetwork:
        async def _host_infos(self, host):
            raise AssertionError("known services need no lookup")

    urls = ["https://example.ru/", "https://mc.yandex.ru/metrika/tag.js"]
    check, rows = asyncio.run(run_dataflow(urls, "example.ru", NoNetwork()))
    assert rows[0]["country"] == "RU" and check.status is Status.OK


def test_report_shows_the_flow_and_counts_it_with_cross_border_once():
    from test_view import sample_report

    from suveren.advice import overall_score
    from suveren.catalog import BY_ID
    from suveren.checks import Check
    from suveren.report import render_html

    report = sample_report()
    rows = flow(hosts(HostInfo("connect.facebook.net", "Meta Pixel", "US")))
    report.facts["dataflow"] = rows
    pd6 = BY_ID["SUV-PD-006"]
    report.checks.append(Check(pd6.group, pd6.title, Status.WARN, "", "Уберите пиксели."))
    before = overall_score(report)
    report.checks.append(flow_check(rows))
    assert overall_score(report) == before  # same problem as SUV-PD-006
    html = render_html(report)
    assert 'class="card flow"' in html and "Meta Pixel" in html


def test_report_says_cross_border_once():
    from test_view import sample_report

    from suveren.catalog import BY_ID
    from suveren.checks import Check
    from suveren.report import render_html

    report = sample_report()
    rows = flow(hosts(HostInfo("connect.facebook.net", "Meta Pixel", "US")))
    report.facts["dataflow"] = rows
    pd6 = BY_ID["SUV-PD-006"]
    report.checks += [
        Check(pd6.group, pd6.title, Status.WARN, "Meta Pixel (США).", "Уведомите Роскомнадзор."),
        flow_check(rows),
    ]
    html = render_html(report)
    # The row points to the table; the advice is PD-006's alone.
    assert "в таблице ниже" in html
    assert html.count("уведомите Роскомнадзор о трансграничной") == 0
    assert html.count("Уведомите Роскомнадзор.") == 2  # the to-do list and PD-006 itself
