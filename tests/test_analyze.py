from suveren.analyze import analyze
from suveren.collect import Facts, HostInfo, NetInfo
from suveren.models import Category, Severity
from suveren.report import render_html


def make_facts(**kwargs):
    defaults = {"host": "example.ru", "domain": "example.ru"}
    defaults.update(kwargs)
    return Facts(**defaults)


def ru_net(ip="1.1.1.1"):
    return NetInfo(ip, 49505, "SELECTEL", "RU")


def finding(report, category):
    return next((f for f in report.findings if f.category is category), None)


def test_fully_domestic_site_gets_a():
    facts = make_facts(
        ns=[HostInfo("ns1.selectel.org", ru_net()), HostInfo("ns2.selectel.org", ru_net())],
        mx=[HostInfo("mx.yandex.net", NetInfo("2.2.2.2", 13238, "YANDEX", "RU"))],
        web=[ru_net("3.3.3.3")],
        registrar="RU-CENTER-RU",
        html='<script src="https://mc.yandex.ru/metrika/tag.js"></script>',
    )
    report = analyze(facts)
    assert report.findings == []
    assert report.grade == "A"
    assert report.countries == [("RU", 100)]


def test_google_mail_and_cloudflare_dns_are_high():
    facts = make_facts(
        ns=[HostInfo("ada.ns.cloudflare.com", NetInfo("4.4.4.4", 13335, "CLOUDFLARENET", "US"))],
        mx=[HostInfo("aspmx.l.google.com", NetInfo("5.5.5.5", 15169, "GOOGLE", "US"))],
    )
    report = analyze(facts)
    assert finding(report, Category.DNS).severity == Severity.HIGH
    assert finding(report, Category.MAIL).severity == Severity.HIGH
    assert "Google Workspace" in finding(report, Category.MAIL).title
    assert report.score == 60


def test_mixed_ns_lowers_severity():
    facts = make_facts(
        ns=[
            HostInfo("ns1.hetzner.com", NetInfo("6.6.6.6", 24940, "HETZNER", "DE")),
            HostInfo("ns1.selectel.org", ru_net()),
        ]
    )
    f = finding(analyze(facts), Category.DNS)
    assert f.severity == Severity.MEDIUM
    assert "Часть серверов находится в России" in f.description


def test_cdn_ip_is_cdn_not_hosting():
    facts = make_facts(web=[NetInfo("104.16.1.1", 13335, "CLOUDFLARENET", "US")])
    report = analyze(facts)
    assert finding(report, Category.CDN) is not None
    assert finding(report, Category.HOSTING) is None
    assert any("настоящий хостинг скрыт" in n for n in report.notes)


def test_unknown_network_uses_as_country():
    facts = make_facts(web=[NetInfo("7.7.7.7", 64500, "SOME HOSTER LTD", "NL")])
    dep = next(d for d in analyze(facts).dependencies if d.category is Category.HOSTING)
    assert (dep.service, dep.country, dep.foreign) == ("SOME HOSTER LTD", "NL", True)


def test_unknown_country_is_not_a_finding():
    facts = make_facts(registrar="Some Unknown Registrar Inc.")
    report = analyze(facts)
    assert report.findings == []
    assert report.dependencies[-1].foreign is None


def test_page_services_grouped_into_one_finding_per_category():
    html = (
        '<script src="https://www.googletagmanager.com/gtag/js"></script>'
        '<script src="https://static.hotjar.com/c/hotjar.js"></script>'
    )
    report = analyze(make_facts(html=html))
    analytics = [f for f in report.findings if f.category is Category.ANALYTICS]
    assert len(analytics) == 1
    assert analytics[0].services == ["Google Analytics / Tag Manager", "Hotjar"]
    assert "Яндекс Метрика" in analytics[0].recommendation


def test_foreign_zone_is_low():
    report = analyze(make_facts(host="example.com", domain="example.com"))
    f = finding(report, Category.ZONE)
    assert f.severity == Severity.LOW


def test_report_json_and_html_render():
    facts = make_facts(
        mx=[HostInfo("aspmx.l.google.com", NetInfo("5.5.5.5", 15169, "GOOGLE", "US"))],
        html='<iframe src="https://www.youtube.com/embed/x"></iframe>',
    )
    report = analyze(facts)
    data = report.to_dict()
    assert data["grade"] == report.grade
    assert {d["service"] for d in data["dependencies"]} >= {"Google Workspace", "YouTube"}
    html = render_html(report)
    assert "Google Workspace" in html
    assert "Яндекс 360" in html  # mail alternatives are rendered
