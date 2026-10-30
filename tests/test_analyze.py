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


DOMESTIC = {
    "ns": [HostInfo("ns1.selectel.org", ru_net()), HostInfo("ns2.selectel.org", ru_net())],
    "mx": [HostInfo("mx.yandex.net", NetInfo("2.2.2.2", 13238, "YANDEX", "RU"))],
    "web": [ru_net("3.3.3.3")],
    "registrar": "RU-CENTER-RU",
}


def test_an_unseen_page_caps_the_grades_at_b():
    """A local proxy answered an unreachable host with a bare 503: no findings, so the
    site got A 100/100 in --quick, and --fail-under A let it through."""
    from suveren.advice import PAGE_SECTION, incomplete, overall_grade

    for status, html, why in [
        (503, "", "кодом 503 без страницы"),
        (None, "", "не загрузилась"),
        (403, "<html><body>Access denied</body></html>", "кодом 403"),
    ]:
        report = analyze(make_facts(**DOMESTIC, page_status=status, html=html))
        assert report.findings == [] and why in (report.page_unseen or "")
        assert (report.grade, report.score) == ("B", 89)
        assert overall_grade(report) == "B"
        assert incomplete(report) == [f"не проверены: {PAGE_SECTION}"]
        assert any("оценки не выше B" in n for n in report.notes)
        assert report.to_dict()["facts"]["page_unseen"] == report.page_unseen


def test_a_thin_script_page_is_seen():
    # Its scripts are in the code: a small single-page app keeps its A.
    report = analyze(make_facts(**DOMESTIC, page_status=200, html="<script src=/app.js></script>"))
    assert report.page_unseen is None and report.grade == "A"


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


def test_cloudfront_in_amazons_network_is_a_cdn():
    """CloudFront answers from AS16509 like plain AWS hosting: aviasales.ru got "the
    database is abroad" (SUV-PD-007) and 6 млн ₽ for an edge server."""
    aws = [NetInfo("13.33.1.1", 16509, "AMAZON-02", "US")]
    edge = analyze(make_facts(web=aws, headers={"x-amz-cf-id": "abc", "via": "1.1 x (CloudFront)"}))
    dep = next(d for d in edge.dependencies if d.service == "Amazon CloudFront")
    assert dep.category is Category.CDN and "x-amz-cf-id" in dep.evidence
    assert not any(d.category is Category.HOSTING for d in edge.dependencies)
    assert any("настоящий хостинг скрыт" in n for n in edge.notes)
    plain = analyze(make_facts(web=aws, headers={"server": "nginx"}))
    assert any(
        d.category is Category.HOSTING and d.service == "Amazon Web Services"
        for d in plain.dependencies
    )


def test_ddos_guard_abroad_network_is_its_cdn():
    # ddos-guard.net answered from AS59692 (IQWeb FZ-LLC, UAE): hosting "abroad" before.
    report = analyze(make_facts(web=[NetInfo("186.2.163.1", 59692, "IQWEB-AS", "AE")]))
    assert [
        (d.category, d.service) for d in report.dependencies if d.evidence.startswith("IP")
    ] == [(Category.CDN, "DDoS-Guard")]


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
    assert "Яндекс Метрику" in analytics[0].recommendation


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


def test_own_network_is_recognised():
    from suveren.analyze import own_network

    assert own_network(NetInfo("1.1.1.1", 64500, "Habr Europe OU", "EE"), "habr.com")
    assert own_network(NetInfo("1.1.1.1", 64500, "OOO Habr", "RU"), "habr.com")
    # Generic or short names, and other companies, are not the site's own network.
    assert not own_network(NetInfo("1.1.1.1", 13335, "CLOUDFLARENET", "US"), "cloud.ru")
    assert not own_network(NetInfo("1.1.1.1", 64501, "CLOUD.DOG OU", "EE"), "cloud.ru")
    assert not own_network(NetInfo("1.1.1.1", 24940, "Hetzner Online GmbH", "DE"), "habr.com")
    assert not own_network(NetInfo("1.1.1.1", 64502, "VK", "RU"), "vk.com")


def test_own_mail_servers_are_a_low_risk_not_a_vendor():
    own = NetInfo("5.5.5.5", 64500, "Habr Europe OU", "EE")
    report = analyze(
        make_facts(host="habr.com", domain="habr.com", mx=[HostInfo("mxs.habramail.net", own)])
    )
    mail = finding(report, Category.MAIL)
    assert mail.severity is Severity.LOW
    assert "Собственная сеть (Habr Europe OU)" in mail.title
    assert "собственная сеть компании" in mail.description


def test_unknown_dns_name_on_a_known_network_names_both():
    """ns1.dyna-ns.net was reported as Cloudflare: its network, not its operator."""
    cf = NetInfo("104.16.0.1", 13335, "CLOUDFLARENET", "US")
    report = analyze(make_facts(ns=[HostInfo("ns1.some-dns.net", cf)]))
    dns = next(d for d in report.dependencies if d.category is Category.DNS)
    assert dns.service == "some-dns.net (на сети Cloudflare)" and dns.country == "US"
    dynadot = analyze(make_facts(ns=[HostInfo("ns1.dyna-ns.net", cf)]))
    assert [d.service for d in dynadot.dependencies if d.category is Category.DNS] == ["Dynadot"]


def test_a_redirect_to_another_domain_is_said():
    facts = make_facts(final_url="https://www.vtb.ru/personal/")
    note = next(n for n in analyze(facts).notes if "перенаправляет" in n)
    assert "vtb.ru" in note and facts.domain in note
    same = make_facts(final_url=f"https://www.{make_facts().domain}/ru/")
    assert not any("перенаправляет" in n for n in analyze(same).notes)


def test_an_unlisted_ru_registrar_handle_is_russian():
    def registrar(name):
        deps = analyze(make_facts(registrar=name)).dependencies
        return next(d for d in deps if d.category is Category.REGISTRAR)

    assert registrar("MASTERHOST-RU").country == "RU"
    assert registrar("FLEXBE-RU").country == "RU"
    assert registrar("Register SPA").country is None  # unknown stays unknown
