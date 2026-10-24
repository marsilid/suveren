import pytest

from suveren import services as db
from suveren.models import Category, Severity
from suveren.utils import host_matches


@pytest.mark.parametrize(
    ("host", "pattern", "expected"),
    [
        ("ns1.cloudflare.com", "cloudflare.com", True),
        ("cloudflare.com", "cloudflare.com", True),
        ("notcloudflare.com", "cloudflare.com", False),
        ("ns-12.awsdns-34.com", "*awsdns-*", True),
        ("ns1.yandexcloud.net", "yandex.net", False),
        ("NS1.Yandex.NET.", "yandex.net", True),
    ],
)
def test_host_matches(host, pattern, expected):
    assert host_matches(host, pattern) is expected


@pytest.mark.parametrize(
    ("host", "name"),
    [
        ("lana.ns.cloudflare.com", "Cloudflare"),
        ("ns-1536.awsdns-00.co.uk", "Amazon Web Services"),
        ("ns1.yandexcloud.net", "Yandex Cloud"),
        ("dns1.yandex.net", "Яндекс 360"),
        ("ns3-l2.nic.ru", "RU-CENTER"),
        ("ns1.selectel.org", "Selectel"),
        ("ns1.dns-parking.com", "Hostinger"),
    ],
)
def test_ns_detection(host, name):
    service = db.by_ns(host)
    assert service is not None
    assert service.name == name


@pytest.mark.parametrize(
    ("host", "name", "foreign"),
    [
        ("aspmx.l.google.com", "Google Workspace", True),
        ("example-ru.mail.protection.outlook.com", "Microsoft 365", True),
        ("mx.yandex.net", "Яндекс 360", False),
        ("emx.mail.ru", "VK WorkSpace (Mail.ru)", False),
        ("mx1.beget.com", "Beget", False),
    ],
)
def test_mx_detection(host, name, foreign):
    service = db.by_mx(host)
    assert service is not None
    assert service.name == name
    assert service.foreign is foreign


def test_network_by_asn_beats_name():
    assert db.by_network(13335, "SOMETHING ELSE").name == "Cloudflare"


def test_network_by_name_fallback():
    service = db.by_network(None, "HETZNER-AS")
    assert service is not None
    assert service.name == "Hetzner"


def test_network_unknown():
    assert db.by_network(64512, "PRIVATE NETWORK") is None


@pytest.mark.parametrize(
    ("registrar", "name", "country"),
    [
        ("REGRU-RU", "REG.RU", "RU"),
        ("RU-CENTER-RU", "RU-CENTER", "RU"),
        ("NameCheap, Inc.", "Namecheap", "US"),
        ("GoDaddy.com, LLC", "GoDaddy", "US"),
    ],
)
def test_registrar_detection(registrar, name, country):
    service = db.by_registrar(registrar)
    assert service is not None
    assert (service.name, service.country) == (name, country)


def test_issuer_severity():
    le = db.by_issuer("Let's Encrypt")
    sectigo = db.by_issuer("Sectigo Limited")
    assert le is not None and le.severity is None  # category default (low)
    assert sectigo is not None and sectigo.severity == Severity.MEDIUM


def test_zone_info():
    assert db.zone_info("example.ru")[1] == "RU"
    assert db.zone_info("xn--d1acufc.xn--p1ai")[1] == "RU"  # домен.рф
    assert db.zone_info("example.com") == (".com — Verisign", "US")
    assert db.zone_info("example.de")[1] == "DE"
    assert db.zone_info("example.co.uk")[1] == "GB"
    assert db.zone_info("example.museum")[1] is None


def page_names(html):
    return {s.name for s, _ in db.scan_page(html)}


def test_page_detects_common_scripts():
    html = """
    <script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">
    <script src="https://www.google.com/recaptcha/api.js"></script>
    <script src="https://mc.yandex.ru/metrika/tag.js"></script>
    """
    assert page_names(html) == {
        "Google Analytics / Tag Manager",
        "Google Fonts",
        "Google reCAPTCHA",
        "Яндекс Метрика",
    }


def test_plain_links_are_not_dependencies():
    html = """
    <a href="https://www.youtube.com/@channel">YouTube</a>
    <a href="https://www.google.com/maps/place/Moscow">Карта</a>
    <a href="https://facebook.com/company">Facebook</a>
    """
    assert page_names(html) == set()


def test_youtube_embed_is_medium():
    found = db.scan_page('<iframe src="https://www.youtube.com/embed/abc"></iframe>')
    assert len(found) == 1
    service, matched = found[0]
    assert service.category is Category.VIDEO
    assert service.severity == Severity.MEDIUM
    assert "youtube.com/embed/" in matched


def test_meta_pixel_has_note():
    found = db.scan_page("<script>fbq('init', '123');</script>")
    assert found[0][0].name == "Meta Pixel (Facebook)"
    assert "экстремист" in found[0][0].note


def test_every_page_service_has_category_and_valid_country():
    for service in db.ALL_SERVICES:
        assert len(service.country) == 2 and service.country.isupper(), service.name
        if service.page:
            assert service.category is not None, service.name


def test_service_names_are_unique():
    names = [s.name for s in db.ALL_SERVICES]
    assert len(names) == len(set(names))


def test_unknown_domains_skip_own_and_known():
    from suveren.unknown import resource_urls, unknown_domains

    html = (
        '<script src="/app.js"></script>'
        '<script src="https://cdn.example.ru/x.js"></script>'
        '<script src="https://mc.yandex.ru/metrika/tag.js"></script>'
        '<img src="https://pixel.some-adtech.io/p.gif">'
        '<a href="https://not-a-resource.com/">ссылка</a>'
    )
    urls = resource_urls(html, "https://example.ru/")
    assert "https://example.ru/app.js" in urls
    assert unknown_domains(urls, "example.ru") == {"some-adtech.io"}


def test_unknown_record_and_load(tmp_path, monkeypatch):
    from suveren import unknown

    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    unknown.record({"a.io", "b.io"}, "site1.ru")
    unknown.record({"a.io"}, "site2.ru")
    unknown.record({"a.io"}, "site2.ru")  # the same site twice counts once
    data = unknown.load()
    assert data["a.io"]["count"] == 2
    assert data["a.io"]["sites"] == ["site1.ru", "site2.ru"]
    unknown.clear()
    assert unknown.load() == {}


def test_page_patterns_are_fast_on_long_tokens():
    r"""A pattern that starts with an unbounded character class (like [\w.-]*x) is
    quadratic on minified JS and once hung a whole batch: keep every pattern linear."""
    import time

    html = "<script>var " + "a" * 50_000 + "=1;" + "b." * 20_000 + "</script>"
    started = time.perf_counter()
    db.scan_page(html)
    assert time.perf_counter() - started < 1.0


def test_own_domain_is_not_a_dependency():
    html = (
        '<a href="https://www.beeline.ru/tariffs">Тарифы</a><img src="https://ad.beeline.ru/p.gif">'
    )
    assert "Билайн (реклама)" not in {
        s.name for s, _ in db.scan_page(html, own_domain="beeline.ru")
    }
    assert "Билайн (реклама)" in {s.name for s, _ in db.scan_page(html, own_domain="example.ru")}


def test_mintsifry_issuer_recognised_by_ministry_name():
    service = db.by_issuer("The Ministry of Digital Development and Communications")
    assert service is not None and service.country == "RU"


def code_names(html):
    from suveren.page import page_code

    return {s.name for s, _ in db.scan_page(page_code(html))}


def test_mention_in_text_is_not_a_dependency():
    html = "<article><p>Подключите googletagmanager.com и fonts.googleapis.com</p></article>"
    assert code_names(html) == set()


def test_commented_out_tag_is_not_a_dependency():
    html = '<!-- <script src="https://www.googletagmanager.com/gtag/js"></script> -->'
    assert code_names(html) == set()


def test_tags_attributes_and_inline_scripts_are_checked():
    html = """
    <script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>
    <img data-src="https://fonts.googleapis.com/css2?family=Inter">
    <script>fbq('init', '123');</script>
    """
    assert code_names(html) == {
        "Google Analytics / Tag Manager",
        "Google Fonts",
        "Meta Pixel (Facebook)",
    }


def test_data_file_entries_are_valid():
    """data/services.json is edited by hand: every entry must load and make sense."""
    import json
    import re
    from importlib.resources import files

    from suveren.models import Category, Severity

    raw = json.loads(files("suveren").joinpath("data/services.json").read_text("utf-8"))
    allowed = {
        "name", "country", "category", "ns", "mx", "asn", "as_names", "cdn", "registrar",
        "issuer", "page", "severity", "note", "alternative",
    }  # fmt: skip
    names = set()
    for group in ("infra", "tls", "page"):
        for d in raw[group]:
            assert set(d) <= allowed, (d["name"], set(d) - allowed)
            assert re.fullmatch(r"[A-Z]{2}", d["country"]), d["name"]
            assert (group, d["name"]) not in names, f"duplicate {d['name']}"
            names.add((group, d["name"]))
            if "category" in d:
                Category(d["category"])
            if "severity" in d:
                Severity[d["severity"].upper()]
            for pattern in d.get("page", ()):
                re.compile(pattern)
            if group == "page":
                assert d.get("page") and "category" in d, d["name"]
            if group == "tls":
                assert d.get("issuer"), d["name"]


def test_a_plain_link_is_not_a_dependency_a_form_link_is():
    # "Мы на YouTube" in the footer counted as a YouTube player, a news link as Rambler ads.
    from suveren.page import page_code

    html = (
        '<a href="https://www.youtube.com/@shop">YouTube</a>'
        '<a href="https://news.rambler.ru/a">Новость</a>'
        '<a href="https://docs.google.com/forms/d/1/viewform">Анкета</a>'
    )
    names = {s.name for s, _ in db.scan_page(page_code(html, links=False))}
    assert "YouTube" not in names and not any("Rambler" in n for n in names)
    assert any("Google" in n for n in names)  # visitors' answers go to Google
