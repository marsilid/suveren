"""Cases where a check used to say something untrue about a real site with confidence
(the review of 2026-11-11): each test is the page, the DNS or the network that fooled it."""

import asyncio
import ssl
from datetime import UTC, datetime

import httpx
import pytest

import suveren.collect as collect_module
import suveren.websec as websec
from suveren import services as db
from suveren.blocklist import DOMAINS, IP_LISTS, domain_candidates, run_blocklist, shared_parents
from suveren.checks import Status
from suveren.collect import Collector, interception_note, local_interceptor
from suveren.compliance import ComplianceInput, PolicyInfo, evaluate, has_cookie_notice
from suveren.dnszone import DnssecResult, dnssec_check
from suveren.models import Category, Dependency
from suveren.page import page_code, parse_page
from suveren.websec import TlsInfo, tls_check

METRIKA = Dependency(Category.ANALYTICS, "Яндекс Метрика", "RU", "mc.yandex.ru")


def by_title(checks, title):
    return next(c for c in checks if c.title == title)


# --- SUV-PD-005: what is not a cookie notice ----------------------------------------------


@pytest.mark.parametrize(
    "html",
    [
        # A counter reads document.cookie; the page says "мы используем" about its goods.
        "<script>function id(){return document.cookie}</script><p>Мы используем только "
        "качественные материалы.</p>",
        # accept-charset of a form next to a script with "cookie" in it.
        '<form accept-charset="utf-8"></form><script>var c=document.cookie.split(";")</script>',
        # A footer link to a document is not a banner.
        '<footer><a href="/cookie-policy/">Политика использования файлов cookie</a> '
        '<a href="/terms">Пользовательское соглашение</a></footer>',
        "<p>Рецепт печенья (cookie) с шоколадом</p>",
    ],
)
def test_code_and_document_links_are_not_a_cookie_notice(html):
    assert not has_cookie_notice(html)


@pytest.mark.parametrize(
    "html",
    [
        '<div class="cookie-banner">Мы используем cookies</div>',
        "<p>Продолжая работу с сайтом, вы соглашаетесь на cookie</p>",
        "<div>Сайт использует файлы куки. <button>Принять</button></div>",
        "<div>This site uses cookies <button>Accept</button></div>",
        # The banner's text sits in the script that shows it.
        "<script>showBar('Мы используем файлы cookie, чтобы сайт работал лучше');</script>",
        '<script src="https://consent.cookiebot.com/uc.js"></script>',
    ],
)
def test_a_real_cookie_notice_is_still_found(html):
    assert has_cookie_notice(html)


def test_missing_cookie_notice_says_what_plain_html_cannot_see():
    def notice(rendered):
        data = ComplianceInput(
            final_url="https://example.ru/",
            page=parse_page("<p>Привет</p>"),
            deps=[METRIKA],
            rendered=rendered,
        )
        return by_title(evaluate(data, "<p>Привет</p>"), "Уведомление о cookies")

    plain, seen = notice(False), notice(True)
    assert plain.status is Status.WARN and "--browser" in plain.details
    assert seen.status is Status.WARN and "--browser" not in seen.details


# --- SUV-PD-011: a policy that was not read ------------------------------------------------


def test_unread_policy_is_not_compared_with_the_site():
    # The policy page answered with the site's shell: its text is drawn by a script.
    shell = "<script src='/app.js'></script>Главная Каталог Контакты Политика © 2026"
    policy = PolicyInfo(
        url="https://example.ru/privacy", text=parse_page(shell).text, fetched=True, scripted=True
    )
    data = ComplianceInput(
        final_url="https://example.ru/", page=parse_page(""), deps=[METRIKA], policy=policy
    )
    checks = evaluate(data, "")
    assert by_title(checks, "Содержание политики").status is Status.UNKNOWN
    reality = by_title(checks, "Политика и реальность")
    assert reality.status is Status.UNKNOWN and "прочитать не удалось" in reality.details


# --- services found by a mention -------------------------------------------------------------


def found(html):
    return {s.name for s, _ in db.scan_page(page_code(html, links=False))}


def test_event_calls_left_without_the_pixel_are_not_meta_pixel():
    assert not found("<script>if(window.fbq){fbq('track','Lead');}</script>")
    assert not found("<script>function goal(){try{fbq('track', 'Purchase')}catch(e){}}</script>")
    assert found("<script>fbq('init', '1234567890');fbq('track','PageView');</script>") == {
        "Meta Pixel (Facebook)"
    }
    assert found('<script src="https://connect.facebook.net/en_US/fbevents.js"></script>') == {
        "Meta Pixel (Facebook)"
    }


def test_json_data_of_a_page_loads_nothing():
    ld = (
        '<script type="application/ld+json">{"@type":"Organization","sameAs":'
        '["https://www.youtube.com/embed/abc123"]}</script>'
    )
    assert not found(ld)
    # Next.js keeps the article's text as JSON: an article about counters is not a counter.
    article = (
        '<script id="__NEXT_DATA__" type="application/json">{"props":{"text":"Вставьте код '
        'https://www.googletagmanager.com/gtm.js и mc.yandex.ru/metrika"}}</script>'
    )
    assert not found(article)
    # A script that is code still counts, and so does the tag of a data script itself.
    assert found('<script>load("https://www.googletagmanager.com/gtm.js?id=GTM-1")</script>')
    assert "application/ld+json" in page_code(ld, links=False)
    # Sign-in routes are looked for in everything, data included (links=True).
    assert "youtube.com/embed/abc123" in page_code(ld)


# --- SUV-BLK-001/003: a shared hosting suffix in the register -------------------------------


def test_candidates_stop_at_the_registrable_domain():
    assert domain_candidates("a.b.example.ru") == ["a.b.example.ru", "b.example.ru", "example.ru"]
    assert domain_candidates("shop.pages.dev") == ["shop.pages.dev"]
    assert domain_candidates("www.bbc.co.uk") == ["www.bbc.co.uk", "bbc.co.uk"]
    assert shared_parents("www.shop.pages.dev") == ["pages.dev"]
    assert shared_parents("www.example.ru") == []


def test_a_blocked_hosting_suffix_does_not_block_its_sites(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    (tmp_path / f"blocklist-{DOMAINS}").write_text("pages.dev\nbad.pages.dev\n", "utf-8")
    for name in IP_LISTS:
        (tmp_path / f"blocklist-{name}").write_text("", "utf-8")

    def no_network(request):
        raise AssertionError(f"a real request to {request.url}")

    async def go(host, third):
        async with httpx.AsyncClient(transport=httpx.MockTransport(no_network)) as client:
            checks, _ = await run_blocklist(client, host, ["203.0.113.5"], third_party=third)
            return {c.id: c for c in checks}

    site = asyncio.run(go("shop.pages.dev", ["cdn.other.pages.dev", "x.ru"]))
    assert site["SUV-BLK-001"].status is Status.WARN
    assert (
        "общий домен" in site["SUV-BLK-001"].details and "pages.dev" in site["SUV-BLK-001"].details
    )
    assert site["SUV-BLK-003"].status is Status.OK  # someone else's site on the same hosting
    # A site of that hosting that is itself in the register is blocked, as before.
    assert asyncio.run(go("bad.pages.dev", None))["SUV-BLK-001"].status is Status.FAIL
    assert asyncio.run(go("example.ru", None))["SUV-BLK-001"].status is Status.OK


# --- SUV-WEB-013: a DS digest the check cannot compute --------------------------------------


def test_gost_ds_digest_is_unknown_not_a_broken_chain():
    key = "257 3 23 " + "QUJD" * 16
    gost = dnssec_check(DnssecResult("example.ru", ["12345 23 3 " + "ab" * 32], [key]))
    assert gost.status is Status.UNKNOWN and "ГОСТ" in gost.details
    # A digest we do compute and that does not match is still a broken chain.
    stale = dnssec_check(DnssecResult("example.ru", ["12345 13 2 " + "ab" * 32], [key]))
    assert stale.status is Status.FAIL


# --- SUV-WEB-008: HTTPS re-signed on the checking computer ---------------------------------

AV = "Kaspersky Anti-Virus Personal Root Certificate"


@pytest.fixture
def no_cache(monkeypatch):
    monkeypatch.setattr(collect_module, "_interceptors", {})


def fake_peers(monkeypatch, issuers: dict[str, str], trusted: set[str]):
    """Hosts and who issued their certificates; the chain verifies only for ``trusted``."""
    asked = []

    async def peer_issuer(host, timeout, *, verify):
        asked.append((host, verify))
        if host not in issuers:
            raise OSError("no route")
        if verify and host not in trusted:
            raise ssl.SSLCertVerificationError("unable to get local issuer certificate")
        return issuers[host]

    monkeypatch.setattr(collect_module, "peer_issuer", peer_issuer)
    return asked


def test_interceptor_is_named_when_the_control_site_fails_too(monkeypatch, no_cache):
    asked = fake_peers(monkeypatch, {"ya.ru": AV, "example.ru": AV}, trusted=set())
    c = Collector(None, None, 1.0)  # type: ignore[arg-type]
    assert asyncio.run(c.tls_issuer("example.ru")) == (None, None)
    assert c.tls_intercepted == AV
    assert AV in interception_note(AV)
    # The control site is asked once per run.
    assert asyncio.run(local_interceptor(1.0)) == AV
    assert [h for h, _ in asked].count("ya.ru") == 2  # one verifying, one not


def test_untrusted_certificate_of_the_site_itself_is_still_reported(monkeypatch, no_cache):
    fake_peers(
        monkeypatch,
        {"ya.ru": "GlobalSign nv-sa", "example.ru": "The Ministry of Digital Development"},
        trusted={"ya.ru"},
    )
    c = Collector(None, None, 1.0)  # type: ignore[arg-type]
    assert asyncio.run(c.tls_issuer("example.ru")) == ("The Ministry of Digital Development", False)
    assert not c.tls_intercepted


def test_no_answer_from_the_control_site_proves_nothing(monkeypatch, no_cache):
    fake_peers(monkeypatch, {"example.ru": "Some CA"}, trusted=set())
    c = Collector(None, None, 1.0)  # type: ignore[arg-type]
    assert asyncio.run(c.tls_issuer("example.ru")) == ("Some CA", False)
    assert collect_module._interceptors == {}  # asked again next time


def test_tls_check_of_an_intercepted_connection_is_not_checked():
    exp = datetime(2027, 1, 1, tzinfo=UTC)
    seen = TlsInfo(
        "example.ru",
        "TLSv1.2",
        exp,
        {"TLS 1.0": True},
        "self-signed certificate in certificate chain",
        f"CN={AV}",
        intercepted=AV,
    )
    w = websec.WebFacts("example.ru", True, {}, [], [], [], seen)
    check = tls_check(w)
    assert check is not None and check.status is Status.UNKNOWN
    assert AV in check.details and "TLS 1.0" not in check.details
    # Without the mark the same data is the old verdict about the site.
    seen.intercepted = ""
    assert tls_check(w).status is Status.FAIL


def test_probe_tls_asks_the_control_site_before_blaming_the_certificate(monkeypatch, no_cache):
    der = b"certificate"

    async def handshake(host, ctx, timeout, chain=None):
        if ctx.verify_mode is ssl.CERT_NONE:
            return "TLSv1.3", der
        error = ssl.SSLCertVerificationError("self-signed certificate in certificate chain")
        error.verify_message = "self-signed certificate in certificate chain"
        raise error

    class Cert:
        not_valid_after_utc = not_valid_before_utc = datetime(2027, 1, 1, tzinfo=UTC)
        issuer = type("N", (), {"rfc4514_string": lambda self: f"CN={AV}"})()

    async def interceptor(timeout):
        return AV

    monkeypatch.setattr(websec, "_handshake", handshake)
    monkeypatch.setattr(websec.x509, "load_der_x509_certificate", lambda d: Cert())
    monkeypatch.setattr(websec, "issuer_from_der", lambda d: AV)
    monkeypatch.setattr(websec, "local_interceptor", interceptor)
    info = asyncio.run(websec.probe_tls("example.ru", 1.0))
    assert info.intercepted == AV and not info.legacy  # old protocols were not even tried
