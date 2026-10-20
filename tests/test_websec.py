import asyncio
import ssl
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from suveren import websec
from suveren.checks import Status
from suveren.collect import bot_wall
from suveren.websec import (
    TlsInfo,
    WebFacts,
    csp_check,
    csp_weaknesses,
    evaluate,
    find_abandoned,
    headers_check,
    hsts_check,
    is_third_party,
    legacy_accepted,
    page_resources,
    parse_set_cookie,
    sri_check,
    supply_chain,
    tls_check,
)

NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)


def web(html="", headers=None, cookies=(), tls=None, https=True, **kwargs) -> WebFacts:
    resources, meta = page_resources(html, "https://example.ru/")
    w = WebFacts("example.ru", https, headers or {}, resources, meta, list(cookies), tls, now=NOW)
    for key, value in kwargs.items():
        setattr(w, key, value)
    return w


# --- page parsing ---------------------------------------------------------------------


def test_page_resources():
    html = """
    <script src="/static/app.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"
            integrity="sha384-abc" crossorigin="anonymous"></script>
    <link rel="stylesheet" href="//fonts.example.com/a.css">
    <link rel="preload" href="https://other.com/x.js">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
    """
    found, meta = page_resources(html, "https://example.ru/shop/")
    assert [(r.url, r.kind, r.integrity) for r in found] == [
        ("https://example.ru/static/app.js", "script", False),
        ("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js", "script", True),
        ("https://fonts.example.com/a.css", "style", False),
    ]
    assert meta == ["default-src 'self'"]


def test_third_party():
    assert not is_third_party("example.ru", "example.ru")
    assert not is_third_party("cdn.example.ru", "example.ru")
    assert is_third_party("example.ru.evil.com", "example.ru")
    assert is_third_party("mc.yandex.ru", "example.ru")


# --- scripts --------------------------------------------------------------------------


def test_compromised_cdn_is_a_failure():
    check = supply_chain(web('<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>'))
    assert check.status is Status.FAIL
    assert "polyfill.io" in check.details


def test_abandoned_script_domains():
    html = '<script src="https://widget.oldagency.com/w.js"></script>'
    assert supply_chain(web(html, abandoned={"oldagency.com": True})).status is Status.FAIL
    assert supply_chain(web(html, abandoned={"oldagency.com": False})).status is Status.WARN
    assert supply_chain(web(html)).status is Status.OK


def test_sri_only_for_library_cdns():
    analytics = '<script src="https://mc.yandex.ru/metrika/tag.js"></script>'
    assert sri_check(web(analytics)) is None  # can't have SRI, not asked for
    bare = '<script src="https://cdn.jsdelivr.net/npm/vue@3.4.0/dist/vue.global.js"></script>'
    check = sri_check(web(bare))
    assert check.status is Status.WARN and "vue.global.js" in check.details
    signed = bare.replace("></script>", ' integrity="sha384-x"></script>')
    assert sri_check(web(signed)).status is Status.OK


def test_find_abandoned_asks_the_registry():
    class Resolver:
        async def exists(self, domain):
            return domain not in {"oldagency.com", "takenquiet.com"}

    def handler(request):
        return httpx.Response(404 if "oldagency" in request.url.path else 200)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            hosts = ["w.oldagency.com", "x.takenquiet.com", "cdn.example.ru", "mc.yandex.ru"]
            return await find_abandoned(Resolver(), c, hosts, "example.ru")

    # takenquiet.com is registered but not delegated: nobody else can buy it.
    assert asyncio.run(go()) == {"oldagency.com": True}


# --- CSP and headers ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("policy", "problem"),
    [
        ("script-src 'self' 'unsafe-inline'; object-src 'none'", "'unsafe-inline'"),
        ("script-src 'self' 'unsafe-eval'; object-src 'none'", "'unsafe-eval'"),
        ("default-src https:; object-src 'none'", "https:"),
        ("img-src 'self'", "нет script-src"),
        ("script-src 'self'", "object-src"),
    ],
)
def test_csp_weaknesses(policy, problem):
    assert any(problem in p for p in csp_weaknesses(policy))


def test_strong_csp_has_no_weaknesses():
    nonce = "script-src 'nonce-r4nd' 'unsafe-inline' 'strict-dynamic' https:; object-src 'none'"
    assert csp_weaknesses(nonce) == []
    assert csp_weaknesses("default-src 'self'; object-src 'none'") == []


def test_csp_check():
    assert csp_check(web()).status is Status.WARN
    only_report = csp_check(
        web(headers={"content-security-policy-report-only": "default-src 'self'"})
    )
    assert "Report-Only" in only_report.details
    good = {"content-security-policy": "default-src 'self'; object-src 'none'"}
    assert csp_check(web(headers=good)).status is Status.OK
    policy = "default-src 'self'; object-src 'none'"
    meta = f'<meta http-equiv="Content-Security-Policy" content="{policy}">'
    assert csp_check(web(meta)).status is Status.OK


def test_hsts():
    assert hsts_check(web(https=False)) is None
    assert hsts_check(web()).status is Status.WARN
    short = hsts_check(web(headers={"strict-transport-security": "max-age=86400"}))
    assert short.status is Status.WARN and "1 дн." in short.details
    year = {"strict-transport-security": "max-age=31536000; includeSubDomains"}
    assert hsts_check(web(headers=year)).status is Status.OK


def test_protective_headers():
    assert headers_check(web()).status is Status.WARN
    via_csp = {
        "content-security-policy": "frame-ancestors 'self'",
        "x-content-type-options": "nosniff",
    }
    assert headers_check(web(headers=via_csp)).status is Status.OK


# --- cookies --------------------------------------------------------------------------


def test_parse_set_cookie():
    c = parse_set_cookie("PHPSESSID=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert (c.name, c.secure, c.http_only, c.same_site) == ("PHPSESSID", True, True, "lax")
    assert parse_set_cookie("garbage") is None


def test_cookie_flags():
    weak = parse_set_cookie("sessionid=abc; Path=/")
    tracker = parse_set_cookie("_ym_uid=123; Path=/")
    check = websec.cookies_check(web(cookies=[weak, tracker]))
    assert check.status is Status.WARN
    assert "sessionid" in check.details and "_ym_uid" not in check.details
    assert websec.cookies_check(web()) is None


# --- TLS ------------------------------------------------------------------------------


def test_tls_expiry_and_protocols():
    soon = TlsInfo(
        "example.ru", "TLSv1.3", NOW + timedelta(days=5), {"TLS 1.0": False, "TLS 1.1": False}
    )
    check = tls_check(web(tls=soon))
    assert check.status is Status.FAIL
    assert "Сервер example.ru, соединение TLS 1.3" in check.details
    month = TlsInfo(
        "example.ru", "TLSv1.3", NOW + timedelta(days=20), {"TLS 1.0": False, "TLS 1.1": False}
    )
    assert tls_check(web(tls=month)).status is Status.WARN
    old = TlsInfo(
        "example.ru", "TLSv1.2", NOW + timedelta(days=200), {"TLS 1.0": False, "TLS 1.1": True}
    )
    check = tls_check(web(tls=old))
    assert check.status is Status.WARN and "TLS 1.1" in check.details
    unknown = TlsInfo(
        "example.ru", "TLSv1.3", NOW + timedelta(days=200), {"TLS 1.0": None, "TLS 1.1": None}
    )
    check = tls_check(web(tls=unknown))
    assert check.status is Status.OK and "проверить не удалось" in check.details


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            ssl.SSLError(1, "[SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version"),
            False,
        ),
        (ssl.SSLError(1, "[SSL: NO_PROTOCOLS_AVAILABLE] no protocols available"), None),
        (ConnectionResetError(), False),
        (TimeoutError(), None),
    ],
)
def test_legacy_handshake_outcomes(monkeypatch, error, expected):
    async def fail(host, ctx, timeout):
        raise error

    monkeypatch.setattr(websec, "_handshake", fail)
    assert asyncio.run(legacy_accepted("example.ru", ssl.TLSVersion.TLSv1_2, 5)) is expected


# --- bot walls ------------------------------------------------------------------------


def test_bot_wall_hides_headers_but_not_tls():
    tls = TlsInfo(
        "example.ru", "TLSv1.3", NOW + timedelta(days=200), {"TLS 1.0": False, "TLS 1.1": False}
    )
    checks = evaluate(web(tls=tls, page_problem="заглушка", http_problem="заглушка"))
    assert [c.status for c in checks] == [Status.UNKNOWN, Status.UNKNOWN, Status.OK]
    assert checks[-1].title.startswith("TLS")


def test_bot_wall_detection():
    assert bot_wall(403, "<html>Forbidden</html>")
    stub = "<html><script>const e={serviceName:'waf',code:'user_blocked'}</script></html>"
    assert bot_wall(200, stub)
    shell = '<html><body><div id="root"></div><script src="/app.js"></script></body></html>'
    assert bot_wall(200, shell) is None  # an app shell: its headers are real


def test_redirect_to_another_domain_hides_its_headers(monkeypatch):
    from suveren.collect import Facts
    from suveren.websec import run_web_checks

    async def no_tls(host, timeout):
        return TlsInfo(host)

    class Resolver:
        async def exists(self, domain):
            return True

    monkeypatch.setattr(websec, "probe_tls", no_tls)
    facts = Facts(host="example.ru", domain="example.ru")
    facts.final_url = "https://partner-site.com/landing"
    facts.html = "<html><body>" + "текст " * 400 + "</body></html>"
    facts.headers = {"strict-transport-security": "max-age=31536000"}

    async def go():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200))
        ) as c:
            return await run_web_checks(facts, Resolver(), c, 5)

    checks, _ = asyncio.run(go())
    headers = next(c for c in checks if c.title.startswith("Заголовки безопасности"))
    assert headers.status is Status.UNKNOWN
    assert "partner-site.com" in headers.details


@pytest.mark.parametrize(
    ("name", "session"),
    [
        ("PHPSESSID", True),
        ("JSESSIONID", True),
        ("connect.sid", True),
        ("sid", True),
        ("auth_token", True),
        ("refresh_token", True),
        ("XSRF-TOKEN", False),
        ("csrftoken", False),
        ("ngtoken", False),
        ("_ym_uid", False),
        ("consider", False),
    ],
)
def test_session_cookie_names(name, session):
    assert parse_set_cookie(f"{name}=1; Path=/").session_like is session


def test_plural():
    from suveren.websec import plural

    forms = ("домен", "домена", "доменов")
    assert [plural(n, *forms) for n in (1, 2, 5, 11, 12, 21, 22, 25, 111)] == [
        "домен",
        "домена",
        "доменов",
        "доменов",
        "доменов",
        "домен",
        "домена",
        "доменов",
        "доменов",
    ]
    one = web('<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>')
    assert "с 1 стороннего адреса (1 домен)" in websec.scripts_inventory(one).details


def test_advice_names_only_what_is_missing():
    only_report = csp_check(
        web(headers={"content-security-policy-report-only": "default-src 'self'"})
    )
    assert "Режим наблюдения уже включён" in only_report.recommendation
    assert "Начните с" in csp_check(web()).recommendation

    frames_ok = headers_check(web(headers={"x-frame-options": "SAMEORIGIN"}))
    assert frames_ok.recommendation == "Добавьте заголовок X-Content-Type-Options: nosniff."
    both = headers_check(web())
    assert both.recommendation.startswith("Добавьте заголовки X-Frame-Options")


def test_browser_headers_stand_in_for_a_bot_wall():
    import asyncio

    import httpx

    from suveren.collect import Facts
    from suveren.websec import run_web_checks

    facts = Facts(
        host="example.ru",
        domain="example.ru",
        final_url="http://example.ru/",  # http: no TLS probe in the test
        page_status=200,
        html="<html><body>" + "<p>текст</p>" * 200 + "</body></html>",
        headers={"server": "ddos-guard"},
        http_problem="сайт показал страницу защиты от ботов",
        browser_headers={
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "set-cookie": "sid=1; Secure; HttpOnly; SameSite=Lax\nlang=ru",
        },
        rendered=True,
    )

    async def go():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(404))
        ) as c:
            return await run_web_checks(facts, None, c, 5)

    checks, _ = asyncio.run(go())
    by_id = {c.id: c for c in checks}
    assert by_id["SUV-WEB-006"].status.value == "ok"  # protective headers seen
    assert by_id["SUV-WEB-004"].status.value != "unknown"  # CSP judged, not "not checked"


def test_hsts_under_a_day_is_not_zero_days():
    hour = hsts_check(web(headers={"strict-transport-security": "max-age=3600"}))
    assert "1 ч." in hour.details and "0 дн." not in hour.details
    assert "300 с" in hsts_check(web(headers={"strict-transport-security": "max-age=300"})).details
    off = hsts_check(web(headers={"strict-transport-security": "max-age=0"}))
    assert off.status is Status.WARN and "выключает HSTS" in off.details


def test_script_inventory_warns_only_when_many_domains_can_run_code():
    few = web(
        "".join(f'<script src="https://cdn{i}.vendor{i}.ru/a.js"></script>' for i in range(3))
    )
    check = websec.scripts_inventory(few)
    # A short list is information, not an alarm: no "может выполнить любой код" in "в порядке".
    assert check.status is Status.OK and "любой код" not in check.details
    many = web("".join(f'<script src="https://cdn.vendor{i}.ru/a.js"></script>' for i in range(10)))
    check = websec.scripts_inventory(many)
    assert check.status is Status.WARN and "любой код" in check.details and check.recommendation
