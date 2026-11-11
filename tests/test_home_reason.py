"""Why the home page did not load, said plainly, and www. tried (domix32, 2.2.3).

The 152-FZ section said only "the home page did not load, nothing to check", and it was
not clear whether the tool or the site was broken. A site living only on www. was
reported as not opening at all."""

import asyncio
import ssl

import httpx
import pytest

import suveren.collect as collect_module
from suveren import net
from suveren.collect import Collector, Facts, home_reason
from suveren.errors import ModuleError

PAGE = "<html><body><h1>Магазин</h1>" + "<p>текст</p>" * 50 + "</body></html>"


class Resolver:
    def __init__(self, records):
        self.records = records

    async def resolve(self, name, rtype):
        return self.records.get((name, rtype), [])


def _homepage(handler, records):
    def make_client(timeout, *, verify=True):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)

    async def go():
        collect_module.make_client = make_client
        async with make_client(5) as client:
            c = Collector(Resolver(records), client, 5)
            try:
                return await c.homepage("shop.ru"), c.www_fallback
            finally:
                await c.aclose()

    return asyncio.run(go())


@pytest.fixture(autouse=True)
def _restore_make_client(monkeypatch):
    monkeypatch.setattr(collect_module, "make_client", collect_module.make_client)


def test_a_site_only_on_www_is_found_and_said_so():
    def handler(request):
        if request.url.host == "shop.ru":
            raise httpx.ConnectError("Connection refused", request=request)
        return httpx.Response(200, text=PAGE, headers={"Content-Type": "text/html"})

    (url, status, html, _), fallback = _homepage(handler, {("www.shop.ru", "A"): ["192.0.2.1"]})
    assert url == "https://www.shop.ru/" and status == 200 and html == PAGE
    assert fallback == (
        "shop.ru",
        home_reason(ModuleError("сайт не открылся (нет связи с сервером)")),
    )


def test_no_www_in_dns_keeps_the_first_error():
    tried = []

    def handler(request):
        tried.append(request.url.host)
        raise httpx.ConnectError("Connection refused", request=request)

    with pytest.raises(ModuleError, match="нет связи с сервером"):
        _homepage(handler, {})
    assert set(tried) == {"shop.ru"}  # no second round of attempts for a name with no address


@pytest.mark.parametrize(
    ("exc", "says"),
    [
        (httpx.ConnectTimeout("t"), "сайт не ответил вовремя"),
        (httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]"), "ошибка TLS"),
        (httpx.ConnectError("getaddrinfo failed"), "адрес сайта не найден в DNS"),
        (httpx.ConnectError("Connection refused"), "сайт недоступен или закрыт для вашей сети"),
        (ModuleError("сайт не открылся (сервер не ответил вовремя)"), "не ответил вовремя"),
    ],
)
def test_each_reason_in_plain_words(exc, says, monkeypatch):
    for name in net.PROXY_VARS:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    text = home_reason(exc)
    assert says in text and "прокси" not in text and not text.startswith("сайт не открылся")


def test_a_proxy_in_the_environment_is_named(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp:3128")
    assert "прокси из окружения" in home_reason(httpx.ConnectError("Connection refused"))


def test_no_internet_is_this_computer_not_the_site():
    net.note_unreachable(OSError(101, "Network is unreachable"))
    assert "нет выхода в интернет с этого компьютера" in home_reason(
        httpx.ConnectError("Network is unreachable")
    )


def test_the_reason_reaches_the_152fz_section_and_json():
    from suveren.report import Report
    from suveren.scan import _compliance

    facts = Facts(host="shop.ru", domain="shop.ru")
    facts.home_error = home_reason(httpx.ReadTimeout("t"))
    assert facts.page_problem == (
        "главная страница не открылась, причина: сайт не ответил вовремя, возможно, он перегружен "
        "или закрыт для вашей сети"
    )
    assert facts.page_unseen == facts.page_problem
    assert facts.to_dict()["home_error"] == facts.home_error
    checks = asyncio.run(_compliance(None, facts, Report(target="shop.ru")))
    assert checks[0].details == f"Не проверено: {facts.page_problem}."


def test_tls_error_class_is_recognised():
    assert "ошибка TLS" in home_reason(ssl.SSLError("bad handshake"))
