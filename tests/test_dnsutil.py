import asyncio

import dns.nameserver
import pytest

from suveren import dnsutil
from suveren.dnsutil import (
    NOTE_DOH,
    NOTE_DOT,
    DnsLookupError,
    DohResolver,
    DotResolver,
    SystemResolver,
    create_resolver,
    parse_doh_answer,
)


@pytest.fixture(autouse=True)
def fresh_health(monkeypatch):
    """Health answers are cached per process; every test starts from scratch."""
    monkeypatch.setattr(dnsutil, "_system_healthy", None)
    monkeypatch.setattr(dnsutil, "_dot_healthy", None)


def _health(monkeypatch, *, system: bool, dot: bool) -> None:
    async def healthy(self) -> bool:
        return dot if isinstance(self, DotResolver) else system

    monkeypatch.setattr(SystemResolver, "is_healthy", healthy)


def _pick(mode: str = "auto"):
    return asyncio.run(create_resolver(mode, 5.0, client=None))  # type: ignore[arg-type]


def test_auto_keeps_a_working_system_resolver(monkeypatch):
    _health(monkeypatch, system=True, dot=True)
    resolver, note = _pick()
    assert type(resolver) is SystemResolver
    assert note is None


def test_auto_falls_back_to_yandex_dot(monkeypatch):
    _health(monkeypatch, system=False, dot=True)
    resolver, note = _pick()
    assert isinstance(resolver, DotResolver)
    assert note == NOTE_DOT


def test_auto_uses_foreign_doh_last_and_says_so(monkeypatch):
    _health(monkeypatch, system=False, dot=False)
    resolver, note = _pick()
    assert isinstance(resolver, DohResolver)
    assert note == NOTE_DOH
    assert "--dns ru" in note


def test_ru_mode_never_falls_back_abroad(monkeypatch):
    _health(monkeypatch, system=False, dot=False)
    resolver, note = _pick("ru")
    assert isinstance(resolver, DotResolver)
    assert note is None


def test_dot_resolver_talks_to_yandex_over_tls():
    servers = DotResolver(5.0)._resolver.nameservers
    assert {s.address for s in servers} == {"77.88.8.8", "77.88.8.1"}
    assert all(isinstance(s, dns.nameserver.DoTNameserver) for s in servers)
    assert all(s.hostname == "common.dot.dns.yandex.net" for s in servers)


def test_parse_doh_answer_joins_txt_parts():
    payload = {"Status": 0, "Answer": [{"type": 16, "data": '"v=spf1 " "-all"'}]}
    assert parse_doh_answer(payload, "TXT") == ["v=spf1 -all"]


def test_doh_falls_back_to_the_second_endpoint_and_reads_answers():
    import httpx

    calls = []

    def handler(request):
        calls.append(request.url.host)
        if request.url.host == "dns.google":
            return httpx.Response(503)
        if request.url.params["name"] == "gone.example":
            return httpx.Response(200, json={"Status": 3})
        return httpx.Response(
            200, json={"Status": 0, "Answer": [{"type": 15, "data": "10 mx.yandex.net."}]}
        )

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            r = DohResolver(client)
            return await r.resolve("example.ru", "MX"), await r.exists("gone.example")

    mx, exists = asyncio.run(go())
    assert mx == ["10 mx.yandex.net."] and exists is False
    assert calls[:2] == ["dns.google", "cloudflare-dns.com"]


def test_doh_down_everywhere_is_a_lookup_error_but_not_a_missing_domain():
    import httpx

    async def go():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(503))
        ) as client:
            r = DohResolver(client)
            exists = await r.exists("example.ru")
            with pytest.raises(DnsLookupError):
                await r.resolve("example.ru", "A")
            return exists, await r.is_healthy()

    assert asyncio.run(go()) == (True, False)


def test_system_resolver_maps_dnspython_outcomes():
    import dns.exception
    import dns.resolver

    from suveren.dnsutil import SystemResolver

    class Record:
        def __init__(self, text, strings=()):
            self.text, self.strings = text, strings

        def to_text(self):
            return self.text

    class Fake:
        async def resolve(self, name, rtype):
            if name == "gone.example":
                raise dns.resolver.NXDOMAIN
            if name == "slow.example":
                raise dns.exception.Timeout
            if rtype == "TXT":
                return [Record("", (b"v=spf1 include:_spf.", b"yandex.net ~all"))]
            return [Record("192.0.2.1")]

    r = SystemResolver(2.0)
    r._resolver = Fake()
    assert asyncio.run(r.resolve("example.ru", "A")) == ["192.0.2.1"]
    assert asyncio.run(r.resolve("example.ru", "TXT")) == ["v=spf1 include:_spf.yandex.net ~all"]
    assert asyncio.run(r.resolve("gone.example", "A")) == []
    with pytest.raises(DnsLookupError):
        asyncio.run(r.resolve("slow.example", "A"))
    assert asyncio.run(r.exists("gone.example")) is False
    assert asyncio.run(r.exists("slow.example")) is True  # no proof it is missing
    assert asyncio.run(r.is_healthy()) is True
