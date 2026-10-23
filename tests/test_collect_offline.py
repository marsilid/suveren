"""collect(): the first stage of every scan, run offline end to end.

DNS answers come from a fake resolver (Team Cymru's TXT records included), HTTP from
a mock transport, WHOIS and the TLS issuer from stubs; the rest is the real code.
"""

import asyncio

import httpx
import pytest

import suveren.collect as collect_module
from suveren.collect import Collector, collect
from suveren.errors import TargetNotFoundError

DNS = {
    ("example.com", "NS"): ["ns1.example-dns.net.", "ns2.example-dns.net."],
    ("example.com", "MX"): ["10 mx.yandex.net."],
    ("example.com", "A"): ["192.0.2.10"],
    ("ns1.example-dns.net", "A"): ["198.51.100.1"],
    ("ns2.example-dns.net", "A"): ["198.51.100.2"],
    ("mx.yandex.net", "A"): ["77.88.21.249"],
    ("10.2.0.192.origin.asn.cymru.com", "TXT"): ["49505 | 192.0.2.0/24 | RU | ripencc | 2010"],
    ("1.100.51.198.origin.asn.cymru.com", "TXT"): ["13335 | 198.51.100.0/24 | US | arin | 2010"],
    ("2.100.51.198.origin.asn.cymru.com", "TXT"): ["13335 | 198.51.100.0/24 | US | arin | 2010"],
    ("249.21.88.77.origin.asn.cymru.com", "TXT"): ["13238 | 77.88.0.0/18 | RU | ripencc | 2001"],
    ("AS49505.asn.cymru.com", "TXT"): ["49505 | RU | ripencc | 2009 | SELECTEL, RU"],
    ("AS13335.asn.cymru.com", "TXT"): ["13335 | US | arin | 2010 | CLOUDFLARENET, US"],
    ("AS13238.asn.cymru.com", "TXT"): ["13238 | RU | ripencc | 2002 | YANDEX, RU"],
}
PAGE = "<html><body><h1>Пример</h1></body></html>"
RDAP = {
    "entities": [
        {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "REG.RU LLC"]]]}
    ]
}


class Resolver:
    kind = "fake"

    def __init__(self, records, missing=()):
        self.records, self.missing = records, set(missing)

    async def resolve(self, name, rtype):
        return self.records.get((name, rtype), [])

    async def exists(self, domain):
        return domain not in self.missing


def handler(request: httpx.Request) -> httpx.Response:
    if request.url.host == "rdap.org":
        return httpx.Response(200, json=RDAP)
    if request.url.host == "example.com":
        return httpx.Response(
            200,
            text=PAGE,
            headers=[
                ("Content-Type", "text/html; charset=utf-8"),
                ("Strict-Transport-Security", "max-age=31536000"),
                ("Set-Cookie", "sid=1; Secure; HttpOnly"),
                ("Set-Cookie", "_ym_uid=2; Secure"),
            ],
        )
    return httpx.Response(404)


@pytest.fixture
def offline(monkeypatch):
    def make_client(timeout, *, verify=True):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)

    async def create_resolver(mode, timeout, client):
        return Resolver(DNS, missing={"nothing-here.com", "gone.example.com"}), None

    async def issuer(self, host, *, verify):
        return "Let's Encrypt"

    monkeypatch.setattr(collect_module, "make_client", make_client)
    monkeypatch.setattr(collect_module, "create_resolver", create_resolver)
    monkeypatch.setattr(Collector, "_issuer", issuer)


def test_collect_gathers_every_fact(offline):
    facts = asyncio.run(collect("example.com"))
    assert facts.domain == "example.com" and facts.final_url == "https://example.com/"
    assert facts.html == PAGE and facts.page_status == 200 and facts.page_problem is None
    assert facts.headers["strict-transport-security"] == "max-age=31536000"
    assert facts.set_cookies == ["sid=1; Secure; HttpOnly", "_ym_uid=2; Secure"]
    assert [h.host for h in facts.ns] == ["ns1.example-dns.net", "ns2.example-dns.net"]
    assert facts.ns[0].net.as_name and "CLOUDFLARE" in facts.ns[0].net.as_name
    assert facts.mx[0].host == "mx.yandex.net" and facts.mx[0].net.country == "RU"
    assert facts.web[0].asn == 49505 and "SELECTEL" in facts.web[0].as_name
    assert facts.registrar == "REG.RU LLC"
    assert (facts.tls_issuer, facts.tls_trusted) == ("Let's Encrypt", True)
    assert facts.to_dict()["web"][0]["ip"] == "192.0.2.10"


def test_collect_refuses_a_domain_that_does_not_exist(offline):
    with pytest.raises(TargetNotFoundError):
        asyncio.run(collect("nothing-here.com"))
    # solar.rt.ru: the parent exists, the address does not.
    with pytest.raises(TargetNotFoundError, match=r"gone.example.com"):
        asyncio.run(collect("gone.example.com"))


def test_a_failed_stage_becomes_a_note_not_a_crash(offline, monkeypatch):
    async def whois_down(self, domain):
        raise collect_module.ModuleError("WHOIS недоступен (TimeoutError)")

    monkeypatch.setattr(Collector, "registrar", whois_down)
    facts = asyncio.run(collect("example.com"))
    assert facts.registrar is None
    assert any("регистратора" in n and "WHOIS" in n for n in facts.notes)
    assert facts.html == PAGE  # the other stages went on


def test_ru_registrar_comes_from_whois(monkeypatch):
    queries = []

    async def whois_query(server, query, timeout):
        queries.append((server, query))
        if server == "whois.iana.org":
            return "refer: whois.tcinet.ru\n"
        return "domain: EXAMPLE.RU\nregistrar: RU-CENTER-RU\n"

    monkeypatch.setattr(collect_module, "whois_query", whois_query)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await Collector(Resolver(DNS), client, 5).registrar("example.ru")

    assert asyncio.run(go()) == "RU-CENTER-RU"
    # .ru has no RDAP: straight to WHOIS, IANA first for the server.
    assert queries == [("whois.iana.org", "ru"), ("whois.tcinet.ru", "example.ru")]
