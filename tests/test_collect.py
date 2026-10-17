import asyncio

from suveren.collect import (
    clean_as_name,
    issuer_org,
    parse_cymru_asname,
    parse_cymru_origin,
    parse_mx,
    parse_rdap_registrar,
    parse_whois_registrar,
)


def test_parse_cymru_origin():
    assert parse_cymru_origin('"13335 | 104.16.0.0/13 | US | arin | 2014-03-28"') == (13335, "US")


def test_parse_cymru_origin_multiple_asns():
    assert parse_cymru_origin("16509 14618 | 3.0.0.0/9 | US | arin | ") == (16509, "US")


def test_parse_cymru_origin_garbage():
    assert parse_cymru_origin("nonsense") == (None, None)


def test_parse_cymru_asname_uses_owner_country():
    txt = "201978 | EE | ripencc | 2015-01-01 | HABR-AS - Habr Europe OU, EE"
    assert parse_cymru_asname(txt) == ("EE", "Habr Europe OU")


def test_clean_as_name():
    assert clean_as_name("CLOUDFLARENET, US") == "CLOUDFLARENET"
    assert clean_as_name("PAGM-AS - CLOUD.DOG OU, EE") == "CLOUD.DOG OU"
    assert clean_as_name("YANDEX, RU") == "YANDEX"


def test_parse_mx_sorts_and_skips_null():
    assert parse_mx(["20 mx2.example.ru.", "10 MX1.Example.RU.", "0 ."]) == [
        "mx1.example.ru",
        "mx2.example.ru",
    ]


def test_parse_rdap_registrar():
    doc = {
        "entities": [
            {"roles": ["registrant"], "handle": "X"},
            {
                "roles": ["registrar"],
                "handle": "146",
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", "GoDaddy.com, LLC"]],
                ],
            },
        ]
    }
    assert parse_rdap_registrar(doc) == "GoDaddy.com, LLC"


def test_parse_whois_registrar_ru():
    text = """
% TCI Whois Service. Terms of use:
domain:        EXAMPLE.RU
nserver:       ns1.selectel.org.
registrar:     REGRU-RU
"""
    assert parse_whois_registrar(text) == "REGRU-RU"


def test_issuer_org():
    cert = {
        "issuer": (
            (("countryName", "US"),),
            (("organizationName", "Let's Encrypt"),),
            (("commonName", "R11"),),
        )
    }
    assert issuer_org(cert) == "Let's Encrypt"


class _RotatingResolver:
    """Returns ns1's addresses in a different order on every call, like real DNS."""

    kind = "fake"

    def __init__(self) -> None:
        self.calls = 0
        self.nets = {"1.1.1.1": (64500, "US"), "2.2.2.2": (64501, "RU"), "3.3.3.3": (64500, "US")}

    async def resolve(self, name: str, rtype: str) -> list[str]:
        if name == "example.ru" and rtype == "NS":
            return ["ns1.example.net."]
        if name == "ns1.example.net" and rtype == "A":
            self.calls += 1
            ips = list(self.nets)
            shift = self.calls % len(ips)
            return ips[shift:] + ips[:shift]
        if name.endswith(".origin.asn.cymru.com"):
            ip = ".".join(reversed(name.split(".")[:4]))
            asn, country = self.nets[ip]
            return [f"{asn} | {ip}/24 | {country} | ripe | "]
        if name.endswith(".asn.cymru.com"):
            asn = int(name.split(".")[0][2:])
            return [f"{asn} | ZZ | ripe | | NET{asn}, ZZ"]
        return []


def test_ns_lists_every_network_in_a_stable_order():
    from suveren.collect import Collector

    resolver = _RotatingResolver()
    collector = Collector(resolver, None, 5.0)  # type: ignore[arg-type]
    runs = [asyncio.run(collector.ns("example.ru")) for _ in range(3)]
    seen = [[(h.host, h.net.asn) for h in run] for run in runs]
    # Two networks (the third address shares AS64500), same answer every time.
    assert seen[0] == [("ns1.example.net", 64500), ("ns1.example.net", 64501)]
    assert seen[0] == seen[1] == seen[2]


def test_host_without_address_is_kept():
    from suveren.collect import Collector

    collector = Collector(_RotatingResolver(), None, 5.0)  # type: ignore[arg-type]
    hosts = asyncio.run(collector._hosts(["gone.example.net"]))
    assert [(h.host, h.net) for h in hosts] == [("gone.example.net", None)]
