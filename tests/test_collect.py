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
