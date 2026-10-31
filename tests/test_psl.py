"""Registrable domains by the Public Suffix List, with its private section."""

import pytest

from suveren.psl import public_suffix, registrable
from suveren.utils import registrable_domain


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("www.example.ru", "example.ru"),
        ("www.shop.example.co.uk", "example.co.uk"),
        ("www.nalog.gov.ru", "nalog.gov.ru"),
        ("shop.msk.ru", "shop.msk.ru"),
        # Site builders: the customer's subdomain is the site, not the platform.
        ("mysite.tilda.ws", "mysite.tilda.ws"),
        ("user.github.io", "user.github.io"),
        ("www.user.narod.ru", "user.narod.ru"),
        ("club.ucoz.ru", "club.ucoz.ru"),
        ("blog.blogspot.com", "blog.blogspot.com"),
        # Wildcard and exception rules (*.ck, !www.ck).
        ("a.b.ck", "a.b.ck"),
        ("www.ck", "www.ck"),
        # Internationalised names in both forms.
        ("www.пример.рф", "пример.рф"),
        ("www.xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"),
        # A suffix itself, and a name the list does not know.
        ("github.io", "github.io"),
        ("host.unknowntld", "host.unknowntld"),
        ("EXAMPLE.RU.", "example.ru"),
    ],
)
def test_registrable(host, expected):
    assert registrable(host) == expected
    assert registrable_domain(host) == expected


def test_public_suffix():
    assert public_suffix("www.example.co.uk") == "co.uk"
    assert public_suffix("mysite.tilda.ws") == "tilda.ws"
    assert public_suffix("x.y.z.ck") == "z.ck"
    assert public_suffix("www.ck") == "ck"
