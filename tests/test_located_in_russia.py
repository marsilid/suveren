"""A server in Russia on a network registered abroad is not called foreign (borisdenis).

His own mail server stands in Russia, but its network was registered to another country
(Team Cymru), and the report advised moving mail to Yandex 360 or a server in Russia."""

from suveren.analyze import find_dependencies
from suveren.collect import Facts, HostInfo, NetInfo, locate
from suveren.models import Category


class GeoDb:
    problem = ""
    origin = "DB-IP Lite, база от 01.11.2026"

    def __init__(self, places):
        self.places = places

    def country_of(self, ip):
        return self.places.get(ip)


def _facts(located: dict[str, str]) -> Facts:
    def net(ip):
        return NetInfo(ip, asn=64500, as_name="SMALLHOST-NET", country="NL")

    facts = Facts(host="mail-owner.ru", domain="mail-owner.ru")
    facts.mx = [HostInfo("mx.mail-owner.ru", net("192.0.2.25"))]
    facts.ns = [HostInfo("ns1.mail-owner.ru", net("192.0.2.53"))]
    facts.web = [net("192.0.2.80")]
    locate(facts, GeoDb(located))
    return facts


def _by(deps, category):
    return next(d for d in deps if d.category is category)


def test_servers_in_russia_on_a_foreign_registered_network_are_not_foreign():
    facts = _facts({"192.0.2.25": "RU", "192.0.2.53": "RU", "192.0.2.80": "RU"})
    deps, _ = find_dependencies(facts)
    for category in (Category.MAIL, Category.DNS, Category.HOSTING):
        dep = _by(deps, category)
        assert dep.foreign is False and dep.severity is None, category
        assert "записана на Нидерланды" in dep.note and "стоит в России" in dep.note
        assert "DB-IP" in dep.note
        assert dep.country_text == "Россия"


def test_a_server_abroad_stays_foreign():
    facts = _facts({"192.0.2.25": "NL", "192.0.2.53": "NL"})
    deps, _ = find_dependencies(facts)
    mail = _by(deps, Category.MAIL)
    assert mail.foreign is True and mail.severity is not None and not mail.note


def test_without_the_geo_database_the_network_decides_as_before():
    facts = _facts({})
    deps, _ = find_dependencies(facts)
    assert _by(deps, Category.MAIL).foreign is True
    assert _by(deps, Category.DNS).foreign is True
