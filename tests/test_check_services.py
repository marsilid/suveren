"""tools/check_services.py: what it reads from the base and what it flags, offline."""

import asyncio
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "check_services", Path(__file__).parent.parent / "tools" / "check_services.py"
)
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)


def test_domains_are_read_from_patterns_and_suffixes():
    assert cs.pattern_domains(r"googletagmanager\.com") == ["googletagmanager.com"]
    assert cs.pattern_domains(r"mc\.yandex\.ru/metrika") == ["yandex.ru"]
    assert cs.pattern_domains(r"vk\.com/js/api/openapi\.js") == ["vk.com"]  # not openapi.js
    assert cs.suffix_domain("*awsdns-*") is None
    assert cs.suffix_domain("ns.cloudflare.com") == "cloudflare.com"


class Resolver:
    kind = "fake"

    async def exists(self, domain):
        return domain != "dead-widget.example"

    async def resolve(self, name, rtype):
        return {
            "AS100.asn.cymru.com": ["100 | US | arin | 2000 | GOODHOST, US"],
            "AS200.asn.cymru.com": ["200 | US | arin | 2000 | SOMEONE ELSE INC, US"],
        }.get(name, [])


def test_dead_domains_and_new_as_owners_are_flagged():
    data = {
        "infra": [
            {"name": "GoodHost", "country": "US", "asn": [100], "as_names": ["goodhost"]},
            {"name": "SoldHost", "country": "US", "asn": [200], "as_names": ["soldhost"]},
            {"name": "GoneHost", "country": "US", "asn": [300], "as_names": ["gone"]},
        ],
        "page": [
            {"name": "Widget", "country": "US", "category": "widget",
             "page": [r"dead-widget\.example/w\.js"]},
        ],
    }  # fmt: skip
    problems = asyncio.run(cs.check(Resolver(), data))
    assert any("dead-widget.example" in p and "Widget" in p for p in problems)
    assert any("AS200" in p and "SOMEONE ELSE" in p for p in problems)
    assert any("AS300" in p and "не знает" in p for p in problems)
    assert not any("AS100" in p for p in problems)


def test_renamed_owners_are_still_recognised():
    from suveren.services import by_network

    assert by_network(None, "The Constant Company, LLC").name == "Vultr"
    assert by_network(None, "LLC VK").name == "VK Cloud"
