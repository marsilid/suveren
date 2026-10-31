"""Cloud address lists and the dangling A record warning (SUV-SUB-003)."""

import asyncio
import sys
from pathlib import Path

import httpx
import pytest

from suveren import cloud, subdomains
from suveren.checks import Status
from suveren.cloud import (
    CloudRanges,
    load_ranges,
    parse_aws,
    parse_digitalocean,
    parse_gcp,
    parse_oracle,
)
from suveren.subdomains import Subdomain, SubdomainScan, dangling_check, find_cloud_hosts

sys.path.insert(0, str(Path(__file__).parent))
from lab import CLOUD_LISTS


@pytest.fixture(autouse=True)
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))


def client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def lists(request):
    body = CLOUD_LISTS.get(str(request.url))
    return httpx.Response(200, text=body) if body else httpx.Response(404)


def ranges() -> CloudRanges:
    async def go():
        async with client(lists) as c:
            return await load_ranges(c)

    return asyncio.run(go())


# --- lists ----------------------------------------------------------------------------


def test_parsers_read_the_published_formats():
    aws = (
        '{"prefixes": [{"ip_prefix": "3.5.140.0/22", "service": "EC2"},'
        '{"ip_prefix": "3.5.140.0/22", "service": "AMAZON"}],'
        '"ipv6_prefixes": [{"ipv6_prefix": "2600:1f00::/24", "service": "EC2"}]}'
    )
    assert parse_aws(aws) == ["3.5.140.0/22", "2600:1f00::/24"]
    gcp = '{"prefixes": [{"ipv4Prefix": "34.0.0.0/15"}, {"ipv6Prefix": "2600:1900::/35"}, {}]}'
    assert parse_gcp(gcp) == ["34.0.0.0/15", "2600:1900::/35"]
    oracle = '{"regions": [{"cidrs": [{"cidr": "130.61.0.0/16"}, {"tags": []}]}, {}]}'
    assert parse_oracle(oracle) == ["130.61.0.0/16"]
    do = "104.131.0.0/18,US,US-NY,New York,10001\n\n# comment\n2604:a880::/32,US,,,\n"
    assert parse_digitalocean(do) == ["104.131.0.0/18", "2604:a880::/32"]


def test_lookup_finds_the_cloud_of_an_address():
    r = ranges()
    assert r.cloud_of("3.5.143.255") == "AWS"
    assert r.cloud_of("13.32.1.1") is None  # CloudFront is not EC2
    assert r.cloud_of("34.1.0.1") == "Google Cloud"
    assert r.cloud_of("130.61.9.9") == "Oracle Cloud"
    assert r.cloud_of("104.131.63.1") == "DigitalOcean"
    assert r.cloud_of("198.51.100.1") is None
    assert r.cloud_of("not an address") is None
    assert len(r.sources) == 4 and not r.missing
    assert r.sources[0].startswith(
        "AWS, https://ip-ranges.amazonaws.com/ip-ranges.json, список от "
    )


def test_ipv6_and_junk_prefixes():
    r = CloudRanges()
    r.add("X", ["2600:1f00::/24", "junk", "10.0.0.0/8"])
    assert r.cloud_of("2600:1f00::1") == "X"
    assert r.cloud_of("10.1.2.3") == "X"
    assert r.cloud_of("2600:2000::1") is None


def test_a_list_that_fails_or_is_junk_leaves_the_others(monkeypatch):
    def handler(request):
        url = str(request.url)
        if "amazonaws" in url:
            return httpx.Response(503)
        if "gstatic" in url:
            return httpx.Response(200, text="{not json")
        return lists(request)

    async def go():
        async with client(handler) as c:
            return await load_ranges(c)

    r = asyncio.run(go())
    assert r.missing == ["AWS", "Google Cloud"]
    assert r.cloud_of("130.61.0.1") == "Oracle Cloud"
    assert not r.empty


def test_lists_are_cached_for_a_week():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return lists(request)

    async def go():
        async with client(handler) as c:
            await load_ranges(c)
            await load_ranges(c)

    asyncio.run(go())
    assert len(calls) == len(cloud.SOURCES)


# --- probing and the check ------------------------------------------------------------


def _subs(*pairs):
    return [Subdomain(n, addresses=[a]) for n, a in pairs]


def test_only_own_a_records_on_cloud_addresses_are_opened(monkeypatch):
    opened = []

    async def fetch(_client, name):
        opened.append(name)
        return (200, "ok") if name.startswith("live") else None

    monkeypatch.setattr(subdomains, "_fetch", fetch)
    subs = _subs(("old.a.ru", "3.5.140.1"), ("live.a.ru", "34.0.0.1"), ("own.a.ru", "198.51.100.1"))
    subs.append(Subdomain("cname.a.ru", ["x.cloudfront.net"], ["3.5.140.2"]))
    subs.append(Subdomain("broken.a.ru", failed=True))
    hosts, total = asyncio.run(find_cloud_hosts(None, ranges(), subs))  # type: ignore[arg-type]
    assert total == 2 and sorted(opened) == ["live.a.ru", "old.a.ru"]
    assert [(h.sub.name, h.cloud, h.silent) for h in hosts] == [
        ("old.a.ru", "AWS", True),
        ("live.a.ru", "Google Cloud", False),
    ]


def test_probes_are_capped(monkeypatch):
    async def fetch(_client, name):
        return None

    monkeypatch.setattr(subdomains, "_fetch", fetch)
    monkeypatch.setattr(subdomains, "MAX_CLOUD_PROBES", 2)
    subs = _subs(*((f"s{i}.a.ru", f"3.5.140.{i}") for i in range(5)))
    hosts, total = asyncio.run(find_cloud_hosts(None, ranges(), subs))  # type: ignore[arg-type]
    assert (len(hosts), total) == (2, 5)
    scan = SubdomainScan("a.ru", [], "crt.sh", subs, [], hosts, total, ranges())
    check = dangling_check(scan)
    assert check.status is Status.WARN and "Открыты первые 2 из 5" in check.details


def _scan(hosts=(), total=None, r=None):
    hosts = list(hosts)
    return SubdomainScan(
        "a.ru", [], "crt.sh", [], [], hosts, len(hosts) if total is None else total, r
    )


def test_check_statuses():
    from suveren.subdomains import CloudHost

    nothing = dangling_check(_scan())
    assert nothing.id == "SUV-SUB-003" and nothing.status is Status.OK
    assert "проверять нечего" in nothing.details

    r = ranges()
    clean = dangling_check(_scan(r=r))
    assert clean.status is Status.OK and "Ни один поддомен" in clean.details
    assert len([e for e in clean.evidence if e.what == "Источник"]) == 4

    silent = [CloudHost(Subdomain(f"s{i}.a.ru", addresses=["3.5.140.1"]), "AWS", "3.5.140.1", True)
              for i in range(7)]  # fmt: skip
    warn = dangling_check(_scan(silent, r=r))
    assert warn.status is Status.WARN and "и ещё 2" in warn.details
    assert warn.recommendation and "только подозрение" in warn.details
    assert [e.what for e in warn.evidence][:2] == ["A s0.a.ru", "A s1.a.ru"]

    live = [CloudHost(Subdomain("app.a.ru"), "AWS", "3.5.140.1", False)]
    ok = dangling_check(_scan(live, r=r))
    assert ok.status is Status.OK and "(AWS): 1" in ok.details

    partial = CloudRanges(r.by_length, r.sources[1:], ["AWS"])
    assert "Список AWS не загрузился" in dangling_check(_scan(live, r=partial)).details

    down = dangling_check(_scan(r=CloudRanges(missing=["AWS", "Google Cloud"])))
    assert down.status is Status.UNKNOWN and "AWS, Google Cloud" in down.details
