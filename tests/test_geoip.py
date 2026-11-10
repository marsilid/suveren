"""The offline geolocation database: parsing, lookup, download and its failures."""

import asyncio
import gzip
import os
import time
from datetime import date

import httpx
import pytest

from suveren import geoip
from suveren.analyze import analyze
from suveren.collect import Facts, NetInfo, locate
from suveren.models import Category

# A tiny DB-IP file: v4 and v6 rows, neighbours of one country, a reserved block.
ROWS = b"""0.0.0.0,0.255.255.255,ZZ
5.0.0.0,5.0.0.255,RU
5.0.1.0,5.0.1.255,RU
5.0.2.0,5.0.2.255,DE
9.9.9.9,9.9.9.9,
2a00::,2a00:ffff:ffff:ffff:ffff:ffff:ffff:ffff,RU
2a01::,2a01:ffff:ffff:ffff:ffff:ffff:ffff:ffff,NL
bad row
1.2.3.4,::1,US
"""


def test_parse_joins_neighbours_and_looks_up_both_versions():
    db = geoip.parse(gzip.compress(ROWS))
    assert len(db.starts[4]) == 4  # 5.0.0.0 and 5.0.1.0 joined
    assert db.country_of("5.0.1.7") == "RU"
    assert db.country_of("5.0.2.1") == "DE"
    assert db.country_of("5.0.3.1") is None  # outside every range
    assert db.country_of("0.1.2.3") is None  # ZZ: reserved
    assert db.country_of("9.9.9.9") is None  # empty code
    assert db.country_of("2a00:1::5") == "RU"
    assert db.country_of("2a01::1") == "NL"
    assert db.country_of("::1") is None
    assert db.country_of("not an ip") is None
    assert not db.empty and geoip.GeoDb().empty


def test_out_of_order_rows_are_skipped():
    db = geoip.parse(b"5.0.2.0,5.0.2.255,DE\n5.0.0.0,5.0.0.255,RU\n")
    assert db.country_of("5.0.0.1") is None and db.country_of("5.0.2.1") == "DE"


def test_month_urls_this_month_then_the_last():
    jan, nov = geoip.month_urls(date(2027, 1, 1)), geoip.month_urls(date(2026, 11, 9))
    assert jan[0].endswith("2027-01.csv.gz") and jan[1].endswith("2026-12.csv.gz")
    assert nov[1].endswith("2026-10.csv.gz")


def load(handler, **kwargs):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await geoip.load(client, **kwargs)

    return asyncio.run(go())


def test_load_falls_back_to_last_month_and_is_read_once(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    asked = []

    def handler(request):
        asked.append(str(request.url))
        if len(asked) == 1:
            return httpx.Response(404)  # the 1st, before the new file is out
        return httpx.Response(200, content=gzip.compress(ROWS))

    db = load(handler)
    assert db.country_of("5.0.2.1") == "DE" and not db.problem
    assert db.origin.startswith("DB-IP, https://db-ip.com, база от ")
    assert len(asked) == 2 and asked[1] == geoip.month_urls()[1]
    assert load(handler) is db  # fresh and unchanged: not downloaded or parsed again
    assert geoip.cached_path().exists()


def test_load_without_any_copy_says_so(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    db = load(lambda r: httpx.Response(503))
    assert db.empty and "не скачалась" in db.problem


def test_too_old_or_broken_copy_is_not_used(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    path = tmp_path / geoip.FILENAME
    path.parent.mkdir(parents=True)
    path.write_bytes(gzip.compress(ROWS))
    old = time.time() - 100 * 86400
    os.utime(path, (old, old))
    db = load(lambda r: httpx.Response(503))  # refresh fails, the old copy is kept
    assert db.empty and "старше" in db.problem

    path.write_bytes(b"\x1f\x8bnot gzip")
    assert "повреждён" in load(lambda r: httpx.Response(503)).problem
    path.write_bytes(b"nothing,here\n")
    assert "пуст" in load(lambda r: httpx.Response(503)).problem


@pytest.mark.parametrize("problem", [False, True])
def test_located_goes_to_hosting_not_to_cdn(problem):
    facts = Facts(
        "lab.ru",
        "lab.ru",
        web=[
            NetInfo("5.0.2.1", 49505, "Selectel", "RU"),
            NetInfo("104.16.0.1", 13335, "CLOUDFLARENET", "US"),
        ],
    )
    db = geoip.GeoDb(problem="база DB-IP не скачалась") if problem else geoip.parse(ROWS)
    if not problem:
        db.origin = "DB-IP, база от 01.11.2026"
        db.starts[4].append(1745879040)  # 104.16.0.0: a CDN answers from everywhere
        db.ends[4].append(1745879295)
        db.countries[4].append("CA")
    locate(facts, db)
    report = analyze(facts)
    hosting = [d for d in report.dependencies if d.category is Category.HOSTING]
    cdn = [d for d in report.dependencies if d.category is Category.CDN]
    assert cdn and all(d.located is None for d in cdn)
    if problem:
        assert hosting[0].located is None and hosting[0].country_text == "Россия"
        assert any("не проверено" in n and "не скачалась" in n for n in report.notes)
    else:
        assert hosting[0].located == "DE" and hosting[0].stored_abroad
        assert hosting[0].country_text == "сеть: Россия, сервер: Германия"
        assert hosting[0].located_by == "DB-IP, база от 01.11.2026"
        assert hosting[0].to_dict()["located"] == "DE"


def test_two_servers_of_one_network_in_two_countries_stay_two_rows():
    facts = Facts(
        "lab.ru",
        "lab.ru",
        web=[
            NetInfo("5.0.0.1", 49505, "Selectel", "RU", "RU"),
            NetInfo("5.0.2.1", 49505, "Selectel", "RU", "DE"),
        ],
    )
    hosting = [d for d in analyze(facts).dependencies if d.category is Category.HOSTING]
    assert sorted(d.located for d in hosting) == ["DE", "RU"]


def test_scan_does_not_hang_on_a_download_that_never_answers(tmp_path, monkeypatch):
    """redfox0, 2.2.2: no direct internet, the DB-IP download hung until Ctrl+C."""
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    monkeypatch.setattr(geoip, "SCAN_BUDGET", 0.5)
    timeouts = []

    async def handler(request):
        timeouts.append(request.extensions["timeout"])
        await asyncio.sleep(3600)  # a proxy or a firewall that swallows the packets

    started = time.monotonic()
    db = load(handler)
    assert time.monotonic() - started < 5
    assert db.empty and "не скачалась" in db.problem
    # The scan asks with short timeouts of its own, not the 2-minute read of big lists.
    assert timeouts[0]["connect"] == 5.0 and timeouts[0]["read"] == 10.0


def test_dead_connection_is_not_retried_with_last_month(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    asked = []

    def handler(request):
        asked.append(request.url)
        raise httpx.ConnectTimeout("timed out", request=request)

    assert "не скачалась" in load(handler).problem
    assert len(asked) == 1


def test_unreachable_network_stops_later_downloads(tmp_path, monkeypatch):
    """Once the network is unreachable, the next download does not wait for its timeout."""
    from suveren import cache, net

    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    asked = []

    def handler(request):
        asked.append(request.url)
        raise httpx.ConnectError("[Errno 101] Network is unreachable", request=request)

    assert "не скачалась" in load(handler).problem
    assert net.offline()

    async def other():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await cache.fetch_cached(client, "https://example.org/list", "list.txt")

    with pytest.raises(geoip.ModuleError, match="сеть недоступна"):
        asyncio.run(other())
    assert len(asked) == 1  # the second download never went out
