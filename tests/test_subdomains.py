import asyncio
import json

import httpx
import pytest

from suveren import subdomains
from suveren.checks import Status
from suveren.subdomains import (
    Candidate,
    Subdomain,
    SubdomainScan,
    clean_names,
    ct_subdomains,
    evaluate,
    find_candidate,
    parse_certspotter,
    parse_crtsh,
    resolve_subdomain,
    run_subdomain_checks,
)
from suveren.takeover_signatures import find_signature


@pytest.fixture(autouse=True)
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    monkeypatch.setattr(subdomains, "CRTSH_RETRY_DELAY", 0)


class FakeResolver:
    kind = "fake"

    def __init__(self, records=None, missing=()):
        self.records = records or {}
        self.missing = set(missing)  # domains that answer NXDOMAIN

    async def resolve(self, name, rtype):
        return self.records.get((name, rtype), [])

    async def exists(self, domain):
        return domain not in self.missing


def client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def run(coro):
    return asyncio.run(coro)


# --- CT -------------------------------------------------------------------------------


def test_clean_names():
    raw = ["*.example.ru\nexample.ru\nShop.Example.ru", "x.int.example.ru.", "example.ru.evil.com"]
    assert clean_names(raw, "example.ru") == ["shop.example.ru", "x.int.example.ru"]


def test_parsers():
    assert parse_crtsh([{"name_value": "a.example.ru\nb.example.ru"}]) == [
        "a.example.ru\nb.example.ru"
    ]
    assert parse_certspotter([{"dns_names": ["a.example.ru", "other.com"]}]) == [
        "a.example.ru",
        "other.com",
    ]


def test_ct_uses_crtsh_and_caches():
    calls = []

    def handler(request):
        calls.append(request.url.host)
        return httpx.Response(200, json=[{"name_value": "promo.example.ru\n*.example.ru"}])

    async def go():
        async with client(handler) as c:
            first = await ct_subdomains(c, "example.ru")
            second = await ct_subdomains(c, "example.ru")
        return first, second

    first, second = run(go())
    assert first == (["promo.example.ru"], "crt.sh")
    assert second == first
    assert calls == ["crt.sh"]  # the second call came from the cache


def test_crtsh_is_retried_once():
    calls = []

    def handler(request):
        calls.append(request.url.host)
        if len(calls) == 1:
            return httpx.Response(502)
        return httpx.Response(200, json=[{"name_value": "promo.example.ru"}])

    async def go():
        async with client(handler) as c:
            return await ct_subdomains(c, "example.ru")

    assert run(go()) == (["promo.example.ru"], "crt.sh")
    assert calls == ["crt.sh", "crt.sh"]


def test_ct_falls_back_to_certspotter_and_reads_every_page():
    pages = {
        None: [{"id": "1", "dns_names": ["api.example.ru", "x.other.ru"]}],
        "1": [{"id": "2", "dns_names": ["mail.example.ru"]}],
        "2": [],
    }

    def handler(request):
        if request.url.host == "crt.sh":
            return httpx.Response(502)
        return httpx.Response(200, json=pages[request.url.params.get("after")])

    async def go():
        async with client(handler) as c:
            return await ct_subdomains(c, "example.ru")

    assert run(go()) == (["api.example.ru", "mail.example.ru"], "Cert Spotter")


def test_ct_down_is_not_checked():
    async def go():
        async with client(lambda r: httpx.Response(503)) as c:
            return await run_subdomain_checks(FakeResolver(), c, c, "example.ru")

    checks, data = run(go())
    assert [c.status for c in checks] == [Status.UNKNOWN]
    assert data == {}


# --- DNS and takeover -----------------------------------------------------------------


def test_resolve_follows_cname_chain():
    resolver = FakeResolver(
        {
            ("www.example.ru", "CNAME"): ["edge.cdn.net."],
            ("edge.cdn.net", "CNAME"): ["pop1.cdn.net."],
            ("www.example.ru", "A"): ["10.0.0.1"],
        }
    )
    sub = run(resolve_subdomain(resolver, "www.example.ru"))
    assert sub.cnames == ["edge.cdn.net", "pop1.cdn.net"]
    assert sub.alive


def _candidate(sub, resolver=None, page=None, rdap=200):
    def handler(request):
        if request.url.host == "rdap.org":
            return httpx.Response(rdap)
        status, body = page or (200, "<html>ok</html>")
        return httpx.Response(status, text=body)

    async def go():
        async with client(handler) as c:
            return await find_candidate(resolver or FakeResolver(), c, sub, "example.ru")

    return run(go())


def test_cname_to_unregistered_domain_is_certain():
    sub = Subdomain("promo.example.ru", ["promo.agency2019.com"])
    found = _candidate(sub, FakeResolver(missing={"agency2019.com"}), rdap=404)
    assert found is not None and found.certain
    assert "не зарегистрирован" in found.reason


def test_registered_domain_without_dns_is_not_for_sale():
    # lamoda.tech: registered until 2027, status "inactive", no name servers.
    sub = Subdomain("tableau.example.ru", ["tableau.example.tech"])
    assert _candidate(sub, FakeResolver(missing={"example.tech"}), rdap=200) is None


def test_silent_registry_is_only_a_warning():
    sub = Subdomain("promo.example.ru", ["promo.agency2019.com"])
    found = _candidate(sub, FakeResolver(missing={"agency2019.com"}), rdap=503)
    assert found is not None and not found.certain
    assert "реестр не ответил" in found.reason


def test_ru_domains_are_checked_in_whois(monkeypatch):
    answers = {
        "free-agency.ru": "% TCI Whois Service\n\nNo entries found for the selected source(s).",
        "taken-agency.ru": "% TCI Whois Service\n\ndomain:        TAKEN-AGENCY.RU\n",
    }

    async def fake_whois(server, query, timeout):
        assert server == "whois.tcinet.ru"
        return answers[query]

    monkeypatch.setattr(subdomains, "whois_query", fake_whois)
    resolver = FakeResolver(missing=set(answers))
    free = _candidate(Subdomain("a.example.ru", ["site.free-agency.ru"]), resolver)
    assert free is not None and free.certain
    assert _candidate(Subdomain("b.example.ru", ["site.taken-agency.ru"]), resolver) is None


def test_internal_names_are_not_for_sale():
    sub = Subdomain("intra.example.ru", ["srv1.corp"])
    assert _candidate(sub, FakeResolver(missing={"corp", "srv1.corp"})) is None


def test_github_pages_fingerprint():
    sub = Subdomain("docs.example.ru", ["example.github.io"], ["185.199.108.153"])
    found = _candidate(sub, page=(404, "<h1>There isn't a GitHub Pages site here.</h1>"))
    assert found is not None and not found.certain
    assert found.service == "GitHub Pages"
    assert _candidate(sub, page=(200, "<h1>Docs</h1>")) is None


def test_nxdomain_signature():
    dead = Subdomain("app.example.ru", ["example-app.azurewebsites.net"])
    found = _candidate(dead)
    assert found is not None and found.service == "Microsoft Azure"
    live = Subdomain("app.example.ru", ["example-app.azurewebsites.net"], ["20.0.0.1"])
    assert _candidate(live) is None


def test_status_code_signature():
    sub = Subdomain("help.example.ru", ["example.helprace.com"], ["10.0.0.1"])
    assert _candidate(sub, page=(301, "")) is not None
    assert _candidate(sub, page=(200, "")) is None


def test_signatures_match_whole_domain_suffixes():
    assert find_signature(["example.github.io."]).service == "GitHub Pages"
    assert find_signature(["evilgithub.io"]) is None
    assert find_signature(["shop.example.ru"]) is None


# --- Checks ---------------------------------------------------------------------------


def _scan(candidates=(), names=3, checked=3):
    subs = [Subdomain(f"s{i}.example.ru") for i in range(checked)]
    return SubdomainScan(
        "example.ru", [f"s{i}.example.ru" for i in range(names)], "crt.sh", subs, list(candidates)
    )


def test_evaluate_statuses():
    inventory, takeover = evaluate(_scan())
    assert inventory.status is Status.OK and "Найдено поддоменов: 3" in inventory.details
    assert takeover.status is Status.OK

    weak = Candidate(Subdomain("docs.example.ru", ["x.github.io"]), "страница-заглушка", False)
    assert evaluate(_scan([weak]))[1].status is Status.WARN
    strong = Candidate(Subdomain("old.example.ru", ["gone.ru"]), "не зарегистрирован", True)
    check = evaluate(_scan([weak, strong]))[1]
    assert check.status is Status.FAIL
    assert "проверьте вручную" in check.details


def test_evaluate_says_when_the_list_was_cut():
    inventory, _ = evaluate(_scan(names=500, checked=300))
    assert "Проверены первые 300" in inventory.details


def test_run_returns_json_data():
    def handler(request):
        if request.url.host == "crt.sh":
            return httpx.Response(200, json=[{"name_value": "old.example.ru"}])
        return httpx.Response(404 if request.url.host == "rdap.org" else 200)

    resolver = FakeResolver(
        {("old.example.ru", "CNAME"): ["gone-site.com."]}, missing={"gone-site.com"}
    )

    async def go():
        async with client(handler) as c:
            return await run_subdomain_checks(resolver, c, c, "example.ru")

    checks, data = run(go())
    assert checks[1].status is Status.FAIL
    assert data["takeover"][0]["name"] == "old.example.ru"
    json.dumps(data)  # serialisable for the JSON report


def test_ct_error_names_both_sources():
    def handler(request):
        return httpx.Response(502 if request.url.host == "crt.sh" else 429)

    async def go():
        async with client(handler) as c:
            return await run_subdomain_checks(FakeResolver(), c, c, "example.ru")

    checks, _ = run(go())
    assert "crt.sh: HTTP 502" in checks[0].details
    assert "Cert Spotter: слишком много запросов" in checks[0].details


def test_takeover_data_file_is_valid():
    """data/takeover.json is edited by hand: every entry must load and make sense."""
    import json
    import re
    from importlib.resources import files

    raw = json.loads(files("suveren").joinpath("data/takeover.json").read_text("utf-8"))
    assert raw["source"].startswith("https://github.com/EdOverflow/") and raw["checked"]
    allowed = {"service", "cnames", "fingerprints", "nxdomain", "vulnerable", "added", "seen",
               "comment"}  # fmt: skip
    names = set()
    for d in raw["signatures"]:
        assert set(d) <= allowed, d["service"]
        assert d["service"] not in names
        names.add(d["service"])
        assert d["cnames"] and (d.get("fingerprints") or d.get("nxdomain")), d["service"]
        for fp in d.get("fingerprints", ()):
            if not fp.startswith("HTTP_STATUS="):
                re.compile(fp)
        assert set(d.get("seen", ())) <= set(d.get("fingerprints", ())), d["service"]
