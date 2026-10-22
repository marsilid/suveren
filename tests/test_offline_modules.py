"""The block-list stage and `suveren doctor`, run offline from start to finish."""

import asyncio
from datetime import date

import httpx
from typer.testing import CliRunner

import suveren.doctor as doctor
from suveren.blocklist import DOMAINS, IP_LISTS, run_blocklist
from suveren.checks import Status
from suveren.cli import app
from suveren.registries import EgrulRecord, RknOperator


def no_network(request):
    raise AssertionError(f"a real request to {request.url}")


def test_block_lists_from_the_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    (tmp_path / f"blocklist-{DOMAINS}").write_text("blocked.example\nfacebook.com\n", "utf-8")
    (tmp_path / f"blocklist-{IP_LISTS[0]}").write_text("192.0.2.10\n", "utf-8")
    (tmp_path / f"blocklist-{IP_LISTS[1]}").write_text("198.51.100.0/24\n", "utf-8")

    async def go(host, ips, third):
        async with httpx.AsyncClient(transport=httpx.MockTransport(no_network)) as client:
            return await run_blocklist(client, host, ips, third_party=third)

    checks, _ = asyncio.run(go("site.example", ["192.0.2.10"], ["connect.facebook.com", "x.ru"]))
    by_id = {c.id: c for c in checks}
    assert by_id["SUV-BLK-001"].status is Status.OK
    assert (
        by_id["SUV-BLK-002"].status is Status.WARN and "192.0.2.10" in by_id["SUV-BLK-002"].details
    )
    assert by_id["SUV-BLK-003"].status is not Status.OK  # facebook.com is in the register

    checks, _ = asyncio.run(go("blocked.example", ["203.0.113.5"], None))
    by_id = {c.id: c for c in checks}
    assert by_id["SUV-BLK-001"].status is Status.FAIL
    assert by_id["SUV-BLK-002"].status is Status.OK
    assert "SUV-BLK-003" not in by_id  # the page was not read


class Resolver:
    kind = "fake"

    async def resolve(self, name, rtype):
        return {
            ("google.com", "MX"): ["10 smtp.google.com."],
            ("8.8.8.8.origin.asn.cymru.com", "TXT"): ["15169 | 8.8.8.0/24 | US | arin | 2023"],
            ("AS15169.asn.cymru.com", "TXT"): ["15169 | US | arin | 2000 | GOOGLE, US"],
        }.get((name, rtype), [])

    async def exists(self, domain):
        return True


def test_doctor_reports_every_source(monkeypatch):
    def handler(request):
        url = str(request.url)
        if request.url.host == "rdap.org":
            entity = {"roles": ["registrar"], "handle": "MarkMonitor Inc."}
            return httpx.Response(200, json={"entities": [entity]})
        if request.url.host == "crt.sh":
            return httpx.Response(200, json=[{"name_value": "www.example.com"}])
        if "antifilter" in url:
            return httpx.Response(206, content=b"x" * 1024)
        return httpx.Response(503)  # sanctions lists: down

    def make_client(timeout, *, verify=True):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def create_resolver(mode, timeout, client):
        return Resolver(), None

    async def whois_query(server, query, timeout):
        return "registrar: RU-CENTER-RU\n"

    async def egrul_search(client, inn):
        return [
            EgrulRecord(
                'ПАО "СБЕРБАНК РОССИИ"', "ПАО СБЕРБАНК", inn, None, None,
                date(1991, 6, 20), None, None, None, False,
            )
        ]  # fmt: skip

    async def rkn_operator(client, inn):
        return RknOperator("10-0137716", "ПАО Сбербанк", inn, "", None, None)

    for name, fake in {
        "make_client": make_client,
        "create_resolver": create_resolver,
        "whois_query": whois_query,
        "egrul_search": egrul_search,
        "rkn_operator": rkn_operator,
    }.items():
        monkeypatch.setattr(doctor, name, fake)
    monkeypatch.setattr("suveren.collect.whois_query", whois_query)

    class NoBrowser:  # the probe must not start a real browser
        def __init__(self, **_):
            pass

        async def __aenter__(self):
            raise doctor.ModuleError("нет браузера")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr("suveren.render.BrowserSession", NoBrowser)

    probes = {p.name: p for p in asyncio.run(doctor.run_doctor(5))}
    assert probes["DNS"].ok and probes["Team Cymru (сети IP-адресов)"].ok
    assert probes["RDAP"].details == "MarkMonitor Inc."
    assert probes["WHOIS .ru"].details == "RU-CENTER-RU"
    assert probes["ЕГРЮЛ (ФНС)"].ok and probes["Реестр операторов ПДн (РКН)"].ok
    assert probes["Реестр блокировок"].ok and probes["Журналы сертификатов (crt.sh)"].ok
    sanctions = [p for n, p in probes.items() if n.startswith("Санкции")]
    assert sanctions and all(p.ok is False and "503" in p.details for p in sanctions)
    assert probes["Браузер для --browser"].ok is None  # optional, not a failure

    # The command prints them and fails because the sanctions lists are down.
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code != 0 and "Санкции" in result.output


def test_update_downloads_every_list(tmp_path, monkeypatch):
    from pathlib import Path

    import suveren.cli as cli_module

    fixtures = Path(__file__).parent / "fixtures"
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))

    def handler(request):
        host = request.url.host
        if "ofac" in host:
            return httpx.Response(200, content=(fixtures / "sdn_sample.xml").read_bytes())
        if "europa" in host:
            return httpx.Response(200, content=(fixtures / "eu_sample.csv").read_bytes())
        if "fcdo" in host:
            return httpx.Response(200, content=(fixtures / "uk_sample.csv").read_bytes())
        if "antifilter" in host:
            return httpx.Response(200, text="blocked.example\n")
        raise AssertionError(f"a real request to {request.url}")

    monkeypatch.setattr(
        cli_module,
        "make_client",
        lambda timeout, *, verify=True: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    result = CliRunner().invoke(app, ["update"])
    assert result.exit_code == 0, result.output
    assert "Реестр блокировок РКН" in result.output and "записей" in result.output
    assert (tmp_path / f"blocklist-{DOMAINS}").read_text("utf-8") == "blocked.example\n"


def test_unknown_domains_list_and_clear(tmp_path, monkeypatch):
    from suveren import unknown

    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    assert "Пока пусто" in CliRunner().invoke(app, ["unknown"]).output
    unknown.record(["widget.example", "cdn.example"], "a.ru")
    unknown.record(["widget.example"], "b.ru")
    shown = CliRunner().invoke(app, ["unknown"]).output
    assert shown.index("widget.example") < shown.index("cdn.example")  # most sites first
    assert "Список очищен" in CliRunner().invoke(app, ["unknown", "--clear"]).output
    assert unknown.load() == {}
