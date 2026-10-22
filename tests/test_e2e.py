"""`suveren scan` from the command line to the files it writes, offline.

The lab (tests/lab.py) checks each module's verdicts; this runs the whole command on
lab sites: collection, every stage of run_scan, scenarios, the terminal view, the JSON
and HTML files and the exit codes. Only the network edges are replaced: collect() gets
the lab's facts, HTTP goes to the lab's transport, DNS to its records, TLS to its result.
"""

import asyncio
import json

import httpx
import lab
import pytest
from test_schema import SCHEMA, errors
from typer.testing import CliRunner

import suveren.cli as cli_module
import suveren.scan as scan_module
from suveren import subdomains, websec
from suveren.audit import audit
from suveren.cli import app
from suveren.collect import Facts, NetInfo

CASES = {c.name: c for c in lab.CASES}


@pytest.fixture
def offline(monkeypatch, tmp_path):
    """Point run_scan's network edges at one lab case; returns a function to pick it."""
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(subdomains, "CRTSH_RETRY_DELAY", 0)

    # Any real HTTP request or TCP connection fails the test: only the lab answers.
    async def no_http(self, request):
        raise AssertionError(f"a real request to {request.url}")

    async def no_tcp(host=None, port=None, **_):
        raise AssertionError(f"a real connection to {host}:{port}")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", no_http)
    monkeypatch.setattr(asyncio, "open_connection", no_tcp)
    by_host = {c.host: c for c in lab.CASES}

    def case_for(host: str) -> lab.Case:
        # mta-sts.lab-good.ru belongs to lab-good.ru; other hosts get the reference site.
        return next((c for h, c in by_host.items() if host == h or host.endswith("." + h)), None)

    async def collect(host, **_):
        case = by_host[host]
        scheme = "http" if case.http else "https"
        return Facts(
            host,
            host,
            web=[NetInfo("192.0.2.10", 64500, case.hosting[0], case.hosting[1])],
            final_url=f"{scheme}://{host}/",
            page_status=200,
            html=case.html,
            headers={k.lower(): v for k, v in case.headers.items()},
            set_cookies=list(case.cookies),
        )

    transports = {c.host: lab._transport(c) for c in lab.CASES}

    def route(request: httpx.Request) -> httpx.Response:
        case = case_for(request.url.host)
        if case is None:  # crt.sh, RDAP, block lists: as if they were down
            return httpx.Response(503, text="нет в лаборатории")
        return transports[case.host].handler(request)

    def make_client(timeout, *, verify=True):
        return httpx.AsyncClient(transport=httpx.MockTransport(route), follow_redirects=True)

    records = {}
    for c in lab.CASES:
        records.update({**lab.good_dns(c.host), **(c.dns or {})})

    async def create_resolver(mode, timeout, client):
        return lab.FakeResolver(records), None

    async def probe_tls(host, timeout):
        case = by_host[host]
        return case.tls or lab.good_tls(host)

    monkeypatch.setattr(scan_module, "collect", collect)
    monkeypatch.setattr(scan_module, "make_client", make_client)
    monkeypatch.setattr(cli_module, "make_client", make_client)
    monkeypatch.setattr(scan_module, "create_resolver", create_resolver)
    monkeypatch.setattr(websec, "probe_tls", probe_tls)
    return lambda name: CASES[name]


def run_cli(tmp_path, *args):
    result = CliRunner().invoke(app, ["scan", *args, "--no-open"], catch_exceptions=False)
    return result


@pytest.mark.parametrize("name", ["lab-good", "lab-ga-no-banner", "lab-tls-wrong-host"])
def test_scan_writes_a_consistent_report(offline, tmp_path, name):
    case = offline(name)
    out_json, out_html = tmp_path / "r.json", tmp_path / "r.html"
    result = run_cli(tmp_path, case.host, "--json", str(out_json), "-o", str(out_html))
    assert result.exit_code == 0, result.output
    data = json.loads(out_json.read_text(encoding="utf-8"))
    # The file is what the schema promises and has no contradictions.
    assert errors(data, SCHEMA) == []
    assert audit(data) == []
    # The whole command reaches the same verdicts as the lab's module-level run.
    got = {c["id"]: c["status"] for c in data["checks"]}
    for check_id, want in case.expect.items():
        assert got.get(check_id) == want, (check_id, got.get(check_id), want)
    html = out_html.read_text(encoding="utf-8")
    assert case.host in html and "<script>alert" not in html


def test_fail_on_gives_exit_code_4(offline, tmp_path):
    case = offline("lab-tls-wrong-host")
    result = run_cli(tmp_path, case.host, "--fail-on", "fail", "-o", str(tmp_path / "r.html"))
    assert result.exit_code == 4
    assert "SUV-WEB-008" in result.output


def test_checks_narrow_the_report(offline, tmp_path):
    case = offline("lab-no-hsts")
    out_json = tmp_path / "r.json"
    result = run_cli(
        tmp_path, case.host, "--checks", "SUV-WEB-005", "--json", str(out_json),
        "-o", str(tmp_path / "r.html"),
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert [c["id"] for c in data["checks"]] == ["SUV-WEB-005"]
    assert data["checks"][0]["status"] == "warn"


def test_quick_profile_and_sarif(offline, tmp_path):
    case = offline("lab-ga-no-banner")
    sarif = tmp_path / "r.sarif"
    result = run_cli(
        tmp_path, case.host, "--quick", "--sarif", str(sarif), "-o", str(tmp_path / "r.html")
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    rules = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rules  # the foreign services Google Analytics brings are findings


def test_batch_then_diff_then_audit(offline, tmp_path):
    sites = tmp_path / "sites.txt"
    sites.write_text("lab-good.ru\nlab-no-hsts.ru\n", encoding="utf-8")
    out = tmp_path / "batch"
    result = CliRunner().invoke(
        app, ["batch", str(sites), "--out", str(out), "--no-open"], catch_exceptions=False
    )
    assert result.exit_code == 0, result.output
    written = {p.name for p in out.iterdir()}
    assert {"lab-good.ru.json", "lab-no-hsts.ru.json", "lab-good.ru.html"} <= written
    assert any(name.endswith(".csv") for name in written)

    # The site that lost HSTS, compared with the reference one.
    diff = CliRunner().invoke(
        app, ["diff", str(out / "lab-good.ru.json"), str(out / "lab-no-hsts.ru.json")]
    )
    assert diff.exit_code == 0, diff.output

    audited = CliRunner().invoke(app, ["audit", str(out)])
    assert audited.exit_code == 0, audited.output


class FakeBrowser:
    """A BrowserSession that 'renders' lab pages: the HTML as served, the requests a
    browser would make for Google Analytics, and who started each of them."""

    GA = "https://www.googletagmanager.com/gtag/js?id=G-LAB1234"
    COLLECT = "https://www.google-analytics.com/g/collect?v=2"

    def __init__(self, *, timeout=25.0):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def open(self, url, *, initiators=False, settle_ms=None):
        from urllib.parse import urlsplit

        from suveren.render import Rendered

        host = urlsplit(url).hostname
        case = next(c for c in lab.CASES if host and host.endswith(c.host))
        resp = lab._transport(case).handler(httpx.Request("GET", url))
        requests = [self.GA, self.COLLECT] if "googletagmanager" in case.html else []
        return Rendered(
            url,
            resp.status_code,
            resp.text,
            requests,
            {self.COLLECT: self.GA} if initiators and requests else {},
            {k.lower(): v for k, v in resp.headers.items()},
        )

    async def open_many(self, urls, *, concurrency=3):
        return [await self.open(u) for u in urls]


def test_browser_mode_sees_requests_and_who_started_them(offline, monkeypatch, tmp_path):
    monkeypatch.setattr(scan_module, "BrowserSession", FakeBrowser)
    case = offline("lab-ga-no-banner")
    out_json = tmp_path / "r.json"
    result = run_cli(
        tmp_path, case.host, "--browser", "--json", str(out_json), "-o", str(tmp_path / "r.html")
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["facts"]["rendered"] is True
    statuses = {c["id"]: c["status"] for c in data["checks"]}
    assert "SUV-WEB-011" in statuses  # the script graph exists only in the browser
    for check_id, want in case.expect.items():
        assert statuses.get(check_id) == want, check_id
    assert audit(data) == []


def test_cutoff_that_breaks_is_not_checked_not_a_crash(offline, monkeypatch, tmp_path):
    async def broken(*args, **kwargs):
        raise RuntimeError("браузер упал")

    monkeypatch.setattr(scan_module, "run_cutoff", broken)
    case = offline("lab-ga-no-banner")
    out_json = tmp_path / "r.json"
    result = run_cli(
        tmp_path, case.host, "--cutoff", "--json", str(out_json), "-o", str(tmp_path / "r.html")
    )
    assert result.exit_code == 0, result.output
    checks = {c["id"]: c for c in json.loads(out_json.read_text(encoding="utf-8"))["checks"]}
    assert checks["SUV-CUT-001"]["status"] in ("ok", "warn", "fail")  # the infrastructure part
    assert checks["SUV-CUT-002"]["status"] == "unknown"
    assert "браузер упал" in checks["SUV-CUT-002"]["details"]
