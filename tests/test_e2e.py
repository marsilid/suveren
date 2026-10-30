"""`suveren scan` from the command line to the files it writes, offline.

The lab (tests/lab.py) checks each module's verdicts; this runs the whole command on
lab sites: collection, every stage of run_scan, scenarios, the terminal view, the JSON
and HTML files and the exit codes. Only the network edges are replaced: collect() gets
the lab's facts, HTTP goes to the lab's transport, DNS to its records, TLS to its result.
"""

import asyncio
import csv
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
from suveren.errors import TargetNotFoundError

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


def test_an_unreachable_site_does_not_pass_fail_under_a(offline, tmp_path, monkeypatch):
    # The proxy's bare 503 for a host that doesn't answer gave A 100/100 and exit 0.
    case = offline("lab-good")

    async def no_page(host, **_):
        return Facts(host, host, web=[NetInfo("192.0.2.10", 64500, "Selectel", "RU")],
                     page_status=503, html="")  # fmt: skip

    monkeypatch.setattr(scan_module, "collect", no_page)
    out = tmp_path / "r.json"
    result = run_cli(tmp_path, case.host, "--quick", "--no-report", "--json", str(out),
                     "--fail-under", "A")  # fmt: skip
    assert result.exit_code == 3, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert (data["grade"], data["overall_grade"]) == ("B", "B")
    assert data["overall_incomplete"] and errors(data, SCHEMA) == [] and audit(data) == []


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
    rows = [json.loads(line) for line in (out / "summary.jsonl").read_text("utf-8").splitlines()]
    assert {r["domain"] for r in rows} == {"lab-good.ru", "lab-no-hsts.ru"}
    no_hsts = next(r for r in rows if r["domain"] == "lab-no-hsts.ru")
    assert no_hsts["checks"]["SUV-WEB-005"] == "warn"

    good = str(out / "lab-good.ru.json")
    diff = CliRunner().invoke(app, ["diff", good, good])
    assert diff.exit_code == 0, diff.output
    # Two different sites are not one site's change: every service looked "removed".
    other = CliRunner().invoke(app, ["diff", good, str(out / "lab-no-hsts.ru.json")])
    assert other.exit_code == 2 and "разных сайтов" in other.output

    # The folder also holds summary.jsonl and the like: those are not reports, not errors.
    (out / "extra.json").write_text('{"note": 1}', encoding="utf-8")
    audited = CliRunner().invoke(app, ["audit", str(out)])
    assert audited.exit_code == 0, audited.output
    assert "2 отчётов" in audited.output


@pytest.mark.parametrize(
    ("content", "why"),
    [(None, "не удалось прочитать"), ("{}", "не отчёт"), ("[1, 2]", "не отчёт"),
     ('{"target": "x.ru", "dependencies": [], "schema_version": "2.0"}', "только 1.x"),
     ("{broken", "не удалось прочитать")],
)  # fmt: skip
def test_audit_and_diff_refuse_what_is_not_a_report(tmp_path, content, why):
    # audit said "✓ Противоречий нет" with exit 0 on all of these; diff crashed on some.
    path = tmp_path / "r.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    runner = CliRunner()
    audited = runner.invoke(app, ["audit", str(path)])
    assert audited.exit_code == 2 and why in audited.output, audited.output
    assert "Противоречий нет" not in audited.output
    diffed = runner.invoke(app, ["diff", str(path), str(path)])
    # A clean refusal: exit 2 with the reason, no traceback.
    assert diffed.exit_code == 2 and why in diffed.output, diffed.output
    assert diffed.exception is None or isinstance(diffed.exception, SystemExit)


def test_audit_of_an_empty_folder_is_an_error(tmp_path):
    result = CliRunner().invoke(app, ["audit", str(tmp_path)])
    assert result.exit_code == 2 and "нет JSON-отчётов" in result.output


def test_since_is_checked_before_the_scan(offline, tmp_path):
    case = offline("lab-good")
    other = tmp_path / "other.json"
    other.write_text(
        json.dumps({"target": "lab-no-hsts.ru", "dependencies": [], "checks": []}), "utf-8"
    )
    for since, why in [(other, "другого сайта"), (tmp_path / "nofile.json", "прочитать")]:
        result = run_cli(tmp_path, case.host, "--since", str(since), "--no-report")
        assert result.exit_code == 2 and why in result.output, result.output
        assert "готово за" not in result.output  # refused before any network work


def test_batch_with_gaps_exits_1_and_lists_them(offline, tmp_path, monkeypatch):
    # Exit 0 when sites failed let a nightly or CI run look clean.
    lab_collect = scan_module.collect

    async def collect(host, **kw):
        if host == "lab-missing.ru":
            raise TargetNotFoundError("домен lab-missing.ru не существует (NXDOMAIN)")
        return await lab_collect(host, **kw)

    monkeypatch.setattr(scan_module, "collect", collect)
    sites = tmp_path / "sites.txt"
    sites.write_text("lab-good.ru\nnot a domain!!\nlab-missing.ru\n", encoding="utf-8")
    out = tmp_path / "batch"
    result = CliRunner().invoke(
        app, ["batch", str(sites), "--out", str(out), "--no-open"], catch_exceptions=False
    )
    assert result.exit_code == 1, result.output
    assert "строка 2" in result.output and "Не проверены: 1" in result.output
    # The warning comes under the header, not above it as stray shell output.
    assert result.output.index("2 сайта") < result.output.index("строка 2")
    with (out / "summary.csv").open(encoding="utf-8-sig", newline="") as fh:
        rows = {r["domain"]: r for r in csv.DictReader(fh)}
    assert rows["lab-good.ru"]["error"] == "" and rows["lab-good.ru"]["overall_grade"]
    assert rows["lab-missing.ru"]["error"] and rows["lab-missing.ru"]["grade"] == ""


def test_batch_passes_the_dns_mode_on(offline, tmp_path, monkeypatch):
    # The nightly run asks for --dns ru: no site name may go to a resolver abroad.
    modes = []
    fake = scan_module.create_resolver

    async def recording(mode, timeout, client):
        modes.append(mode)
        return await fake(mode, timeout, client)

    monkeypatch.setattr(scan_module, "create_resolver", recording)
    sites = tmp_path / "sites.txt"
    sites.write_text("lab-good.ru\n", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        ["batch", str(sites), "--dns", "ru", "--out", str(tmp_path / "b"), "--no-open"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert modes and set(modes) == {"ru"}


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


def test_since_shows_what_changed(offline, tmp_path):
    case = offline("lab-ga-no-banner")
    old = tmp_path / "old.json"
    assert (
        run_cli(tmp_path, case.host, "--json", str(old), "-o", str(tmp_path / "a.html")).exit_code
        == 0
    )
    # Pretend that last time HSTS was fine and Google Analytics was not there yet.
    data = json.loads(old.read_text(encoding="utf-8"))
    data["dependencies"] = [d for d in data["dependencies"] if "Google" not in d["service"]]
    for c in data["checks"]:
        if c["id"] == "SUV-PD-005":
            c["status"] = "ok"
    old.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    new, html = tmp_path / "new.json", tmp_path / "b.html"
    result = run_cli(tmp_path, case.host, "--since", str(old), "--json", str(new), "-o", str(html))
    assert result.exit_code == 0, result.output
    assert "С прошлой проверки" in result.output and "SUV-PD-005" in result.output
    report = json.loads(new.read_text(encoding="utf-8"))
    assert errors(report, SCHEMA) == []
    hist = report["history"]
    assert any(a["service"].startswith("Google") and a["foreign"] for a in hist["added"])
    assert {"id": "SUV-PD-005", "before": "ok", "after": "warn"}.items() <= next(
        c for c in hist["checks"] if c["id"] == "SUV-PD-005"
    ).items()
    assert "С прошлой проверки" in html.read_text(encoding="utf-8")


def test_history_matches_old_reports_by_title():
    from suveren.history import compare

    old = {"checks": [{"title": "Принудительный HTTPS (HSTS)", "status": "warn"}]}
    new = {
        "checks": [{"id": "SUV-WEB-005", "title": "Принудительный HTTPS (HSTS)", "status": "ok"}]
    }
    (change,) = compare(old, new).checks
    assert (change.id, change.before, change.after, change.better) == (
        "SUV-WEB-005",
        "warn",
        "ok",
        True,
    )


def test_quiet_prints_nothing_but_keeps_files_and_exit_codes(offline, tmp_path):
    case = offline("lab-tls-wrong-host")
    out = tmp_path / "r.json"
    result = CliRunner().invoke(
        app,
        ["scan", case.host, "-q", "--fail-on", "fail", "--json", str(out), "--no-report"],
        catch_exceptions=False,
    )
    assert result.exit_code == 4
    assert result.stdout == ""  # the failure is on stderr
    assert "SUV-WEB-008" in result.stderr
    assert json.loads(out.read_text(encoding="utf-8"))["target"] == case.host
    # The next command in the same process is not silenced.
    assert "Ничего не изменилось" in CliRunner().invoke(app, ["diff", str(out), str(out)]).output


@pytest.mark.parametrize("flag", ["--json", "--sarif"])
def test_dash_sends_the_data_to_stdout_and_the_view_to_stderr(offline, tmp_path, flag):
    # "-" used to create a file named "-" and leave the terminal view on stdout.
    case = offline("lab-good")
    result = CliRunner().invoke(
        app, ["scan", case.host, flag, "-", "--no-report", "--no-open"], catch_exceptions=False
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)  # nothing but the document
    assert data.get("target") == case.host or data.get("version") == "2.1.0"
    assert case.host in result.stderr  # the header and verdicts went to stderr
    assert not (tmp_path / "-").exists()
    # The next command prints to stdout again.
    assert "SUV-MAIL-003" in CliRunner().invoke(app, ["checks", "mail"]).stdout


@pytest.mark.parametrize(
    ("args", "why"),
    [(["-o", "-"], "HTML-отчёт в stdout"), (["--json", "-", "--sarif", "-"], "одно")],
)
def test_impossible_stdout_requests_are_refused(offline, tmp_path, args, why):
    result = run_cli(tmp_path, offline("lab-good").host, *args)
    assert result.exit_code == 2 and why in result.stderr and result.stdout == ""


def test_errors_go_to_stderr_even_before_quiet_takes_effect(offline, tmp_path):
    result = run_cli(tmp_path, offline("lab-good").host, "-q", "--checks", "BOGUS")
    assert result.exit_code == 2 and result.stdout == "" and "BOGUS" in result.stderr


def test_both_thresholds_are_told(offline, tmp_path, monkeypatch):
    # The grade's message used to hide the failing checks: CI learned only one of them.
    case = offline("lab-tls-wrong-host")
    lab_collect = scan_module.collect

    async def walled(host, **kw):  # a bot wall caps the grade at B; TLS is still probed
        facts = await lab_collect(host, **kw)
        facts.page_status, facts.html = 403, "<html><body>Access denied</body></html>"
        return facts

    monkeypatch.setattr(scan_module, "collect", walled)
    result = run_cli(tmp_path, case.host, "--fail-under", "A", "--fail-on", "fail", "--no-report")
    assert result.exit_code == 3  # the grade's code comes first
    assert "хуже требуемой A" in result.stderr and "SUV-WEB-008" in result.stderr


def test_shell_completion_is_offered():
    result = CliRunner().invoke(app, ["--help"])
    assert "--install-completion" in result.output


def test_an_incomplete_grade_does_not_pass_a_threshold(offline, tmp_path):
    # Offline the block register and the CT logs do not answer: the grade is incomplete,
    # and passing --fail-under with it hid what was not seen.
    case = offline("lab-good")
    result = run_cli(tmp_path, case.host, "--fail-under", "C", "--no-report")
    assert result.exit_code == 6, result.output
    assert "Оценка неполная" in result.stderr and "--allow-incomplete" in result.stderr
    allowed = run_cli(tmp_path, case.host, "--fail-under", "C", "--allow-incomplete", "--no-report")
    assert allowed.exit_code == 0, allowed.output
    # Without thresholds nothing changes: exit 0 as before.
    assert run_cli(tmp_path, case.host, "--no-report").exit_code == 0


def test_max_time_bounds_the_whole_scan(offline, tmp_path, monkeypatch):
    case = offline("lab-good")

    async def stuck(host, **_):
        await asyncio.sleep(60)

    monkeypatch.setattr(scan_module, "collect", stuck)
    result = CliRunner().invoke(
        app, ["scan", case.host, "--no-open", "--no-report", "--max-time", "1"]
    )
    assert result.exit_code == 1 and "не уложилась в 1 с" in result.stderr


def test_batch_thresholds_go_by_the_worst_site(offline, tmp_path):
    sites = tmp_path / "sites.txt"
    sites.write_text("lab-good.ru\nlab-tls-wrong-host.ru\n", encoding="utf-8")

    def run(*args):
        out = tmp_path / f"b{len(args)}"
        return CliRunner().invoke(
            app, ["batch", str(sites), "--out", str(out), "--no-open", "-q", *args]
        )

    failing = run("--fail-on", "fail")
    assert failing.exit_code == 4 and "SUV-WEB-008" in failing.stderr
    assert "Итого" not in failing.stdout  # -q
    assert run("--fail-under", "F").exit_code == 6  # incomplete offline
    assert run("--fail-under", "F", "--allow-incomplete").exit_code == 0
    assert run("--fail-under", "Z").exit_code == 2


def test_no_browser_is_opened_in_ci(monkeypatch, tmp_path):
    opened = []
    monkeypatch.setattr(cli_module.webbrowser, "open", opened.append)
    monkeypatch.setattr(cli_module.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setenv("CI", "true")
    cli_module._open(tmp_path / "r.html")
    monkeypatch.delenv("CI")
    cli_module._open(tmp_path / "r.html")
    assert len(opened) == 1


def test_diff_says_when_the_two_runs_did_not_see_the_same(tmp_path):
    # drive2.ru "removed" four ad networks on a night its page was not fully seen.
    from rich.console import Console

    from suveren.history import compare
    from suveren.view import print_changes

    ads = {"category": "ads", "category_title": "Реклама", "service": "AdRiver", "foreign": False}
    policy = {"id": "SUV-PD-001", "title": "Политика", "status": "ok"}
    recs = {"id": "SUV-LAW-002", "title": "Рекомендательные технологии", "status": "ok"}
    unseen = ["не проверены: скрипты и виджеты на странице"]
    old = {"dependencies": [ads], "checks": [policy], "overall_incomplete": []}
    new = {"dependencies": [], "checks": [recs], "overall_incomplete": unseen}
    changes = compare(old, new)
    assert changes.uneven and changes.appeared == ["Рекомендательные технологии"]
    assert changes.vanished == ["Политика"]
    console = Console(record=True, width=200)
    print_changes(console, changes)
    text = console.export_text()
    assert "Сравнение неравноценное" in text and "могло быть просто не видно" in text
    assert "новая проверка: Рекомендательные технологии" in text
    assert changes.to_dict()["incomplete"] == [[], unseen]


def test_diff_header_has_the_overall_grade(tmp_path):
    def report(grade, score):
        return {"tool": "suveren", "schema_version": "1.6", "target": "x.ru", "grade": "A",
                "score": 100, "overall_grade": grade, "overall_score": score,
                "dependencies": [], "checks": []}  # fmt: skip

    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(report("B", 80)), encoding="utf-8")
    b.write_text(json.dumps(report("D", 50)), encoding="utf-8")
    result = CliRunner().invoke(app, ["diff", str(a), str(b)])
    assert result.exit_code == 0, result.output
    assert "общая оценка B → D, 80 → 50" in result.output


def test_batch_max_time_and_quiet_gaps_on_stderr(offline, tmp_path, monkeypatch):
    # -q hid the skipped lines and failed sites; the per-site limit was a fixed 300 s.
    case = offline("lab-good")
    lab_collect = scan_module.collect

    async def collect(host, **kw):
        if host == "lab-no-hsts.ru":
            await asyncio.sleep(60)
        return await lab_collect(host, **kw)

    monkeypatch.setattr(scan_module, "collect", collect)
    sites = tmp_path / "sites.txt"
    sites.write_text(f"{case.host}\nnot a domain!!\nlab-no-hsts.ru\n", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        ["batch", str(sites), "--out", str(tmp_path / "b"), "--no-open", "-q", "--max-time", "1"],
    )
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "строка 2" in result.stderr and "не уложилась в 1 с" in result.stderr
    assert "--max-time" in CliRunner().invoke(app, ["scan", "--help"]).output


def test_since_in_html_warns_about_an_uneven_comparison(offline, tmp_path):
    case = offline("lab-good")
    old = tmp_path / "old.json"
    first = run_cli(tmp_path, case.host, "--json", str(old), "--no-report")
    assert first.exit_code == 0
    data = json.loads(old.read_text(encoding="utf-8"))
    data["overall_incomplete"] = []  # the earlier run saw everything
    data["checks"].append({"id": "SUV-OLD-001", "title": "Старая проверка", "status": "ok"})
    old.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    html = tmp_path / "r.html"
    result = run_cli(tmp_path, case.host, "--since", str(old), "-o", str(html))
    assert result.exit_code == 0, result.output
    page = html.read_text(encoding="utf-8")
    assert "Сравнение неравноценное" in page and "проверки больше нет в отчёте: Старая" in page
