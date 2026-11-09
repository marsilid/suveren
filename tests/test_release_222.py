"""What readers asked for under the Habr article (2.2.2): --verbose, --dkim-selector."""

import asyncio
import sys
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from suveren import trace
from suveren.cli import app

sys.path.insert(0, str(Path(__file__).parent))
from lab import dkim_key
from test_mailsec import facts

runner = CliRunner()


@pytest.fixture
def lines():
    out: list[str] = []
    trace.enable(out.append)
    yield out
    trace.disable()


# --- --verbose --------------------------------------------------------------------------


def test_trace_is_silent_by_default():
    trace.disable()
    with trace.step("DNS A example.ru"):
        pass
    assert not trace.enabled()


def test_step_says_start_end_and_time(lines):
    with trace.step("DNS A example.ru"):
        pass
    assert "→ DNS A example.ru" in lines[0]
    assert "← DNS A example.ru:" in lines[1] and lines[1].rstrip().endswith("с")


def test_step_says_why_it_failed(lines):
    with pytest.raises(TimeoutError), trace.step("WHOIS whois.tcinet.ru:43"):
        raise TimeoutError
    assert "✗ WHOIS whois.tcinet.ru:43: TimeoutError" in lines[-1]


def test_safe_url_drops_queries_and_secrets():
    assert trace.safe_url("https://api.ru/x?key=SECRET#f") == "api.ru/x"
    token = "https://api.telegram.org/bot123456:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage"
    assert "AAHdq" not in trace.safe_url(token)
    assert "user" not in trace.safe_url("https://user:pass@host.ru/")
    assert "pass" not in trace.safe_url("https://user:pass@host.ru/")
    assert "abcdefghijklmnopqrstuvwxyz0123" not in trace.safe_url(
        "https://h.ru/api/abcdefghijklmnopqrstuvwxyz0123/x"
    )


def test_http_requests_are_traced_with_host_and_code(lines):
    from suveren.net import Traced

    inner = httpx.MockTransport(lambda request: httpx.Response(204))

    async def go() -> None:
        async with httpx.AsyncClient(transport=Traced(inner)) as client:
            await client.get("https://example.ru/page?token=SECRET")

    asyncio.run(go())
    text = "\n".join(lines)
    assert "→ HTTP GET example.ru/page" in text
    assert "← HTTP GET example.ru/page: код 204" in text
    assert "SECRET" not in text


def test_a_hanging_host_is_named_before_the_wait(lines):
    from suveren.net import Traced

    def hang(request: httpx.Request) -> httpx.Response:
        assert any("→ HTTP GET blocked.example" in line for line in lines)
        raise httpx.ConnectTimeout("timed out")

    async def go() -> None:
        async with httpx.AsyncClient(transport=Traced(httpx.MockTransport(hang))) as client:
            await client.get("https://blocked.example/")

    with pytest.raises(httpx.ConnectTimeout):
        asyncio.run(go())
    assert "✗ HTTP GET blocked.example/: ConnectTimeout" in lines[-1]


@pytest.mark.parametrize("command", ["scan", "company", "batch", "research", "doctor"])
def test_verbose_flag_in_every_network_command(command):
    result = runner.invoke(app, [command, "--help"], terminal_width=200)
    assert result.exit_code == 0
    assert "--verbose" in result.output and "-v" in result.output


def test_verbose_turns_tracing_on_for_its_run_only(monkeypatch):
    from suveren import cli

    seen = []

    async def fake_doctor(timeout, abroad=False):
        seen.append(trace.enabled())
        return []

    monkeypatch.setattr(cli, "run_doctor", fake_doctor)
    runner.invoke(app, ["doctor", "-v"])
    runner.invoke(app, ["doctor"])
    assert seen == [True, False]


# --- --dkim-selector --------------------------------------------------------------------


class FakeDns:
    def __init__(self, records: dict[str, list[str]]) -> None:
        self.records = records
        self.asked: list[str] = []

    async def resolve(self, name: str, rtype: str) -> list[str]:
        self.asked.append(f"{rtype} {name}")
        return self.records.get(f"{rtype} {name}", [])


def test_given_selectors_are_tried_with_the_common_ones():
    from suveren.mailsec import _dkim

    key = f"v=DKIM1; k=rsa; p={dkim_key(2048)}"
    dns = FakeDns({"TXT ew._domainkey.exoway.ru": [key]})
    raw: dict[str, list[str]] = {}
    found = asyncio.run(_dkim(dns, "exoway.ru", raw, extra=("ew",)))  # type: ignore[arg-type]
    assert found == ["ew"]
    assert "TXT ew._domainkey.exoway.ru" in raw
    assert "TXT default._domainkey.exoway.ru" in dns.asked  # common ones still tried


def test_check_names_the_selectors_looked_at():
    from suveren.mailsec import dkim_check

    m = facts(dkim=[], dkim_given=["ew"])
    details = dkim_check(m).details
    assert "ew" in details and "default" in details and "mail" in details
    plain = dkim_check(facts(dkim=[])).details
    assert "default" in plain and "только распространённые селекторы" in plain


def test_own_long_key_outweighs_the_hosters_short_one():
    """A reader's own 2048-bit key under "ew" was missed and the hoster's 1024-bit key
    was judged. With --dkim-selector ew both are found; the domain signs with its own."""
    from suveren.checks import Status
    from suveren.mailsec import dkim_strength_check

    raw = {
        "TXT ew._domainkey.exoway.ru": [f"v=DKIM1; k=rsa; p={dkim_key(2048)}"],
        "TXT mail._domainkey.exoway.ru": [f"v=DKIM1; k=rsa; p={dkim_key(1024)}"],
    }
    m = facts(domain="exoway.ru", dkim=["mail", "ew"], dkim_given=["ew"], raw=raw)
    check = dkim_strength_check(m)
    assert check.status is Status.OK
    assert "ew: RSA 2048" in check.details and "mail: RSA 1024" in check.details
    # Without the user's selector the short key is still worth a warning.
    alone = facts(domain="exoway.ru", dkim=["mail"], raw=raw)
    assert dkim_strength_check(alone).status is Status.WARN


def test_given_short_key_is_still_judged():
    from suveren.checks import Status
    from suveren.mailsec import dkim_strength_check

    raw = {"TXT ew._domainkey.exoway.ru": [f"v=DKIM1; k=rsa; p={dkim_key(1024)}"]}
    m = facts(domain="exoway.ru", dkim=["ew"], dkim_given=["ew"], raw=raw)
    assert dkim_strength_check(m).status is Status.WARN


def test_dkim_selector_option_is_validated():
    from suveren.cli import dkim_selectors

    assert dkim_selectors(["ew", "s1.mail", "EW", "ew"]) == ["ew", "s1.mail"]
    for bad in ["", "a b", "x/../y", "ew._domainkey", "a" * 64]:
        with pytest.raises(ValueError):
            dkim_selectors([bad])


def test_scan_passes_selectors_to_the_mail_module(monkeypatch):
    from suveren import cli

    seen = {}

    async def fake_scan(host, **kwargs):
        seen.update(kwargs)
        raise cli.SuverenError("stop")

    monkeypatch.setattr(cli, "run_scan", fake_scan)
    runner.invoke(app, ["scan", "exoway.ru", "--dkim-selector", "ew", "--no-report"])
    assert seen.get("dkim_selectors") == ["ew"]
