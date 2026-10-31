"""`suveren company` end to end offline: site -> ИНН -> ЕГРЮЛ -> registers -> report."""

import json
from datetime import date

import httpx
import pytest
from test_company import record
from typer.testing import CliRunner

import suveren.company as company_module
from suveren.cli import app
from suveren.errors import ModuleError
from suveren.registries import RknOperator
from suveren.sanctions import Entry, SanctionsIndex

SITE = (
    "<html><body><h1>Ромашка</h1><p>"
    + "Цветы с доставкой по Москве. " * 40
    + '</p><footer>ООО "Ромашка", ИНН 7707083893, ОГРН 1027700132195</footer></body></html>'
)


# Not a recording: the list's page could not be fetched outside Russia. Only its words
# matter to the search (ИНН, ОГРН, a full name in the text).
FEDSFM = (
    "<html><body><h1>Перечень террористов и экстремистов</h1><ol>"
    "<li>1. ПЕТРОВ ПЕТР ПЕТРОВИЧ*, 01.01.1970 г.р., г. ТВЕРЬ</li></ol></body></html>"
)


@pytest.fixture
def offline(monkeypatch, tmp_path):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path / "cache"))

    def handler(request):
        if request.url.host == "romashka.ru":
            return httpx.Response(200, text=SITE, headers={"content-type": "text/html"})
        if request.url.host == "www.fedsfm.ru":
            return httpx.Response(200, text=FEDSFM, headers={"content-type": "text/html"})
        raise AssertionError(f"a real request to {request.url}")

    def make_client(timeout, *, verify=True):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)

    async def whois_raw(domain, timeout):
        return "domain: ROMASHKA.RU\norg: ООО Ромашка\nregistrar: RU-CENTER-RU\n"

    async def egrul_search(client, query):
        return [record()]

    async def rkn_operator(client, inn):
        return RknOperator("77-15-000001", "ООО Ромашка", inn, "", date(2016, 1, 1), None)

    async def load_index(client, *, refresh=False):
        person = Entry("us", "1", "person", ["IVANOV, Ivan Ivanovich"], [], "RUSSIA-EO14024")
        return SanctionsIndex([person], copies={"us": "США (OFAC SDN), выгрузка от 30.10.2026"})

    for name, fake in {
        "make_client": make_client,
        "whois_raw": whois_raw,
        "egrul_search": egrul_search,
        "rkn_operator": rkn_operator,
        "load_index": load_index,
    }.items():
        monkeypatch.setattr(company_module, name, fake)


def test_company_from_a_domain(offline, tmp_path):
    out = tmp_path / "c.json"
    result = CliRunner().invoke(
        app,
        ["company", "romashka.ru", "--json", str(out), "-o", str(tmp_path / "c.html"), "--no-open"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    checks = {c["id"]: c for c in data["checks"]}
    assert data["inn"] == "7707083893"
    assert checks["SUV-CO-001"]["status"] == "ok"  # active in ЕГРЮЛ
    assert checks["SUV-CO-006"]["status"] == "ok"  # in the operators' register
    assert checks["SUV-CO-006"]["law"] == "152-ФЗ, ст. 22"

    # Every register answer says where and when it came from, in JSON and in HTML.
    def where(cid):
        return [e["value"] for e in checks[cid]["evidence"] if e["what"] == "Источник"]

    assert where("SUV-CO-001")[0].startswith("ЕГРЮЛ (egrul.nalog.ru), запрос от ")
    assert where("SUV-CO-006")[0].startswith("Реестр операторов ПДн Роскомнадзора")
    assert checks["SUV-CO-008"]["status"] == "ok"
    assert where("SUV-CO-008")[0].startswith("Перечень террористов и экстремистов")
    assert any("пока не проверяет" in n for n in data["notes"])
    assert "США (OFAC SDN), выгрузка от 30.10.2026" in where("SUV-CO-003")
    html = (tmp_path / "c.html").read_text(encoding="utf-8")
    assert "Источник: ЕГРЮЛ (egrul.nalog.ru), запрос от " in html
    # The director's name matches a sanctioned person: a lead to check, not a verdict.
    assert checks["SUV-CO-004"]["status"] in ("warn", "fail")
    assert (tmp_path / "c.html").read_text(encoding="utf-8").count("7707083893") >= 1


def test_company_by_inn_when_egrul_is_down(offline, monkeypatch, tmp_path):
    async def egrul_down(client, query):
        raise ModuleError("ФНС не ответила")

    monkeypatch.setattr(company_module, "egrul_search", egrul_down)
    out = tmp_path / "c.json"
    result = CliRunner().invoke(
        app,
        ["company", "7707083893", "--no-sanctions", "--json", str(out), "--no-report"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert any("ЕГРЮЛ: ФНС не ответила" in n for n in data["notes"])
    statuses = {c["id"]: c["status"] for c in data["checks"]}
    # A register that did not answer is "not checked", not "the company does not exist".
    assert statuses["SUV-CO-001"] == "unknown"
    assert "не найдена" not in result.output and "ЕСТЬ ПРОБЛЕМЫ" not in result.output


def test_company_when_the_operators_register_is_down(offline, monkeypatch, tmp_path):
    async def rkn_down(client, inn):
        raise ModuleError("pd.rkn.gov.ru недоступен (ConnectError)")

    monkeypatch.setattr(company_module, "rkn_operator", rkn_down)
    out = tmp_path / "c.json"
    result = CliRunner().invoke(
        app,
        ["company", "7707083893", "--no-sanctions", "--json", str(out), "--no-report"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    checks = {c["id"]: c for c in json.loads(out.read_text(encoding="utf-8"))["checks"]}
    assert checks["SUV-CO-001"]["status"] == "ok"
    assert checks["SUV-CO-006"]["status"] == "unknown"
    assert "ConnectError" not in checks["SUV-CO-006"]["details"]
