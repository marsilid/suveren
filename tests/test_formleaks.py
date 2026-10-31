import asyncio
import base64
import gzip
import hashlib
import json
from typing import ClassVar
from urllib.parse import quote

import pytest
from typer.testing import CliRunner

from suveren import formleaks, scan
from suveren.catalog import SelectionError
from suveren.checks import Status
from suveren.cli import app
from suveren.collect import Facts
from suveren.crawl import FetchedPage
from suveren.cutoff import HostInfo
from suveren.formleaks import (
    BASE64,
    PACKED,
    PLAIN,
    Canaries,
    FormLeaks,
    Leak,
    find_leaks,
    leak_check,
    own_phone,
    pages_with_fields,
    run_form_leaks,
)
from suveren.models import Report
from suveren.plan import Profile, make_plan
from suveren.render import FormProbe, Sent

C = Canaries(
    email="suveren.k3m9x2ab7q@example.com",
    phone="1002703508",
    password="Sv-tie44yfmsc!",
    name="Тест Зодуваке",
)
ALL = [
    {"i": 0, "kind": "name", "visible": True, "label": "Имя", "value": C.name},
    {"i": 1, "kind": "phone", "visible": True, "label": "Телефон", "value": "+7 (100) 270-35-08"},
    {"i": 2, "kind": "email", "visible": False, "label": "email", "value": C.email},
    {"i": 3, "kind": "password", "visible": True, "label": "Пароль", "value": C.password},
]
METRIKA = HostInfo("mc.yandex.ru", "Яндекс Метрика", "RU")
CLARITY = HostInfo("k.clarity.ms", "Microsoft Clarity", "US")


def probe(*sent: Sent, filled=None, url="https://shop.ru/contacts") -> FormProbe:
    return FormProbe(url, url, list(ALL if filled is None else filled), list(sent))


def kinds(p: FormProbe) -> set[tuple[str, str]]:
    return {(x.kind, x.how) for x in find_leaks(p, C)}


def test_canaries_reach_nobody_and_differ_every_run():
    a, b = Canaries.new(), Canaries.new()
    assert a.email.endswith("@example.com") and a != b
    assert a.phone.startswith("100") and len(a.phone) == 10 and a.phone.isdigit()
    assert set(a.values()) == {"name", "phone", "email", "password"}


def test_values_in_the_clear_url_encoded_and_in_json_escapes():
    p = probe(
        Sent(f"https://mc.yandex.ru/watch/1?e={quote(C.email)}"),
        Sent("https://k.clarity.ms/collect", "POST", json.dumps({"v": C.name}).encode()),
        Sent("https://in.hotjar.com/r", "POST", b"phone=%2B7+(100)+270-35-08"),
    )
    assert kinds(p) == {("email", PLAIN), ("name", PLAIN), ("phone", PLAIN)}


def test_base64_inside_a_longer_blob_at_any_offset():
    for prefix in (b"", b"x", b"xy"):
        blob = base64.b64encode(prefix + b'{"f":"' + C.email.encode() + b'","t":1}').decode()
        p = probe(Sent("https://rec.example.net/r", "POST", ("data=" + blob).encode()))
        assert ("email", BASE64) in kinds(p), prefix


def test_compressed_and_hashed_values():
    packed = gzip.compress(json.dumps({"fields": [C.password]}).encode())
    sha = hashlib.sha256(C.email.encode()).hexdigest()
    md5 = hashlib.md5(("7" + C.phone).encode()).hexdigest()
    p = probe(
        Sent("https://rec.example.net/r", "POST", packed),
        Sent(f"https://px.example.net/tr?em={sha}"),
        Sent("https://px.example.net/tr", "POST", f"ph={md5}".encode()),
    )
    assert kinds(p) == {
        ("password", PACKED),
        ("email", "в виде хеша SHA-256"),
        ("phone", "в виде хеша MD5"),
    }


def test_websocket_frames_count_too():
    p = probe(Sent("wss://chat.example.net/ws", "WS", C.email.encode(), websocket=True))
    assert [x.host for x in find_leaks(p, C)] == ["chat.example.net"]


def test_only_typed_fields_count_and_digits_alone_are_not_a_phone():
    # The phone mask changed the number, so the field was erased: nothing to find.
    erased = [dict(ALL[1], value="")]
    p = probe(Sent(f"https://x.example.net/?p={C.phone}"), filled=erased)
    assert find_leaks(p, C) == []
    # The number's digits inside a longer number are not the phone.
    p = probe(Sent(f"https://x.example.net/?ts=9{C.phone}1"))
    assert find_leaks(p, C) == []


def test_one_leak_per_host_kind_and_form():
    sent = Sent(f"https://mc.yandex.ru/watch?e={C.email}")
    leaks = find_leaks(probe(sent, sent), C)
    assert len(leaks) == 1 and leaks[0].page == "https://shop.ru/contacts"


def result(*leaks: Leak, own=(), hosts=None, filled=None) -> FormLeaks:
    return FormLeaks(
        pages=[probe(filled=filled)],
        leaks=list(leaks),
        own=list(own),
        hosts=hosts if hosts is not None else {h.host: h for h in (METRIKA, CLARITY)},
    )


def leak(kind: str, host: str = "mc.yandex.ru", how: str = PLAIN) -> Leak:
    return Leak("https://shop.ru/contacts", kind, host, "POST", f"https://{host}/r", how)


def test_verdicts():
    nothing = leak_check(FormLeaks())
    assert nothing.status is Status.UNKNOWN
    no_fields = leak_check(result(filled=[]))
    assert no_fields.status is Status.UNKNOWN and "не нашлось полей" in no_fields.details
    clean = leak_check(result())
    assert clean.status is Status.OK and "4 поля" in clean.details
    assert "не получили" in clean.details and "Формы не отправлялись" in clean.details
    ru = leak_check(result(leak("phone"), leak("email")))
    assert ru.status is Status.WARN
    assert "Яндекс Метрика (Россия) — телефон, почта (открытым текстом)" in ru.details
    assert "ym-disable-keys" in ru.recommendation and "ст. 7" in ru.recommendation
    assert "трансграничная" not in ru.recommendation
    abroad = leak_check(result(leak("email", "k.clarity.ms", "в base64")))
    assert abroad.status is Status.FAIL and "трансграничная" in abroad.recommendation
    assert "ym-disable-keys" not in abroad.recommendation
    password = leak_check(result(leak("password")))
    assert password.status is Status.FAIL and "захвата учётных записей" in password.recommendation


def test_a_phone_the_mask_rejected_is_said_not_hidden():
    erased = dict(ALL[1], value="")
    check = leak_check(result(filled=[ALL[0], erased]))
    assert check.status is Status.OK and "1 поле (имя)" in check.details
    assert "Телефон проверить не удалось" in check.details
    only_phone = leak_check(result(filled=[erased]))
    assert only_phone.status is Status.UNKNOWN and "маска поля" in only_phone.details


def test_the_site_itself_reading_fields_is_said_but_is_not_a_leak():
    own = leak("phone", "shop.ru")
    check = leak_check(result(own=[own]))
    assert check.status is Status.OK and "Сам сайт получает введённое" in check.details


def test_many_recipients_are_cut_and_an_unknown_host_is_named():
    leaks = [leak("email", f"t{i}.example.net") for i in range(7)]
    check = leak_check(result(*leaks, hosts={}))
    assert check.status is Status.WARN and "и ещё 2" in check.details
    assert "t0.example.net — почта" in check.details


def test_pages_with_fields():
    pages = [
        ("https://a.ru/about", "<p>О нас</p>"),
        ("https://a.ru/contacts", '<input type="tel" name="phone">'),
        ("https://a.ru/login", "<input type=password>"),
        ("https://a.ru/order", '<input name="client_email">'),
    ]
    assert pages_with_fields("https://a.ru/", pages) == [
        "https://a.ru/",
        "https://a.ru/contacts",
        "https://a.ru/login",
    ]
    # The sign-in page found by its link goes first, whatever its HTML says.
    assert pages_with_fields("https://a.ru/", pages, "https://a.ru/auth") == [
        "https://a.ru/",
        "https://a.ru/auth",
        "https://a.ru/contacts",
    ]


def test_the_experiment_runs_only_with_its_flag():
    assert "formleaks" not in make_plan().modules
    assert "formleaks" not in make_plan(Profile.deep).modules
    # Only on the owner's site (1.3): the experiment types into forms.
    with pytest.raises(SelectionError, match="--own-site"):
        make_plan(form_leaks=True)
    assert "formleaks" in make_plan(form_leaks=True, own_site=True).modules
    plan = make_plan(Profile.quick, "SUV-PD-012", form_leaks=True, own_site=True)
    assert "formleaks" in plan.modules
    assert "formleaks" not in make_plan(checks="pd").modules
    with pytest.raises(SelectionError, match="--form-leaks"):
        make_plan(checks="SUV-PD-012")


class FakeSession:
    pages: ClassVar[dict[str, FormProbe]] = {}

    def __init__(self, timeout: float) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def fill_forms(self, url, values):
        if url not in self.pages:
            raise formleaks.ModuleError(f"браузер не открыл {url}")
        return self.pages[url]


def test_run_sorts_own_from_third_parties_and_classifies(monkeypatch):
    home = FormProbe(
        "https://shop.ru/",
        "https://www.shop.ru/",
        list(ALL),
        [
            Sent(f"https://mc.yandex.ru/webvisor/1?e={C.email}"),
            Sent("https://www.shop.ru/api/draft", "POST", C.name.encode()),
        ],
    )
    FakeSession.pages = {"https://shop.ru/": home}
    monkeypatch.setattr("suveren.render.BrowserSession", FakeSession)
    check, r, facts = asyncio.run(
        run_form_leaks(["https://shop.ru/", "https://shop.ru/gone"], "shop.ru", None, canaries=C)
    )
    assert check.status is Status.WARN
    assert [x.host for x in r.leaks] == ["mc.yandex.ru"] and [x.kind for x in r.own] == ["name"]
    assert r.errors == ["браузер не открыл https://shop.ru/gone"]
    assert facts["leaks"][0]["service"] == "Яндекс Метрика"
    assert facts["leaks"][0]["foreign"] is False
    assert facts["values"]["email"] == C.email and facts["pages"][0]["fields"][3]["typed"]


def test_scan_stage_never_takes_the_scan_down(monkeypatch):
    facts = Facts(host="shop.ru", domain="shop.ru")
    report = Report("shop.ru")
    # No page: not checked, without opening a browser.
    check = asyncio.run(scan._form_leaks(None, facts, report, "shop.ru", "auto", 5.0))
    assert check.status is Status.UNKNOWN and check.id == "SUV-PD-012"

    facts.html = '<a href="/login">Войти</a>'
    facts.final_url = "https://shop.ru/"
    facts.extra_pages = [FetchedPage("https://shop.ru/c", 200, "<input type=email>")]
    seen = {}

    async def fake_resolver(mode, timeout, client):
        return None, None

    async def fake_run(urls, site, collector, *, timeout, phone):
        seen["urls"], seen["phone"] = urls, phone
        return leak_check(result(leak("email", "k.clarity.ms"))), None, {"leaks": [1]}

    monkeypatch.setattr(scan, "create_resolver", fake_resolver)
    monkeypatch.setattr(scan, "run_form_leaks", fake_run)
    check = asyncio.run(scan._form_leaks(None, facts, report, "shop.ru", "auto", 5.0))
    assert check.status is Status.FAIL and report.facts["form_leaks"] == {"leaks": [1]}
    assert seen["urls"] == ["https://shop.ru/", "https://shop.ru/login", "https://shop.ru/c"]

    async def broken(*args, **kwargs):
        raise RuntimeError("Target closed")

    # Behind a bot wall over plain HTTP: the browser still tries, with the owner's number.
    facts.page_status = 401
    assert facts.page_problem
    asyncio.run(scan._form_leaks(None, facts, report, "shop.ru", "auto", 5.0, "9991234567"))
    assert seen["phone"] == "9991234567"

    monkeypatch.setattr(scan, "run_form_leaks", broken)
    check = asyncio.run(scan._form_leaks(None, facts, report, "shop.ru", "auto", 5.0))
    assert check.status is Status.UNKNOWN and "ошибка браузера" in check.details


def test_cli_warns_before_typing_into_forms(monkeypatch):
    calls = {}

    async def fake_run_scan(host, **kwargs):
        calls.update(kwargs)
        return Report(host)

    monkeypatch.setattr("suveren.cli.run_scan", fake_run_scan)
    _owned(monkeypatch)
    no_proof = CliRunner().invoke(app, ["scan", "example.ru", "--no-report", "--form-leaks"])
    assert no_proof.exit_code == 2 and "--own-site" in no_proof.output
    result = CliRunner().invoke(
        app, ["scan", "example.ru", "--no-report", "--own-site", "--form-leaks"]
    )
    assert result.exit_code == 0, result.output
    assert calls["formleaks"] and "Эксперимент с формами" in result.output


def _owned(monkeypatch):
    """The ownership proof passes (it is tested in test_ownsite.py)."""
    from suveren.ownership import Proof

    async def proved(host, timeout):
        return Proof(True, "TXT-запись")

    monkeypatch.setattr("suveren.cli._prove_ownership", proved)


def test_owner_phone():
    assert own_phone("+7 (999) 123-45-67") == own_phone("89991234567") == "9991234567"
    for bad in ("+1 202 555 0100", "84951234567", "12345"):
        with pytest.raises(ValueError, match="--form-phone"):
            own_phone(bad)
    c = Canaries.new("9991234567")
    assert c.phone == "9991234567" and c.shown()["phone"] == "999*****67"
    assert Canaries.new().shown()["phone"].startswith("100")


def test_cli_form_phone_needs_the_experiment_and_a_mobile_number(monkeypatch):
    calls = {}

    async def fake_run_scan(host, **kwargs):
        calls.update(kwargs)
        return Report(host)

    monkeypatch.setattr("suveren.cli.run_scan", fake_run_scan)
    _owned(monkeypatch)
    runner = CliRunner()
    alone = runner.invoke(
        app, ["scan", "example.ru", "--no-report", "--form-phone", "+79991234567"]
    )
    assert alone.exit_code == 2 and "--form-leaks" in alone.output
    bad = runner.invoke(
        app,
        ["scan", "example.ru", "--no-report", "--own-site", "--form-leaks", "--form-phone", "1"],
    )
    assert bad.exit_code == 2
    ok = runner.invoke(
        app,
        [
            "scan",
            "example.ru",
            "--no-report",
            "--own-site",
            "--form-leaks",
            "--form-phone",
            "89991234567",
        ],
    )
    assert ok.exit_code == 0 and calls["form_phone"] == "9991234567"


def test_gzip_bomb_is_unpacked_no_further_than_the_limit():
    import gzip

    from suveren.formleaks import _MAX_UNPACKED, _unpack

    bomb = gzip.compress(b"\0" * (50 * 1024 * 1024))
    unpacked = _unpack(bomb)
    assert unpacked is not None and len(unpacked) <= _MAX_UNPACKED
