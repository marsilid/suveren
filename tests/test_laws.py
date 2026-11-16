"""Laws as data (data/laws.json) and the weekly text check (tools/check_laws.py)."""

import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

import httpx

from suveren.catalog import BY_ID
from suveren.checks import LAW_URLS
from suveren.laws import fingerprint, laws, provisions_for

_spec = importlib.util.spec_from_file_location(
    "check_laws", Path(__file__).parent.parent / "tools" / "check_laws.py"
)
cl = importlib.util.module_from_spec(_spec)
sys.modules["check_laws"] = cl
_spec.loader.exec_module(cl)


def test_every_law_has_a_url_and_its_provisions_name_real_checks():
    ids = {law.id for law in laws()}
    assert {"152-ФЗ", "149-ФЗ", "КоАП", "ЗоЗПП", "38-ФЗ"} <= ids
    for law in laws():
        assert law.url.startswith("https://") and law.provisions
        for p in law.provisions:
            assert p.checks and all(c in BY_ID for c in p.checks), (law.id, p.article)
    assert LAW_URLS["152-ФЗ"].startswith("https://www.consultant.ru/")


def test_provisions_and_dates():
    [(_law, p)] = [x for x in provisions_for("SUV-LAW-001") if x[0].id == "149-ФЗ"]
    assert p.effective_from == date(2026, 7, 7)
    assert not p.in_force(date(2026, 7, 6)) and p.in_force(date(2026, 7, 7))
    assert provisions_for("SUV-PD-007")[0][1].article == "ст. 18 ч. 5"


def test_fingerprint_ignores_markup_but_not_words():
    a = "<html><script>x=1</script><p>Статья 9.  Согласие</p></html>"
    b = "<div><p>Статья 9. Согласие</p><style>p{}</style></div>"
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a) != fingerprint("<p>Статья 9. Отказ</p>")


def _data():
    return {
        "laws": [
            {"id": "A", "url": "https://x.example/a", "provisions": [{"article": "ст. 1"}],
             "text_sha256": None},
            {"id": "B", "url": "https://x.example/b", "provisions": [{"article": "ст. 2"}],
             "text_sha256": fingerprint("<p>старый текст</p>")},
            {"id": "C", "url": "https://x.example/c", "provisions": [], "text_sha256": None},
        ]
    }  # fmt: skip


def test_check_laws_reports_new_changed_and_unloaded():
    def handler(request):
        if request.url.path == "/c":
            return httpx.Response(503)
        return httpx.Response(200, text="<p>новый текст</p>")

    data = _data()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        lines, code = cl.check(client, data, write=False, pause=0)
    assert lines[0] == "A: отпечаток снят впервые"
    assert lines[1] == "B: ТЕКСТ ИЗМЕНИЛСЯ — перечитайте ст. 2"
    assert lines[2].startswith("C: не загрузился") and code == 1
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        cl.check(client, data, write=True, pause=0)
    assert data["laws"][0]["text_sha256"] == fingerprint("<p>новый текст</p>")
    assert data["laws"][0]["checked"]


def test_a_timeout_is_tried_again_and_a_missing_page_is_not():
    calls: dict[str, int] = {}

    def handler(request):
        path = request.url.path
        calls[path] = calls.get(path, 0) + 1
        if path == "/slow" and calls[path] < 3:
            raise httpx.ReadTimeout("The read operation timed out", request=request)
        if path == "/gone":
            return httpx.Response(404)
        return httpx.Response(200, text="<p>текст</p>")

    data = {
        "laws": [
            {"id": "S", "url": "https://x.example/slow", "provisions": [], "text_sha256": None},
            {"id": "G", "url": "https://x.example/gone", "provisions": [], "text_sha256": None},
        ]
    }  # fmt: skip
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        lines, code = cl.check(client, data, write=False, pause=0)
    assert lines[0] == "S: отпечаток снят впервые" and calls["/slow"] == 3
    assert lines[1].startswith("G: не загрузился") and calls["/gone"] == 1
    assert code == 1


def test_a_law_that_keeps_timing_out_still_fails_the_run():
    def handler(request):
        raise httpx.ReadTimeout("The read operation timed out", request=request)

    law = {"id": "T", "url": "https://x.example/t", "provisions": [], "text_sha256": None}
    data = {"laws": [law]}
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        lines, code = cl.check(client, data, write=False, attempts=2, pause=0)
    assert lines[0].startswith("T: не загрузился (The read operation timed out)") and code == 1


def test_laws_file_is_valid_json_with_the_fields():
    raw = json.loads(
        (Path(__file__).parent.parent / "src/suveren/data/laws.json").read_text("utf-8")
    )
    for law in raw["laws"]:
        assert {"id", "title", "url", "edition", "provisions", "text_sha256"} <= set(law)
