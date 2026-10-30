"""`--browser` mode: open pages in a real browser via Playwright.

This sees what plain HTTP cannot: pages built by JavaScript, cookie banners,
and every script, font and widget a page loads at runtime (including ones
injected by tag managers). A browser that is already installed (Edge, Chrome)
is used, so no extra download is needed; Playwright's own Chromium is the
fallback. One browser session serves the home page and the extra pages.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from suveren.errors import ModuleError

INSTALL_HINT = (
    "для режима --browser установите Playwright: pip install playwright "
    "(нужен Edge или Chrome; иначе ещё playwright install chromium)"
)
CHANNELS = ("msedge", "chrome", None)  # None = Playwright's bundled Chromium
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
SETTLE_MS = 8000
EXTRA_SETTLE_MS = 4000
SCROLL_SETTLE_MS = 2500


@dataclass(slots=True)
class Rendered:
    final_url: str
    status: int | None
    html: str
    requests: list[str] = field(default_factory=list)
    initiators: dict[str, str] = field(default_factory=dict)  # see Facts.initiators
    headers: dict[str, str] = field(default_factory=dict)  # the page's response headers


def initiator_url(initiator: dict[str, Any]) -> str:
    """The script that started a request, from a DevTools initiator: the first frame of
    the call stack (or of a parent stack, for async loads) that has a URL; "" when the
    page's HTML started it."""
    if initiator.get("type") != "script":
        return ""
    stack = initiator.get("stack")
    while stack:
        for frame in stack.get("callFrames", []):
            if frame.get("url"):
                return str(frame["url"])
        stack = stack.get("parent")
    return str(initiator.get("url") or "")


@dataclass(slots=True)
class Probe:
    """One page load of the cutoff experiment."""

    url: str
    final_url: str = ""
    status: int | None = None
    html: str = ""
    requests: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)  # uncaught JavaScript exceptions
    dom: dict[str, Any] = field(default_factory=dict)  # see _DOM_FEATURES
    screenshot: bytes = b""
    ready_ms: int = 0  # until DOMContentLoaded
    stuck: bool = False  # hang mode: DOMContentLoaded did not come within HANG_WAIT_MS
    # Hang mode: the browser painted any content (first-contentful-paint), None if unknown.
    # Read before anything else touches the page: innerText is empty while rendering is
    # blocked, and a screenshot may force a frame the visitor would not get.
    painted: bool | None = None


@dataclass(slots=True)
class Sent:
    """One request (or WebSocket frame) the page sent after the fields were filled."""

    url: str
    method: str = "GET"
    body: bytes = b""
    websocket: bool = False


@dataclass(slots=True)
class FormProbe:
    """One page of the form-leak experiment (formleaks.py)."""

    url: str
    final_url: str = ""
    filled: list[dict[str, Any]] = field(default_factory=list)  # see _FIND_FIELDS
    sent: list[Sent] = field(default_factory=list)
    submits: int = 0  # submit attempts the page made and the probe stopped


# How long the page is watched after typing: session recorders send in batches.
FORM_WATCH_MS = 7000
# Then the page is left, which flushes what recorders keep for "pagehide".
FORM_FLUSH_MS = 2000
MAX_FIELDS = 12

# Nothing typed during the experiment may be sent by the form itself: submit events are
# cancelled before the site's own handlers see them, and form.submit() does nothing.
_NO_SUBMIT = """(() => {
  window.__suverenSubmits = 0;
  const stop = (e) => { window.__suverenSubmits += 1; e.preventDefault();
    e.stopImmediatePropagation(); };
  window.addEventListener('submit', stop, true);
  HTMLFormElement.prototype.submit = function () { window.__suverenSubmits += 1; };
  HTMLFormElement.prototype.requestSubmit = function () { window.__suverenSubmits += 1; };
})();"""

# What scripts send, seen from inside the page. The network view misses the body of a
# beacon made of a Blob and anything sent while the page unloads; so sendBeacon, fetch,
# XMLHttpRequest and WebSocket hand a copy of each body (base64) to the probe, at once,
# through the __suverenKeep binding: a page that navigates away loses nothing.
_SENT_HOOK = """(() => {
  let count = 0;
  const MAX = 2000000;
  const b64 = (bytes) => {
    let s = '';
    for (let i = 0; i < bytes.length; i += 8192) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
    }
    return btoa(s);
  };
  const put = (method, url, bytes) => {
    if (count < 600 && bytes && bytes.length && window.__suverenKeep) {
      count += 1;
      try { window.__suverenKeep(method, String(url), b64(bytes.subarray(0, MAX))); }
      catch (e) { /* the page is closing */ }
    }
  };
  const keep = (method, url, body) => {
    try {
      url = new URL(String(url), location.href).href;
      if (body == null) return;
      if (typeof body === 'string' || body instanceof URLSearchParams) {
        put(method, url, new TextEncoder().encode(String(body)));
      } else if (body instanceof Blob) {
        body.arrayBuffer().then((b) => put(method, url, new Uint8Array(b)), () => {});
      } else if (body instanceof ArrayBuffer) {
        put(method, url, new Uint8Array(body));
      } else if (ArrayBuffer.isView(body)) {
        put(method, url, new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
      } else if (body instanceof FormData) {
        const parts = [];
        body.forEach((v, k) => parts.push(k + '=' + (typeof v === 'string' ? v : '')));
        put(method, url, new TextEncoder().encode(parts.join('&')));
      }
    } catch (e) { /* never break the page */ }
  };
  const beacon = navigator.sendBeacon;
  if (beacon) {
    navigator.sendBeacon = function (url, data) {
      keep('POST', url, data);
      return beacon.apply(this, arguments);
    };
  }
  const fetch0 = window.fetch;
  if (fetch0) {
    window.fetch = function (input, init) {
      try {
        if (init && init.body != null) keep((init.method || 'POST').toUpperCase(),
          input instanceof Request ? input.url : input, init.body);
        else if (input instanceof Request && input.body) {
          input.clone().arrayBuffer().then((b) => put(input.method, input.url,
            new Uint8Array(b)), () => {});
        }
      } catch (e) { /* never break the page */ }
      return fetch0.apply(this, arguments);
    };
  }
  const open = XMLHttpRequest.prototype.open;
  const send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__suverenTo = [String(method).toUpperCase(), url];
    return open.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    if (this.__suverenTo) keep(this.__suverenTo[0], this.__suverenTo[1], body);
    return send.apply(this, arguments);
  };
  const wsSend = WebSocket.prototype.send;
  WebSocket.prototype.send = function (data) {
    keep('WS', this.url, data);
    return wsSend.apply(this, arguments);
  };
})();"""

# A headless tab can't be hidden, so the probe says it was: recorders send what they
# hold when the visitor leaves (visibilitychange to hidden, pagehide), and the page
# stays alive for _SENT_HOOK to see it.
_HIDE = """() => {
  Object.defineProperty(document, 'visibilityState', {configurable: true, get: () => 'hidden'});
  Object.defineProperty(document, 'hidden', {configurable: true, get: () => true});
  document.dispatchEvent(new Event('visibilitychange'));
  window.dispatchEvent(new PageTransitionEvent('pagehide', {persisted: false}));
}"""

# Fields a visitor types personal data into, in the main document: name, phone, e-mail
# and password. Card, code and search fields are never touched. Each field found is
# marked with data-suveren-field so the probe can find it again.
_FIND_FIELDS = """(limit) => {
  const vis = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 4 && r.height > 4 && s.visibility !== 'hidden' && s.display !== 'none'
      && Number(s.opacity) > 0.05;
  };
  const labelOf = (el) => {
    let t = '';
    if (el.id) {
      const l = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
      if (l) t = l.innerText;
    }
    if (!t && el.closest('label')) t = el.closest('label').innerText;
    return (t || '').replace(/\\s+/g, ' ').trim().slice(0, 60);
  };
  const NOT_PD = new RegExp([
    'card|gift|promo|coupon|otp|sms|cvv|cvc|captcha|code|amount|qty|quantity',
    'city|town|station|airport|country|region|hotel|product|goods|item|file|search|query',
    'company|(^|[^a-z])inn([^a-z]|$)|address|street|zip|postal',
    'индекс|город|адрес|компани|организац|код',
  ].join('|'), 'i');
  const kindOf = (el) => {
    const type = (el.getAttribute('type') || 'text').toLowerCase();
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
    const label = labelOf(el);
    const hint = [el.name, el.id, el.placeholder, el.getAttribute('aria-label'), label]
      .join(' ').toLowerCase();
    if (/cc-|card|one-time-code/.test(ac)) return '';
    if (type === 'password') return 'password';
    if (!['text', 'email', 'tel'].includes(type)) return '';
    if (type === 'email' || ac === 'email'
        || /e-?mail|почт(а|ы|у|ой)?(\\s|\\*|:|$)|электронн/.test(hint)) return 'email';
    if (NOT_PD.test(hint)) return '';
    if (type === 'tel' || ac.startsWith('tel')
        || /phone|телефон|mobile|(^|[^a-z])tel([^a-z]|$)/.test(hint)) return 'phone';
    if (/^(name|given-name|family-name|additional-name)$/.test(ac)
        || /(^|[^a-z])(name|fio|first_?name|last_?name)([^a-z]|$)|имя|фио|фамили/.test(hint)) {
      return 'name';
    }
    return '';
  };
  const found = [];
  document.querySelectorAll('input, textarea').forEach((el) => {
    if (el.tagName === 'TEXTAREA' || el.disabled || el.readOnly) return;
    const form = el.closest('form');
    if (form && (form.getAttribute('role') === 'search')) return;
    const kind = kindOf(el);
    if (kind) found.push({el, kind, visible: vis(el), label: labelOf(el)
      || el.placeholder || el.getAttribute('aria-label') || el.name || ''});
  });
  // Visible fields first: what a visitor would type into without opening anything.
  found.sort((a, b) => Number(b.visible) - Number(a.visible));
  return found.slice(0, limit).map((f, i) => {
    f.el.setAttribute('data-suveren-field', String(i));
    return {i, kind: f.kind, visible: f.visible, label: f.label.slice(0, 60)};
  });
}"""


def _digits(text: str) -> str:
    return "".join(c for c in text if c.isdigit())


# A field that can't be typed into (inside a closed pop-up) gets its value set the way
# a framework sees it: the native setter and an input event. Change and blur come after
# the value is checked (_LEAVE), as when a visitor moves on to the next field.
_SET_VALUE = """(el, value) => {
  const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value').set;
  if (el.focus) el.focus();
  setter.call(el, value);
  el.dispatchEvent(new Event('input', {bubbles: true}));
  return el.value;
}"""
_LEAVE = """(el) => {
  el.dispatchEvent(new Event('change', {bubbles: true}));
  // A focused field gets a real blur; a hidden one, which can't hold focus, an event.
  if (document.activeElement === el) el.blur();
  else el.dispatchEvent(new FocusEvent('blur'));
}"""


# Hang mode of the cutoff: a block often drops packets instead of refusing, so the
# browser waits. Requests are held this long, past the moment the page is measured.
HANG_WAIT_MS = 10000
HANG_HOLD_S = HANG_WAIT_MS / 1000 + 8


# What a visitor can see and use, collected in the page. Only visible elements count:
# a hidden mobile menu that "vanishes" is not a finding.
_DOM_FEATURES = """() => {
  const vis = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 4 && r.height > 4 && s.visibility !== 'hidden' && s.display !== 'none'
      && Number(s.opacity) > 0.05;
  };
  const host = (u) => {
    try { return new URL(u, location.href).hostname; } catch (e) { return ''; }
  };
  const label = (el) => (el.innerText || el.value || el.getAttribute('aria-label') || '')
    .replace(/\\s+/g, ' ').trim().slice(0, 60);
  const controls = new Set();
  document.querySelectorAll('button, a[href], input[type=submit], [role=button]').forEach((el) => {
    const t = label(el);
    if (t && t.length > 1 && vis(el)) controls.add(t);
  });
  const frames = [];
  document.querySelectorAll('iframe').forEach((f) => {
    const r = f.getBoundingClientRect();
    if (vis(f) && r.width * r.height > 4000) frames.push(host(f.src || ''));
  });
  let broken = 0, images = 0;
  document.querySelectorAll('img').forEach((img) => {
    if (!vis(img)) return;
    images += 1;
    if (img.complete && img.naturalWidth === 0) broken += 1;
  });
  const forms = [];
  document.querySelectorAll('form').forEach((f) => {
    if (!vis(f)) return;
    const html = f.innerHTML.toLowerCase();
    forms.push({
      fields: f.querySelectorAll('input:not([type=hidden]), textarea, select').length,
      // Only foreign captcha providers: the site's own captcha and Yandex SmartCaptcha
      // keep working when foreign services are cut off.
      captcha: /g-recaptcha|recaptcha/.test(html) ? 'recaptcha'
        : /h-captcha|hcaptcha/.test(html) ? 'hcaptcha'
        : /cf-turnstile|turnstile/.test(html) ? 'turnstile' : '',
    });
  });
  const fonts = [];
  document.fonts.forEach((ff) => {
    if (ff.status === 'loaded') fonts.push(ff.family.replace(/["']/g, ''));
  });
  return {
    controls: [...controls].slice(0, 400),
    frames, images, broken, forms,
    fonts: [...new Set(fonts)],
    text: (document.body ? document.body.innerText : '').length,
    height: document.documentElement.scrollHeight,
  };
}"""

_PAINTED = """() => performance.getEntriesByType('paint')
    .some(e => e.name === 'first-contentful-paint')"""

_IMAGE_DIFF = """async ([a, b]) => {
  const load = (src) => new Promise((ok, fail) => {
    const img = new Image(); img.onload = () => ok(img); img.onerror = fail; img.src = src;
  });
  const [x, y] = await Promise.all([load(a), load(b)]);
  const w = Math.min(x.width, y.width), h = Math.min(x.height, y.height);
  const pixels = (img) => {
    const c = document.createElement('canvas'); c.width = w; c.height = h;
    const ctx = c.getContext('2d'); ctx.drawImage(img, 0, 0);
    return ctx.getImageData(0, 0, w, h).data;
  };
  const p = pixels(x), q = pixels(y);
  let diff = 0;
  for (let i = 0; i < p.length; i += 4) {
    const d = Math.abs(p[i] - q[i]) + Math.abs(p[i + 1] - q[i + 1]) + Math.abs(p[i + 2] - q[i + 2]);
    if (d > 60) diff += 1;   // JPEG noise stays below this
  }
  return diff / (w * h);
}"""


class BrowserSession:
    """``async with BrowserSession() as b: page = await b.open(url)``."""

    def __init__(self, *, timeout: float = 25.0) -> None:
        self.timeout = timeout
        self.browser_name = ""
        self._pw_cm: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._error: type[Exception] = Exception

    async def __aenter__(self) -> BrowserSession:
        try:
            from playwright.async_api import Error as PlaywrightError
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise ModuleError(INSTALL_HINT) from exc
        self._error = PlaywrightError
        self._pw_cm = async_playwright()
        pw = await self._pw_cm.__aenter__()
        for channel in CHANNELS:
            try:
                self._browser = await pw.chromium.launch(
                    channel=channel,
                    headless=True,
                    args=["--disable-blink-features=AutomationControlled"],
                )
                self.browser_name = channel or "chromium"
                break
            except PlaywrightError:
                continue
        if self._browser is None:
            await self._pw_cm.__aexit__(None, None, None)
            raise ModuleError("не найден браузер: установите Edge или Chrome, " + INSTALL_HINT)
        self._context = await self._browser.new_context(
            user_agent=USER_AGENT,
            locale="ru-RU",
            viewport={"width": 1366, "height": 900},
            ignore_https_errors=True,
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        with contextlib.suppress(Exception):
            await self._browser.close()
        with contextlib.suppress(Exception):
            await self._pw_cm.__aexit__(None, None, None)

    async def open(
        self, url: str, *, settle_ms: int = SETTLE_MS, initiators: bool = False
    ) -> Rendered:
        """``initiators``: also record who started each script request (DevTools
        protocol, Chromium only; silently skipped if unavailable)."""
        page = await self._context.new_page()
        requests: list[str] = []
        started_by: dict[str, str] = {}
        page.on("request", lambda req: requests.append(req.url))
        if initiators:

            def on_request(params: dict[str, Any]) -> None:
                if params.get("type") == "Script":
                    target = params.get("request", {}).get("url", "")
                    started_by.setdefault(target, initiator_url(params.get("initiator", {})))

            with contextlib.suppress(Exception):
                cdp = await self._context.new_cdp_session(page)
                cdp.on("Network.requestWillBeSent", on_request)
                await cdp.send("Network.enable")
        try:
            try:
                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=self.timeout * 1000
                )
            except self._error as exc:
                raise ModuleError(f"браузер не открыл {url} ({str(exc).splitlines()[0]})") from exc
            # Let late scripts (tag managers, chats, cookie banners) load.
            with contextlib.suppress(self._error):
                await page.wait_for_load_state("networkidle", timeout=settle_ms)
            # Many sites render the footer (policy link, company details) only when it
            # scrolls into view.
            with contextlib.suppress(self._error):
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await page.wait_for_load_state("networkidle", timeout=SCROLL_SETTLE_MS)
            headers: dict[str, str] = {}
            if response is not None:
                with contextlib.suppress(self._error):
                    headers = {k.lower(): v for k, v in (await response.all_headers()).items()}
            return Rendered(
                final_url=page.url,
                status=response.status if response else None,
                html=await page.content(),
                requests=list(dict.fromkeys(requests)),
                initiators=started_by,
                headers=headers,
            )
        finally:
            with contextlib.suppress(Exception):
                await page.close()

    async def probe(
        self,
        url: str,
        *,
        block: Callable[[str], bool] | None = None,
        settle_ms: int = SETTLE_MS,
        hang: bool = False,
    ) -> Probe:
        """Open ``url`` once for the cutoff experiment (cutoff.py): requests that ``block``
        refuses fail as if the service were cut off, or, with ``hang``, get no answer at
        all while the page is measured; returns what the visitor sees."""
        page = await self._context.new_page()
        probe = Probe(url)
        page.on("request", lambda req: probe.requests.append(req.url))
        page.on("pageerror", lambda exc: probe.errors.append(str(exc).splitlines()[0][:200]))

        async def route(r: Any) -> None:
            if block is not None and block(r.request.url):
                probe.blocked.append(r.request.url)
                if hang:
                    await asyncio.sleep(HANG_HOLD_S)
                with contextlib.suppress(Exception):  # the page may be closed by now
                    await r.abort("timedout" if hang else "connectionrefused")
            else:
                await r.continue_()

        try:
            await page.route("**/*", route)
            started = time.monotonic()
            try:
                response = await page.goto(
                    url,
                    wait_until="commit" if hang else "domcontentloaded",
                    timeout=self.timeout * 1000,
                )
            except self._error as exc:
                raise ModuleError(f"браузер не открыл {url} ({str(exc).splitlines()[0]})") from exc
            if hang:
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=HANG_WAIT_MS)
                except self._error:
                    probe.stuck = True
                with contextlib.suppress(self._error):
                    probe.painted = await page.evaluate(_PAINTED)
            probe.ready_ms = int((time.monotonic() - started) * 1000)
            probe.status = response.status if response else None
            with contextlib.suppress(self._error):
                # Hung requests never let the network go idle: look after a short pause.
                await page.wait_for_load_state(
                    "networkidle", timeout=min(settle_ms, 2000) if hang else settle_ms
                )
            probe.final_url = page.url
            with contextlib.suppress(self._error):
                probe.html = await page.content()
            with contextlib.suppress(self._error):
                probe.dom = await page.evaluate(_DOM_FEATURES)
            with contextlib.suppress(self._error):
                probe.screenshot = await page.screenshot(type="jpeg", quality=55)
            return probe
        except self._error as exc:  # e.g. the page navigated away mid-measurement
            raise ModuleError(f"браузер не измерил {url} ({str(exc).splitlines()[0]})") from exc
        finally:
            with contextlib.suppress(Exception):
                await page.close()

    async def fill_forms(
        self, url: str, values: dict[str, str], *, settle_ms: int = SETTLE_MS
    ) -> FormProbe:
        """Open ``url``, type ``values`` (kind -> text) into the name, phone, e-mail and
        password fields without sending any form, then watch what the page sends.
        ``filled`` holds what ended up in each field: input masks rewrite phones, and a
        phone the mask changed is erased ("value" is then empty)."""
        page = await self._context.new_page()
        probe = FormProbe(url)
        watching = False

        def on_request(req: Any) -> None:
            if not watching:
                return
            body = b""
            with contextlib.suppress(Exception):
                body = req.post_data_buffer or b""
            probe.sent.append(Sent(req.url, req.method, body))

        def on_websocket(ws: Any) -> None:
            def on_frame(payload: Any) -> None:
                if watching:
                    data = payload.encode("utf-8") if isinstance(payload, str) else payload
                    probe.sent.append(Sent(ws.url, "WS", bytes(data), websocket=True))

            ws.on("framesent", on_frame)

        def keep(_source: Any, method: str, to: str, body: str) -> None:
            if watching:
                with contextlib.suppress(ValueError):
                    data = base64.b64decode(body)
                    probe.sent.append(Sent(to, method, data, websocket=method == "WS"))

        page.on("request", on_request)
        page.on("websocket", on_websocket)
        try:
            await page.expose_binding("__suverenKeep", keep)
            await page.add_init_script(_NO_SUBMIT)
            await page.add_init_script(_SENT_HOOK)
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout * 1000)
            except self._error as exc:
                raise ModuleError(f"браузер не открыл {url} ({str(exc).splitlines()[0]})") from exc
            with contextlib.suppress(self._error):
                await page.wait_for_load_state("networkidle", timeout=settle_ms)
            probe.final_url = page.url
            try:
                fields = await page.evaluate(_FIND_FIELDS, MAX_FIELDS)
            except self._error as exc:
                raise ModuleError(
                    f"браузер не прочитал {url} ({str(exc).splitlines()[0]})"
                ) from exc
            watching = True
            for f in fields:
                value = values.get(f["kind"], "")
                if not value:
                    continue
                el = page.locator(f'[data-suveren-field="{f["i"]}"]').first
                try:
                    if f["visible"]:
                        await el.focus(timeout=2000)
                        # Key by key, as a visitor types: keyloggers listen to keys.
                        await el.press_sequentially(value, delay=15, timeout=10000)
                    else:
                        await el.evaluate(_SET_VALUE, value)
                    f["value"] = await el.input_value(timeout=2000)
                    if f["kind"] == "phone" and _digits(value)[-10:] not in _digits(f["value"]):
                        # The mask made another number of it, maybe a real person's. It is
                        # erased before the field is left: "lost lead" widgets read fields
                        # on change and blur and hand the number to a sales manager.
                        await el.evaluate(_SET_VALUE, "")
                        f["value"] = ""
                    await el.evaluate(_LEAVE)
                except self._error:
                    continue
                probe.filled.append(f)
            if probe.filled:
                await page.wait_for_timeout(FORM_WATCH_MS)
                # The visitor "leaves": recorders send what they hold.
                with contextlib.suppress(self._error):
                    await page.evaluate(_HIDE)
                await page.wait_for_timeout(FORM_FLUSH_MS)
                # None when the page went to another address meanwhile.
                with contextlib.suppress(self._error, TypeError, ValueError):
                    probe.submits = int(await page.evaluate("window.__suverenSubmits") or 0)
                watching = False
            return probe
        finally:
            with contextlib.suppress(Exception):
                await page.close()

    async def image_diff(self, a: bytes, b: bytes) -> float | None:
        """Share of pixels (0..1) that differ noticeably between two screenshots of the
        same size, computed on a canvas in the browser (no imaging library needed)."""
        page = await self._context.new_page()
        try:
            return await page.evaluate(
                _IMAGE_DIFF,
                [
                    "data:image/jpeg;base64," + base64.b64encode(a).decode("ascii"),
                    "data:image/jpeg;base64," + base64.b64encode(b).decode("ascii"),
                ],
            )
        except self._error:
            return None
        finally:
            with contextlib.suppress(Exception):
                await page.close()

    async def open_many(self, urls: list[str], *, concurrency: int = 3) -> list[Rendered]:
        """Open several pages in parallel tabs; pages that fail are skipped."""
        semaphore = asyncio.Semaphore(concurrency)

        async def one(url: str) -> Rendered | None:
            async with semaphore:
                try:
                    return await self.open(url, settle_ms=EXTRA_SETTLE_MS)
                except ModuleError:
                    return None

        results = await asyncio.gather(*(one(u) for u in urls))
        return [r for r in results if r is not None]


async def print_pdf(html_path: Path, pdf_path: Path, *, timeout: float = 30.0) -> Path:
    """Print an HTML report to an A4 PDF in the same browser as --browser mode, with the
    "Как переехать" blocks open (a printed page cannot be clicked)."""
    async with BrowserSession(timeout=timeout) as session:
        page = await session._context.new_page()
        try:
            await page.goto(html_path.resolve().as_uri(), wait_until="load")
            await page.evaluate("document.querySelectorAll('details').forEach(d => d.open = true)")
            await page.emulate_media(media="print")
            pdf_path.parent.mkdir(parents=True, exist_ok=True)
            await page.pdf(
                path=str(pdf_path),
                format="A4",
                print_background=True,
                margin={"top": "12mm", "bottom": "12mm", "left": "10mm", "right": "10mm"},
            )
        except session._error as exc:
            raise ModuleError(f"не удалось напечатать PDF ({str(exc).splitlines()[0]})") from exc
        finally:
            with contextlib.suppress(Exception):
                await page.close()
    return pdf_path


async def render(url: str, *, timeout: float = 25.0) -> Rendered:
    async with BrowserSession(timeout=timeout) as session:
        return await session.open(url)
