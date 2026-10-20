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
        self, url: str, *, block: Callable[[str], bool] | None = None, settle_ms: int = SETTLE_MS
    ) -> Probe:
        """Open ``url`` once for the cutoff experiment (cutoff.py): requests that ``block``
        refuses fail as if the service were cut off; returns what the visitor sees."""
        page = await self._context.new_page()
        probe = Probe(url)
        page.on("request", lambda req: probe.requests.append(req.url))
        page.on("pageerror", lambda exc: probe.errors.append(str(exc).splitlines()[0][:200]))

        async def route(r: Any) -> None:
            if block is not None and block(r.request.url):
                probe.blocked.append(r.request.url)
                await r.abort("connectionrefused")
            else:
                await r.continue_()

        try:
            await page.route("**/*", route)
            started = time.monotonic()
            try:
                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=self.timeout * 1000
                )
            except self._error as exc:
                raise ModuleError(f"браузер не открыл {url} ({str(exc).splitlines()[0]})") from exc
            probe.ready_ms = int((time.monotonic() - started) * 1000)
            probe.status = response.status if response else None
            with contextlib.suppress(self._error):
                await page.wait_for_load_state("networkidle", timeout=settle_ms)
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
