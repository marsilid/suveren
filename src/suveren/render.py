"""`--browser` mode: open pages in a real browser via Playwright.

This sees what plain HTTP cannot: pages built by JavaScript, cookie banners,
and every script, font and widget a page loads at runtime (including ones
injected by tag managers). A browser that is already installed (Edge, Chrome)
is used, so no extra download is needed; Playwright's own Chromium is the
fallback. One browser session serves the home page and the extra pages.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
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

    async def open(self, url: str, *, settle_ms: int = SETTLE_MS) -> Rendered:
        page = await self._context.new_page()
        requests: list[str] = []
        page.on("request", lambda req: requests.append(req.url))
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
            return Rendered(
                final_url=page.url,
                status=response.status if response else None,
                html=await page.content(),
                requests=list(dict.fromkeys(requests)),
            )
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


async def render(url: str, *, timeout: float = 25.0) -> Rendered:
    async with BrowserSession(timeout=timeout) as session:
        return await session.open(url)
