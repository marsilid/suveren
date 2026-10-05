"""`--browser` mode: open the home page in a real browser via Playwright.

This sees what plain HTTP cannot: pages built by JavaScript, cookie banners,
and every script, font and widget the page loads at runtime (including ones
injected by tag managers). A browser that is already installed (Edge, Chrome)
is used, so no extra download is needed; Playwright's own Chromium is the
fallback.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field

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


@dataclass(slots=True)
class Rendered:
    final_url: str
    status: int | None
    html: str
    requests: list[str] = field(default_factory=list)
    browser: str = ""


async def render(url: str, *, timeout: float = 25.0) -> Rendered:
    try:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise ModuleError(INSTALL_HINT) from exc

    async with async_playwright() as pw:
        browser = None
        used = ""
        for channel in CHANNELS:
            try:
                browser = await pw.chromium.launch(
                    channel=channel,
                    headless=True,
                    args=["--disable-blink-features=AutomationControlled"],
                )
                used = channel or "chromium"
                break
            except PlaywrightError:
                continue
        if browser is None:
            raise ModuleError("не найден браузер: установите Edge или Chrome, " + INSTALL_HINT)
        try:
            context = await browser.new_context(
                user_agent=USER_AGENT,
                locale="ru-RU",
                viewport={"width": 1366, "height": 900},
                ignore_https_errors=True,
            )
            page = await context.new_page()
            requests: list[str] = []
            page.on("request", lambda req: requests.append(req.url))
            try:
                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=timeout * 1000
                )
            except PlaywrightError as exc:
                raise ModuleError(f"браузер не открыл сайт ({str(exc).splitlines()[0]})") from exc
            # Let late scripts (tag managers, chats, cookie banners) load.
            with contextlib.suppress(PlaywrightError):
                await page.wait_for_load_state("networkidle", timeout=SETTLE_MS)
            html = await page.content()
            return Rendered(
                final_url=page.url,
                status=response.status if response else None,
                html=html,
                requests=list(dict.fromkeys(requests)),
                browser=used,
            )
        finally:
            await browser.close()
