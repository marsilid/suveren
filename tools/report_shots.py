"""Screenshots of the HTML report, light and dark, desktop and phone, and a comparison.

The report is built from fixed lab data (tests/lab.py), so it is the same on every
run: a change in the pictures is a change in the report. Fonts render differently
on each OS, so baselines are per machine and the test runs only when asked:

    python tools/report_shots.py                    # write reports/shots/*.png
    python tools/report_shots.py --compare DIR      # compare with an earlier set
    SUVEREN_VISUAL=1 pytest tests/test_visual.py    # the same, as a test

Needs the browser extra (playwright) and Edge or Chrome.
"""

from __future__ import annotations

import asyncio
import base64
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import lab  # noqa: E402

from suveren.analyze import analyze  # noqa: E402
from suveren.collect import Facts, NetInfo  # noqa: E402
from suveren.render import _IMAGE_DIFF, CHANNELS  # noqa: E402
from suveren.report import render_html  # noqa: E402

OUT = ROOT / "reports" / "shots"
VIEWS = {"desktop": (1280, 900), "phone": (390, 844)}
SCHEMES = ("light", "dark")
# Share of pixels that may differ before a shot counts as changed (antialiasing).
TOLERANCE = 0.002
FIXED = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)


def sample_html(case_name: str = "lab-ga-no-banner") -> str:
    """The report of a lab site, with fixed times so the picture never drifts."""
    case = next(c for c in lab.CASES if c.name == case_name)
    facts = Facts(
        case.host,
        case.host,
        web=[NetInfo("192.0.2.10", 64500, case.hosting[0], case.hosting[1])],
        final_url=f"https://{case.host}/",
        page_status=200,
        html=case.html,
    )
    report = analyze(facts, started_at=FIXED)
    report.checks = list(asyncio.run(lab.run_case(case)).values())
    report.finished_at = FIXED
    return render_html(report)


async def _launch(pw):  # type: ignore[no-untyped-def]
    """Edge, then Chrome, then Playwright's own Chromium: whichever is installed."""
    for channel in CHANNELS:
        try:
            return await pw.chromium.launch(channel=channel, headless=True)
        except Exception:
            continue
    raise SystemExit("нет браузера: установите Edge или Chrome")


async def shoot(html: str, out: Path) -> list[Path]:
    from playwright.async_api import async_playwright

    out.mkdir(parents=True, exist_ok=True)
    page_file = out / "report.html"
    page_file.write_text(html, encoding="utf-8")
    written = []
    async with async_playwright() as pw:
        browser = await _launch(pw)
        for view, (width, height) in VIEWS.items():
            for scheme in SCHEMES:
                context = await browser.new_context(
                    viewport={"width": width, "height": height}, color_scheme=scheme
                )
                page = await context.new_page()
                await page.goto(page_file.as_uri())
                path = out / f"{view}-{scheme}.png"
                await page.screenshot(path=str(path), full_page=True, animations="disabled")
                written.append(path)
                await context.close()
        await browser.close()
    return written


async def compare(new: Path, old: Path) -> dict[str, float | None]:
    """Share of differing pixels per shot; None when sizes differ (the page grew)."""
    from playwright.async_api import async_playwright

    result: dict[str, float | None] = {}
    async with async_playwright() as pw:
        browser = await _launch(pw)
        page = await browser.new_page()
        for shot in sorted(new.glob("*.png")):
            before = old / shot.name
            if not before.exists():
                result[shot.name] = None
                continue
            urls = [
                "data:image/png;base64," + base64.b64encode(p.read_bytes()).decode("ascii")
                for p in (shot, before)
            ]
            result[shot.name] = await page.evaluate(_IMAGE_DIFF, urls)
        await browser.close()
    return result


def main(argv: list[str]) -> int:
    shots = asyncio.run(shoot(sample_html(), OUT))
    print("\n".join(str(p) for p in shots))
    if "--compare" in argv:
        old = Path(argv[argv.index("--compare") + 1])
        changed = 0
        for name, share in asyncio.run(compare(OUT, old)).items():
            bad = share is None or share > TOLERANCE
            changed += bad
            shown = "размер изменился" if share is None else f"{share:.2%}"
            print(f"{'!' if bad else ' '} {name}: {shown}")
        return 1 if changed else 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
