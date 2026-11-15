"""The pictures of the README and the site: the terminal, the menu and the HTML pages.

Everything is made from the lab (tests/lab.py): made-up sites in the reserved `.test`
zone are run through the same checks `suveren scan` uses, offline, so no picture shows
a real company and the pictures change only when the product does. Run it after a
change to the terminal view, the menu or the report, and look at the result:

    python tools/readme_shots.py             # rewrite docs/*.svg and docs/*.png
    python tools/readme_shots.py --out DIR   # write somewhere else, to compare first

The terminal picture is a real `suveren scan lab.test` with the scan itself replaced by
the lab's report (the stage times are fixed numbers), the menu is the real menu.
The PNG shots are taken with Edge or Chrome, light and dark, like report_shots.py.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
# The terminal picture is 100 columns wide, whatever the window it is made in.
os.environ["COLUMNS"] = "100"

import lab  # noqa: E402
from rich.console import Console  # noqa: E402

import suveren.cli as cli  # noqa: E402
import suveren.report as report_module  # noqa: E402
from suveren.collect import Facts, HostInfo, NetInfo  # noqa: E402
from suveren.company import CompanyReport, build_checks  # noqa: E402
from suveren.menu import run_menu  # noqa: E402
from suveren.models import Report  # noqa: E402
from suveren.registries import EgrulRecord  # noqa: E402
from suveren.render import CHANNELS  # noqa: E402
from suveren.report import render_company_html, render_html, write_batch_html  # noqa: E402
from suveren.scenarios import build as build_scenarios  # noqa: E402

DAY = dt.datetime(2026, 11, 15, 12, 0, tzinfo=dt.UTC)
SCAN_SECONDS = 19.4
# The stages `suveren scan` prints, with fixed times.
STAGES = [
    ("DNS, почта, хостинг, сертификат, страница", 3.1),
    ("Внутренние страницы (до 6)", 1.2),
    ("Персональные данные (152-ФЗ)", 2.6),
    ("Реестр блокировок", 1.8),
    ("Защита почты от подделки", 2.2),
    ("Безопасность сайта", 4.0),
    ("CAA и DNSSEC", 0.9),
    ("Поддомены и их захват", 3.6),
]
LINE_HEIGHT = 24.4  # of a line in Rich's SVG
LF = chr(10)  # the SVGs are kept with Unix line ends, whatever the system writing them
OAUTH = (
    "https://accounts.google.com/o/oauth2/v2/auth?client_id=1.apps.googleusercontent.com"
    "&amp;redirect_uri=https%3A%2F%2Flab.test%2Fcb&amp;response_type=code&amp;scope=openid%20email"
)


def net(ip: str, asn: int, name: str, country: str) -> NetInfo:
    return NetInfo(ip, asn, name, country)


def ru_ns(zone: str) -> list[HostInfo]:
    return [
        HostInfo(f"ns1.{zone}", net("192.0.2.53", 49505, "Selectel", "RU")),
        HostInfo(f"ns2.{zone}", net("198.51.100.53", 49505, "Selectel", "RU")),
    ]


YANDEX_MX = [HostInfo("mx.yandex.net", net("203.0.113.25", 13238, "YANDEX LLC", "RU"))]
NO_CSP = {
    k: v
    for k, v in lab.GOOD_HEADERS.items()
    if k not in ("content-security-policy", "permissions-policy")
}
BODY = lab.NAV + lab.ABOUT


@dataclass
class Site:
    case: lab.Case
    facts: dict[str, Any]


def site(host: str, html: str, **facts: Any) -> Site:
    """A made-up site: ``facts`` is what the lab does not model (DNS owners, registrar)."""
    name = host.split(".")[0]

    @dataclass
    class Made(lab.Case):
        @property
        def host(self) -> str:
            return host

    options = {
        key: facts.pop(key) for key in ("hosting", "headers", "dns", "files") if key in facts
    }
    options.setdefault("hosting", ("Selectel", "RU"))
    options.setdefault("files", lab.site_files())
    case = Made(name, "made-up site for the README", {}, html=lab.page(html), subdomains=["www"],
                **options)  # fmt: skip
    return Site(case, facts)


def sites() -> list[Site]:
    """lab.test is the main picture; the other three fill the summary over a list."""
    return [
        # Foreign DNS, mail, captcha, fonts and CDN; mail can be forged; no policy page.
        site(
            "lab.test",
            BODY
            + lab.FORM_NO_CONSENT
            + lab.FOOTER
            + '<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">'
            + '<script src="https://www.google.com/recaptcha/api.js" async></script>'
            + f'<a class="btn" href="{OAUTH}">Войти через Google</a>'
            + '<script src="https://unpkg.com/vue@3.4.21/dist/vue.global.prod.js"></script>'
            + lab.GA,
            ns=[
                HostInfo("ns1.dns-lab.test", net("192.0.2.53", 49505, "Selectel", "RU")),
                HostInfo(
                    "ns2.dns-lab.test", net("198.51.100.53", 24940, "Hetzner Online GmbH", "DE")
                ),
            ],
            mx=[HostInfo("mx.lab.test", net("192.0.2.25", 64501, "Labs Europe OU", "EE"))],
            registrar="REGRU-RU",
            tls_issuer="Sectigo Limited",
            dns={
                ("_dmarc.lab.test", "TXT"): ["v=DMARC1; p=none"],
                ("lab.test", "TXT"): ["v=spf1 mx ~all"],
                ("lab.test", "MX"): ["10 mx.lab.test."],
            },
            files={},
        ),
        # A foreign network for DNS and Google mail.
        site(
            "news.test",
            BODY + lab.FORM_NO_CONSENT + lab.FOOTER + lab.GA,
            headers=NO_CSP,
            ns=[HostInfo("ns1.dns-news.test", net("192.0.2.54", 13335, "Cloudflare, Inc.", "US"))],
            mx=[HostInfo("aspmx.l.google.com", net("203.0.113.26", 15169, "Google LLC", "US"))],
            registrar="REGRU-RU",
            tls_issuer="Let's Encrypt",
            dns={
                ("_dmarc.news.test", "TXT"): ["v=DMARC1; p=none"],
                ("news.test", "TXT"): ["v=spf1 include:_spf.google.com ~all"],
                ("news.test", "MX"): ["1 aspmx.l.google.com."],
            },
        ),
        # Home-grown, with analytics and a form without consent.
        site(
            "cars.test",
            BODY + lab.FORM_NO_CONSENT + lab.FOOTER + lab.GA,
            headers=NO_CSP,
            ns=ru_ns("cars.test"),
            mx=YANDEX_MX,
            registrar="RU-CENTER-RU",
            tls_issuer="GlobalSign nv-sa",
        ),
        # Home-grown, in order.
        site(
            "shop.test",
            BODY + lab.FORM_OK + lab.FOOTER,
            ns=ru_ns("shop.test"),
            mx=YANDEX_MX,
            registrar="RU-CENTER-RU",
            tls_issuer="GlobalSign nv-sa",
        ),
    ]


def build(made: Site) -> Report:
    """The report of a made-up site, put together as scan.run_scan does."""
    holder: dict[str, Report] = {}
    original = lab.analyze

    def with_facts(facts: Facts, **kwargs: Any) -> Report:
        for key, value in made.facts.items():
            setattr(facts, key, value)
        holder["report"] = original(facts, started_at=DAY)
        return holder["report"]

    lab.analyze = with_facts
    try:
        checks = list(asyncio.run(lab.run_case(made.case)).values())
    finally:
        lab.analyze = original
    report = holder["report"]
    report.checks = build_scenarios(checks, report.dependencies, made.case.host) + checks
    report.finished_at = DAY + dt.timedelta(seconds=SCAN_SECONDS)
    return report


TEXT = re.compile(r'<text class="[^"]*" x="[\d.]+" y="([\d.]+)"[^>]*>(.*?)</text>', re.S)
LINE_TEXT = re.compile(r'<text [^>]*clip-path="url\(#[\w-]+-line-(\d+)\)">.*?</text>', re.S)
LINE_CLIP = re.compile(r'<clipPath id="[\w-]+-line-(\d+)">.*?</clipPath>', re.S)
CELL = re.compile(r'<rect [^>]*y="([\d.]+)"[^>]*crispEdges"/>')


def crop(svg: str, before: str) -> str:
    """The terminal picture up to the line before the section called ``before``: the rest
    of the long scan output is cut away, with its lines, clip paths and background cells."""
    text: dict[float, str] = {}
    for m in TEXT.finditer(svg):
        y = float(m.group(1))
        text[y] = text.get(y, "") + m.group(2).replace("&#160;", " ")
    rows = sorted(text)
    heading = next(
        i for i, y in enumerate(rows) if text[y].strip().startswith(before) and "─" in text[y]
    )
    keep = heading - 1
    height = round(50 + LINE_HEIGHT * keep, 1)
    svg = re.sub(r'viewBox="0 0 ([\d.]+) [\d.]+"', rf'viewBox="0 0 \g<1> {height}"', svg, count=1)

    def below(m: re.Match[str]) -> str:
        return "" if int(m.group(1)) > keep + 1 else m.group(0)

    svg = LINE_TEXT.sub(below, svg)
    svg = LINE_CLIP.sub(below, svg)
    return CELL.sub(lambda m: "" if float(m.group(1)) > height else m.group(0), svg)


def terminal_svg(report: Report, out: Path) -> None:
    clock = [0.0]
    real = time.monotonic

    async def scan_instead(host: str, *, progress: Any = None, **_: Any) -> Report:
        for stage, seconds in STAGES:
            progress(stage, seconds)
        clock[0] += SCAN_SECONDS  # "готово за 19 с" is the total of those stages
        return report

    saved = cli.run_scan, cli.time
    cli.run_scan = scan_instead  # type: ignore[assignment]
    cli.time = type(  # type: ignore[assignment]
        "FakeTime", (), {"monotonic": staticmethod(lambda: real() + clock[0]), "time": time.time}
    )
    here = os.getcwd()
    full = out / "terminal-full.svg"
    os.chdir(tempfile.mkdtemp())  # the report path in the last line is a relative one
    try:
        cli.app(
            ["scan", "lab.test", "--no-open", "--output", "reports/lab.test.html",
             "--export-svg", str(full)],
            standalone_mode=False,
        )  # fmt: skip
    finally:
        os.chdir(here)
        cli.run_scan, cli.time = saved  # type: ignore[assignment]
    svg = crop(full.read_text(encoding="utf-8"), "Персональные данные (152-ФЗ)")
    (out / "demo.svg").write_text(svg, encoding="utf-8", newline=LF)
    full.unlink()


def menu_svg(out: Path) -> None:
    console = Console(record=True, width=91, highlight=False, force_terminal=True)
    answers = iter(["0"])

    def answer(prompt: str = "") -> str:
        console.print(prompt, end="")
        return next(answers)

    console.input = answer  # type: ignore[method-assign]
    console.clear = lambda *a, **k: None  # type: ignore[method-assign]
    run_menu(cli.app, console)
    svg = console.export_svg(title="suveren")
    (out / "menu.svg").write_text(svg, encoding="utf-8", newline=LF)


def inn(first9: str) -> str:
    weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
    return first9 + str(sum(int(a) * b for a, b in zip(first9, weights, strict=True)) % 11 % 10)


def company_report() -> CompanyReport:
    number = inn("770099001")
    ogrn = "112774600099"
    report = CompanyReport(
        query="lab.test",
        domain="lab.test",
        inn=number,
        inn_source="сайт",
        egrul=EgrulRecord(
            name_full='ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "ЛАБОРАТОРИЯ ТЕСТ"',
            name_short='ООО "ЛАБОРАТОРИЯ ТЕСТ"',
            inn=number,
            ogrn=ogrn + str(int(ogrn) % 11 % 10),
            kpp="770901001",
            registered=dt.date(2019, 3, 14),
            terminated=None,
            head="ГЕНЕРАЛЬНЫЙ ДИРЕКТОР: Тестов Тест Тестович",
            region="Г.Москва",
            individual=False,
        ),
    )
    report.sanctions_sources = ["us", "eu", "uk", "un"]
    report.started_at = DAY
    report.finished_at = DAY + dt.timedelta(seconds=11.2)
    report.checks = build_checks(report, sanctions_ok=True, today=DAY.date())
    return report


class FixedDatetime(dt.datetime):
    @classmethod
    def now(cls, tz: dt.tzinfo | None = None) -> FixedDatetime:  # type: ignore[override]
        return cls(2026, 11, 15, 15, 5)


# Page, file name, window height, and whether to open the fines table and scroll to it.
SHOTS = [
    ("report.html", "report", 860, False),
    ("report.html", "compliance", 860, True),
    ("company.html", "company", 860, False),
    ("batch.html", "batch", 520, False),
]
SCROLL_TO_FINES = """() => {
    document.querySelector('details.fines').open = true;
    const heading = document.querySelector('#checks-1');
    window.scrollTo(0, heading.getBoundingClientRect().top + window.scrollY - 75);
}"""


async def shoot(pages: Path, out: Path) -> None:
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        for channel in CHANNELS:
            try:
                browser = await pw.chromium.launch(channel=channel, headless=True)
                break
            except Exception:
                continue
        else:
            raise SystemExit("нет браузера: установите Edge или Chrome")
        for source, name, height, fines in SHOTS:
            for scheme in ("light", "dark"):
                context = await browser.new_context(
                    viewport={"width": 1200, "height": height},
                    color_scheme=scheme,  # type: ignore[arg-type]
                )
                page = await context.new_page()
                await page.goto((pages / source).as_uri())
                if fines:
                    await page.evaluate(SCROLL_TO_FINES)
                await page.screenshot(path=str(out / f"{name}-{scheme}.png"), animations="disabled")
                await context.close()
        await browser.close()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", type=Path, default=ROOT / "docs", help="where to write")
    args = parser.parse_args(argv)
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    reports = [build(made) for made in sites()]
    terminal_svg(reports[0], out)
    menu_svg(out)

    pages = Path(tempfile.mkdtemp())
    (pages / "report.html").write_text(render_html(reports[0]), encoding="utf-8")
    (pages / "company.html").write_text(render_company_html(company_report()), encoding="utf-8")
    report_module.datetime = FixedDatetime  # type: ignore[misc,assignment]
    write_batch_html(sorted(reports, key=lambda r: r.target), [], pages / "batch.html")
    asyncio.run(shoot(pages, out))
    print("\n".join(str(p) for p in sorted(out.glob("*")) if p.suffix in (".png", ".svg")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
