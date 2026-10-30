"""Golden corpus: real sites recorded once, replayed offline on every test run.

The page-based checks (152-ФЗ, consent, sign-in through foreign services) are where
false alarms come from, and only real markup shows them. ``record`` saves everything
those checks download for a site and what they concluded; ``test_corpus.py`` replays
the saved responses and fails when a conclusion changes, showing the difference.

The corpus is local only (``corpus/`` is in .gitignore): it is other people's pages.

    python tests/golden.py record habr.com drom.ru     # add or re-record sites
    python tests/golden.py update                       # accept the current results
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import json
import sys
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent.parent / "corpus"
_KEEP_HEADERS = ("content-type", "location")


def _dep_from(d: dict[str, Any]):
    from suveren.models import Category, Dependency, Severity

    sev = d.get("severity")
    return Dependency(
        Category(d["category"]),
        d["service"],
        d.get("country"),
        d.get("evidence", ""),
        Severity[sev.upper()] if sev else None,
        d.get("note", ""),
    )


def site_dir(host: str) -> Path:
    return ROOT / host


def _save(host: str, meta: dict[str, Any], traffic: dict[str, Any]) -> None:
    folder = site_dir(host)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "meta.json.gz").write_bytes(gzip.compress(json.dumps(meta).encode("utf-8")))
    (folder / "traffic.json.gz").write_bytes(gzip.compress(json.dumps(traffic).encode("utf-8")))


def load(host: str) -> tuple[dict[str, Any], dict[str, Any]]:
    folder = site_dir(host)
    meta = json.loads(gzip.decompress((folder / "meta.json.gz").read_bytes()))
    traffic = json.loads(gzip.decompress((folder / "traffic.json.gz").read_bytes()))
    return meta, traffic


def sites() -> list[str]:
    if not ROOT.is_dir():
        return []
    return sorted(p.name for p in ROOT.iterdir() if (p / "meta.json.gz").exists())


def summarize(checks) -> list[list[str]]:
    """What a regression is judged on: ID, status and the text the user reads."""
    return [[c.id, c.status.value, c.details] for c in checks]


async def replay(host: str) -> list[list[str]]:
    return summarize(await replay_checks(host))


_REPLAYED: dict[str, list] = {}


async def replay_checks(host: str):
    """The 152-ФЗ checks for a recorded site, replayed offline (once per test run: the
    regression test and the self-audit read the same result)."""
    if host not in _REPLAYED:
        _REPLAYED[host] = await _replay_checks(host)
    return _REPLAYED[host]


async def _replay_checks(host: str):
    from suveren.compliance import run_compliance
    from suveren.crawl import FetchedPage

    meta, traffic = load(host)

    def handler(request: httpx.Request) -> httpx.Response:
        saved = traffic.get(str(request.url))
        if saved is None:
            return httpx.Response(404, text="not in corpus")
        status, headers, body = saved
        # The exact bytes: drom.ru answers in windows-1251, and re-encoding text as
        # UTF-8 under that header would turn every Cyrillic link into mojibake.
        return httpx.Response(status, headers=headers, content=base64.b64decode(body))

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        checks = await run_compliance(
            client,
            meta["final_url"],
            meta["html"],
            [_dep_from(d) for d in meta["deps"]],
            page_problem=meta.get("page_problem"),
            extra_pages=[FetchedPage(u, s, h) for u, s, h in meta["extra"]],
        )
    return checks


def expected(host: str) -> list[list[str]] | None:
    path = site_dir(host) / "expected.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def write_expected(host: str, result: list[list[str]]) -> None:
    (site_dir(host) / "expected.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8"
    )


async def record(host: str) -> None:
    """Scan ``host`` over HTTP as `suveren scan` does and save what the checks read."""
    from suveren.analyze import analyze
    from suveren.collect import collect, make_client
    from suveren.compliance import run_compliance
    from suveren.crawl import DEFAULT_PAGES, fetch_pages, pick_links
    from suveren.page import parse_page

    facts = await collect(host, timeout=15)
    if not facts.html:
        raise SystemExit(f"{host}: главная не загрузилась")
    async with make_client(15) as client:
        links = pick_links(parse_page(facts.html), facts.final_url or "", DEFAULT_PAGES)
        facts.extra_pages = await fetch_pages(client, links)
    report = analyze(facts)
    traffic: dict[str, Any] = {}

    async def keep(response: httpx.Response) -> None:
        await response.aread()
        headers = {k: v for k, v in response.headers.items() if k.lower() in _KEEP_HEADERS}
        body = base64.b64encode(response.content).decode("ascii")
        traffic[str(response.request.url)] = [response.status_code, headers, body]

    async with make_client(15) as client:
        client.event_hooks["response"] = [keep]
        await run_compliance(
            client,
            facts.final_url,
            facts.html,
            report.dependencies,
            page_problem=facts.page_problem,
            extra_pages=facts.extra_pages,
        )
    meta = {
        "final_url": facts.final_url,
        "html": facts.html,
        "page_problem": facts.page_problem,
        "extra": [[p.url, p.status, p.html] for p in facts.extra_pages],
        "deps": [d.to_dict() for d in report.dependencies],
    }
    _save(host, meta, traffic)
    write_expected(host, await replay(host))
    size = sum(f.stat().st_size for f in site_dir(host).iterdir()) // 1024
    print(f"{host}: {len(traffic)} ответов, {size} КБ")


def main(argv: list[str]) -> None:
    if not argv or argv[0] not in {"record", "update"}:
        raise SystemExit(__doc__)
    if argv[0] == "record":
        for host in argv[1:]:
            try:
                asyncio.run(record(host))
            except Exception as exc:  # one broken site must not stop the rest
                print(f"{host}: не записан ({exc!r})")
    else:
        for host in sites():
            write_expected(host, asyncio.run(replay(host)))
            print(f"{host}: ожидаемый результат обновлён")


if __name__ == "__main__":
    main(sys.argv[1:])
