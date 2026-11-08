"""`suveren watch`: check the same sites again and say what changed since last time.

Each round scans every site (the standard, passive checks), keeps the JSON report in
<state>/<site>/, compares it with the previous one (history.compare: services added or
removed, checks that got better or worse) and appends what changed to
<state>/changes.log. Run it once from cron or the Windows Task Scheduler (--once), or
let it repeat itself (--every, at least an hour apart: a monitor that hammers the sites
it watches is a nuisance to them).
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from suveren.errors import SuverenError
from suveren.history import Changes, compare
from suveren.models import Report

MIN_INTERVAL = 3600.0
KEEP_REPORTS = 30  # per site; older ones are deleted

ScanFn = Callable[[str], Awaitable[Report]]


@dataclass(slots=True)
class WatchResult:
    host: str
    changes: Changes | None  # None: the first round for the site, nothing to compare
    error: str | None = None
    report: Path | None = None


def parse_interval(text: str) -> float:
    """'24h', '90m', '2d' -> seconds; at least an hour."""
    text = text.strip().lower()
    units = {"m": 60, "h": 3600, "d": 86400}
    try:
        seconds = float(text[:-1]) * units[text[-1]] if text[-1] in units else float(text)
    except (ValueError, IndexError) as exc:
        raise SuverenError(f"--every: «{text}» — нужно число с m, h или d (например 24h)") from exc
    if seconds < MIN_INTERVAL:
        raise SuverenError("--every: не чаще раза в час, чтобы не мешать сайтам")
    return seconds


def _latest(folder: Path) -> dict[str, Any] | None:
    reports = sorted(folder.glob("*.json"))
    if not reports:
        return None
    try:
        data: dict[str, Any] = json.loads(reports[-1].read_text("utf-8"))
        return data
    except (OSError, ValueError):
        return None


def _prune(folder: Path) -> None:
    for old in sorted(folder.glob("*.json"))[:-KEEP_REPORTS]:
        old.unlink(missing_ok=True)


def describe(changes: Changes) -> list[str]:
    lines = [f"− {cat}: {svc}" for cat, svc, _ in changes.removed]
    lines += [f"+ {cat}: {svc}" for cat, svc, _ in changes.added]
    lines += [
        f"{'✓' if c.better else '✗'} {c.title} ({c.id}): {c.before} → {c.after}"
        for c in changes.checks
    ]
    lines += [f"• новая проверка: {t}" for t in changes.appeared]
    return lines


async def watch_round(hosts: list[str], state: Path, scan: ScanFn) -> list[WatchResult]:
    results = []
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    for host in hosts:
        folder = state / host
        folder.mkdir(parents=True, exist_ok=True)
        previous = _latest(folder)
        try:
            report = await scan(host)
        except SuverenError as exc:
            results.append(WatchResult(host, None, str(exc)))
            continue
        data = report.to_dict()
        path = folder / f"{stamp}.json"
        path.write_text(json.dumps(data, ensure_ascii=False, default=str), "utf-8")
        _prune(folder)
        changes = compare(previous, data) if previous is not None else None
        results.append(WatchResult(host, changes, None, path))
    _log(state, stamp, results)
    return results


def _log(state: Path, stamp: str, results: list[WatchResult]) -> None:
    lines = []
    for r in results:
        if r.error:
            lines.append(f"{stamp} {r.host}: не проверен ({r.error})")
        elif r.changes is not None and not r.changes.empty:
            lines += [f"{stamp} {r.host}: {line}" for line in describe(r.changes)]
    if lines:
        with (state / "changes.log").open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")


# --- Telegram -------------------------------------------------------------------------

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"
TELEGRAM_LIMIT = 4000  # Telegram takes up to 4096 characters a message


def changes_message(results: list[WatchResult], when: datetime | None = None) -> str | None:
    """The text to send, or None when nothing changed: no change, no message."""
    blocks = []
    for r in results:
        if r.changes is not None and not r.changes.empty:
            blocks.append(r.host + ":\n" + "\n".join(describe(r.changes)))
    if not blocks:
        return None
    head = f"Suveren: изменения на сайтах ({(when or datetime.now()):%d.%m.%Y %H:%M})"
    text = head + "\n\n" + "\n\n".join(blocks)
    if len(text) > TELEGRAM_LIMIT:
        text = text[: TELEGRAM_LIMIT - 40] + "\n… (полностью — в changes.log)"
    return text


async def send_telegram(client: httpx.AsyncClient, token: str, chat: str, text: str) -> None:
    """Raises SuverenError with a message that never contains the token: an httpx error
    names the URL, and the token is part of it."""
    try:
        resp = await client.post(
            TELEGRAM_API.format(token=token),
            json={"chat_id": chat, "text": text, "disable_web_page_preview": True},
        )
    except httpx.HTTPError as exc:
        raise SuverenError(f"Telegram не ответил ({type(exc).__name__})") from None
    if resp.status_code != 200:
        raise SuverenError(f"Telegram не принял сообщение (код {resp.status_code})")
