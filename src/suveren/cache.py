"""Download-and-cache for large public datasets (sanctions lists, block lists)."""

from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
from pathlib import Path

import httpx

from suveren.errors import ModuleError, describe
from suveren.net import MAX_BODY_KEY, note_unreachable, offline

DEFAULT_TTL = 24 * 3600
# Sanctions lists change weekly and the block register daily: a "not found" against an
# older copy (kept when a refresh fails) is not a clean answer.
STALE_DAYS = 14


def cache_dir() -> Path:
    """Per-user cache directory; ``SUVEREN_CACHE`` overrides it."""
    override = os.environ.get("SUVEREN_CACHE")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "suveren" / "cache"
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "suveren"


def is_fresh(path: Path, ttl: float = DEFAULT_TTL) -> bool:
    return path.exists() and time.time() - path.stat().st_mtime < ttl


def stale_days(path: Path, limit: int = STALE_DAYS) -> int | None:
    """Age in whole days when the copy is older than ``limit`` days, else None."""
    days = int((time.time() - path.stat().st_mtime) / 86400)
    return days if days > limit else None


def age_text(path: Path) -> str:
    hours = (time.time() - path.stat().st_mtime) / 3600
    if hours < 1:
        return "меньше часа назад"
    if hours < 48:
        return f"{int(hours)} ч назад"
    return f"{int(hours / 24)} дн назад"


# One download per file at a time: `research` scans several sites at once, and each
# wanted the block list; on Windows the second writer found the file taken and the
# whole run fell over. Keyed by the event loop too: plugins run in their own loops.
_LOCKS: dict[tuple[int, str], asyncio.Lock] = {}


def _lock(name: str) -> asyncio.Lock:
    return _LOCKS.setdefault((id(asyncio.get_running_loop()), name), asyncio.Lock())


async def fetch_cached(
    client: httpx.AsyncClient,
    url: str,
    name: str,
    *,
    ttl: float = DEFAULT_TTL,
    refresh: bool = False,
    html: bool = False,
    timeout: httpx.Timeout | None = None,
) -> tuple[Path, str | None]:
    """Return the cached file, downloading it when missing or stale.

    If the download fails but an old copy exists, the old copy is returned with
    a note. Without any copy a :class:`ModuleError` is raised. Once the network is
    known to be unreachable (``net.offline``), nothing is downloaded: it would only
    wait for its timeout.
    """
    path = cache_dir() / name
    if not refresh and is_fresh(path, ttl):
        return path, None
    down = offline()
    if down:
        if path.exists():
            return path, f"сеть недоступна, использована копия {name} от {age_text(path)}"
        raise ModuleError(f"не удалось скачать {url} (сеть недоступна: {down})")
    async with _lock(name):
        if not refresh and is_fresh(path, ttl):  # another caller has just fetched it
            return path, None
        return await _download(client, url, name, path, html=html, timeout=timeout)


async def _download(
    client: httpx.AsyncClient,
    url: str,
    name: str,
    path: Path,
    *,
    html: bool,
    timeout: httpx.Timeout | None = None,
) -> tuple[Path, str | None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    # A name of its own, so another process downloading the same list does not collide.
    tmp = path.with_name(f"{path.name}.{os.getpid()}-{uuid.uuid4().hex[:8]}.part")
    try:
        # Sanctions lists and the block list are far bigger than a page.
        big = {MAX_BODY_KEY: 1 << 30}
        timeout = timeout or httpx.Timeout(30.0, read=120.0)
        async with client.stream("GET", url, timeout=timeout, extensions=big) as resp:
            resp.raise_for_status()
            with tmp.open("wb") as fh:
                async for chunk in resp.aiter_bytes(1 << 16):
                    fh.write(chunk)
        if not _looks_like_data(tmp, html=html):
            # A 200 with a stub page or nothing used to replace a good copy, and the
            # empty index made from it lived for a day.
            raise _NotData
        tmp.replace(path)
        return path, None
    except (httpx.HTTPError, OSError, _NotData) as exc:
        note_unreachable(exc)
        tmp.unlink(missing_ok=True)
        why = "вместо списка пришла пустая страница или HTML" if isinstance(exc, _NotData) else ""
        if path.exists():
            prefix = f"{why}; " if why else ""
            return (
                path,
                f"{prefix}не удалось обновить {name}, использована копия от {age_text(path)}",
            )
        raise ModuleError(f"не удалось скачать {url} ({why or describe(exc)})") from exc


class _NotData(Exception):
    pass


def _looks_like_data(path: Path, *, html: bool = False) -> bool:
    """Not empty and not an HTML page (a block page, a CDN challenge, a moved source).
    ``html``: the source is a page itself; its caller checks the content."""
    with path.open("rb") as fh:
        head = fh.read(512).lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if html:
        return bool(head)
    return bool(head) and not head.startswith((b"<!doctype html", b"<html", b"<head"))
