"""Download-and-cache for large public datasets (sanctions lists, block lists)."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import httpx

from suveren.errors import ModuleError, describe

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


async def fetch_cached(
    client: httpx.AsyncClient,
    url: str,
    name: str,
    *,
    ttl: float = DEFAULT_TTL,
    refresh: bool = False,
) -> tuple[Path, str | None]:
    """Return the cached file, downloading it when missing or stale.

    If the download fails but an old copy exists, the old copy is returned with
    a note. Without any copy a :class:`ModuleError` is raised.
    """
    path = cache_dir() / name
    if not refresh and is_fresh(path, ttl):
        return path, None
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".part")
    try:
        async with client.stream("GET", url, timeout=httpx.Timeout(30.0, read=120.0)) as resp:
            resp.raise_for_status()
            with tmp.open("wb") as fh:
                async for chunk in resp.aiter_bytes(1 << 16):
                    fh.write(chunk)
        if not _looks_like_data(tmp):
            # A 200 with a stub page or nothing used to replace a good copy, and the
            # empty index made from it lived for a day.
            raise _NotData
        tmp.replace(path)
        return path, None
    except (httpx.HTTPError, OSError, _NotData) as exc:
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


def _looks_like_data(path: Path) -> bool:
    """Not empty and not an HTML page (a block page, a CDN challenge, a moved source)."""
    with path.open("rb") as fh:
        head = fh.read(512).lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    return bool(head) and not head.startswith((b"<!doctype html", b"<html", b"<head"))
