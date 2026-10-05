"""Download-and-cache for large public datasets (sanctions lists, block lists)."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import httpx

from suveren.errors import ModuleError

DEFAULT_TTL = 24 * 3600


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
        tmp.replace(path)
        return path, None
    except (httpx.HTTPError, OSError) as exc:
        tmp.unlink(missing_ok=True)
        if path.exists():
            return path, f"не удалось обновить {name}, использована копия от {age_text(path)}"
        raise ModuleError(f"не удалось скачать {url} ({type(exc).__name__})") from exc
