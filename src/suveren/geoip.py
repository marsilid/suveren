"""Where a server physically is, from an offline IP geolocation database.

The owner of a network (Team Cymru) answers "what breaks under sanctions": a Russian
company's network is Russian even when its server stands in Frankfurt. Data localisation
(152-ФЗ, ст. 18 ч. 5, SUV-PD-007) asks the other question, where the server is.

DB-IP "IP to Country Lite" is used: CC BY 4.0, one file a month, no registration.
IP2Location LITE needs an account and a download token, and is CC BY-SA. The file is
downloaded into the cache (``suveren update`` or the first scan) and never shipped.
"""

from __future__ import annotations

import asyncio
import csv
import gzip
import io
import socket
import time
from bisect import bisect_right
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import httpx

from suveren.cache import cache_dir, fetch_cached
from suveren.checks import copy_of
from suveren.errors import ModuleError

NAME = "DB-IP"
LICENCE = "IP Geolocation by DB-IP (db-ip.com), CC BY 4.0"
HOME = "https://db-ip.com"
FILENAME = "geoip/dbip-country-lite.csv.gz"
URL = "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz"
TTL = 31 * 24 * 3600  # a new file comes out on the 1st of each month
# Two missed months: addresses move between countries, an old answer is not used.
STALE_DAYS = 70


def month_urls(today: date | None = None) -> list[str]:
    """This month's file, then last month's: the new one is out on the 1st, not at 00:00."""
    today = today or date.today()
    prev = date(today.year - (today.month == 1), (today.month - 2) % 12 + 1, 1)
    return [URL.format(month=f"{d:%Y-%m}") for d in (today, prev)]


def _key(address: str) -> tuple[int, int] | None:
    """(version, number) of an address; None for something else."""
    for family, version in ((socket.AF_INET, 4), (socket.AF_INET6, 6)):
        try:
            return version, int.from_bytes(socket.inet_pton(family, address), "big")
        except OSError:
            continue
    return None


@dataclass(slots=True)
class GeoDb:
    """Sorted ranges per IP version: a lookup is one bisect."""

    starts: dict[int, list[int]] = field(default_factory=lambda: {4: [], 6: []})
    ends: dict[int, list[int]] = field(default_factory=lambda: {4: [], 6: []})
    countries: dict[int, list[str]] = field(default_factory=lambda: {4: [], 6: []})
    origin: str = ""  # "DB-IP …, база от 01.11.2026"
    problem: str = ""  # why there is no answer: not downloaded, too old

    def country_of(self, address: str) -> str | None:
        key = _key(address)
        if key is None:
            return None
        version, number = key
        starts = self.starts[version]
        i = bisect_right(starts, number) - 1
        if i < 0 or number > self.ends[version][i]:
            return None
        code = self.countries[version][i]
        return None if code in ("ZZ", "") else code  # ZZ: reserved, private, unknown

    @property
    def empty(self) -> bool:
        return not (self.starts[4] or self.starts[6])


def parse(raw: bytes) -> GeoDb:
    """``start,end,country`` rows, sorted by start (the file is); neighbours with the
    same country are joined, which halves the table."""
    db = GeoDb()
    text = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    for row in csv.reader(io.StringIO(text.decode("ascii", "replace"))):
        if len(row) < 3:
            continue
        start, end = _key(row[0]), _key(row[1])
        if start is None or end is None or start[0] != end[0]:
            continue
        version = start[0]
        starts, ends, codes = db.starts[version], db.ends[version], db.countries[version]
        code = row[2].strip().upper()
        if starts and start[1] < ends[-1]:
            continue  # out of order: a broken file, not trusted for this row
        if codes and codes[-1] == code and ends[-1] + 1 == start[1]:
            ends[-1] = end[1]
            continue
        starts.append(start[1])
        ends.append(end[1])
        codes.append(code)
    return db


_LOADED: dict[Path, tuple[float, GeoDb]] = {}


def read(path: Path) -> GeoDb:
    """The parsed file, once per run (a batch of sites reads it one time)."""
    mtime = path.stat().st_mtime
    hit = _LOADED.get(path)
    if hit and hit[0] == mtime:
        return hit[1]
    db = parse(path.read_bytes())
    _LOADED.clear()
    _LOADED[path] = (mtime, db)
    return db


async def load(client: httpx.AsyncClient, *, refresh: bool = False) -> GeoDb:
    """The database, or an empty one whose ``problem`` says why; a scan never fails on it."""
    path: Path | None = None
    for url in month_urls():
        try:
            path, _ = await fetch_cached(client, url, FILENAME, ttl=TTL, refresh=refresh)
            break
        except ModuleError:
            continue
    if path is None:
        return GeoDb(problem=f"база {NAME} не скачалась")
    age = (time.time() - path.stat().st_mtime) / 86400
    if age > STALE_DAYS:
        return GeoDb(problem=f"копия базы {NAME} старше {STALE_DAYS} дней, не использована")
    try:
        db = await asyncio.to_thread(read, path)
    except (OSError, EOFError, gzip.BadGzipFile, ValueError):
        return GeoDb(problem=f"файл базы {NAME} повреждён")
    if db.empty:
        return GeoDb(problem=f"файл базы {NAME} пуст")
    db.origin = copy_of(f"{NAME}, {HOME}", path, "база")
    return db


def cached_path() -> Path:
    return cache_dir() / FILENAME
