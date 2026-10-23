"""The download cache for large public lists: fresh, refreshed, stale or missing."""

import asyncio
import os
import time

import httpx
import pytest

from suveren.cache import age_text, cache_dir, fetch_cached
from suveren.errors import ModuleError


def fetch(handler, name, **kwargs):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch_cached(client, "https://lists.example/x.txt", name, **kwargs)

    return asyncio.run(go())


def test_download_then_cache_then_stale_copy(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    assert cache_dir() == tmp_path
    calls = []

    def ok(request):
        calls.append(1)
        return httpx.Response(200, content=b"list v1")

    path, note = fetch(ok, "x.txt")
    assert path.read_bytes() == b"list v1" and note is None
    fetch(ok, "x.txt")
    assert len(calls) == 1  # fresh: served from the cache

    day_old = time.time() - 3 * 24 * 3600
    os.utime(path, (day_old, day_old))
    path, note = fetch(lambda r: httpx.Response(503), "x.txt")
    assert path.read_bytes() == b"list v1"  # the old copy, said so
    assert note and "3 дн назад" in note
    assert not (tmp_path / "x.txt.part").exists()


@pytest.mark.parametrize(
    "body", [b"", b"  <!DOCTYPE html><html>blocked</html>", b"\xef\xbb\xbf<html><body>503"]
)
def test_a_stub_answer_does_not_replace_a_good_copy(tmp_path, monkeypatch, body):
    # A 200 with a block page or nothing used to overwrite the list, and the empty
    # index built from it passed for "checked, not found" for a day.
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    path, _ = fetch(lambda r: httpx.Response(200, content=b"list v1"), "x.txt")
    old = time.time() - 2 * 24 * 3600
    os.utime(path, (old, old))
    path, note = fetch(lambda r: httpx.Response(200, content=body), "x.txt")
    assert path.read_bytes() == b"list v1"
    assert note and "HTML" in note and "копия" in note
    with pytest.raises(ModuleError, match="HTML"):
        fetch(lambda r: httpx.Response(200, content=body), "other.txt")
    assert not (tmp_path / "other.txt").exists()


def test_no_copy_and_no_download_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))
    with pytest.raises(ModuleError, match="не удалось скачать"):
        fetch(lambda r: httpx.Response(404), "missing.txt")


def test_age_in_words(tmp_path):
    f = tmp_path / "f"
    f.write_text("x")
    assert age_text(f) == "меньше часа назад"
    five_hours = time.time() - 5 * 3600
    os.utime(f, (five_hours, five_hours))
    assert age_text(f) == "5 ч назад"


def test_cache_dir_on_linux(monkeypatch, tmp_path):
    import sys

    monkeypatch.delenv("SUVEREN_CACHE", raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert cache_dir() == tmp_path / "suveren"
