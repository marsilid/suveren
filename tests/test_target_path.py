"""A target with a path is scanned at that page, not at the root of the host.

`suveren scan https://marsilid.github.io/suveren/` checked marsilid.github.io/, which
on a shared host may be someone else's site or nothing at all."""

import asyncio

import httpx
import pytest

from suveren.collect import Collector
from suveren.utils import target_path


@pytest.mark.parametrize(
    ("target", "path"),
    [
        ("example.ru", "/"),
        ("https://example.ru", "/"),
        ("https://example.ru/", "/"),
        ("https://marsilid.github.io/suveren/", "/suveren/"),
        ("marsilid.github.io/suveren/", "/suveren/"),
        ("https://shop.ru/ru/catalog?token=SECRET#top", "/ru/catalog"),
    ],
)
def test_the_page_a_target_names(target, path):
    assert target_path(target) == path


class Resolver:
    async def resolve(self, name, rtype):
        return []


def test_the_named_page_is_opened_instead_of_the_root():
    asked = []

    def handler(request):
        asked.append(str(request.url))
        return httpx.Response(200, text="<html>docs</html>", headers={"Content-Type": "text/html"})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            c = Collector(Resolver(), client, 5)
            c.start_path = "/suveren/"
            return await c.homepage("marsilid.github.io")

    url, status, html, _ = asyncio.run(go())
    assert html == "<html>docs</html>"
    assert asked == ["https://marsilid.github.io/suveren/"]
    assert url == "https://marsilid.github.io/suveren/" and status == 200
