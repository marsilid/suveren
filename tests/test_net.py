"""Network limits: no requests to internal addresses, no unbounded bodies."""

import asyncio
import gzip
import zlib

import httpcore
import httpx
import pytest

from suveren import net
from suveren.collect import make_client
from suveren.crawl import sitemap_urls
from suveren.errors import describe


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1",
     "[::1]", "::ffff:127.0.0.1", "fe80::1", "0.0.0.0", "localhost"],
)  # fmt: skip
def test_internal_addresses_are_refused(host):
    with pytest.raises(httpcore.ConnectError, match=net.BLOCKED):
        asyncio.run(net.public_addresses(host, 443))


def test_public_address_passes():
    assert asyncio.run(net.public_addresses("93.184.216.34", 443)) == ["93.184.216.34"]


def test_operator_can_allow_own_network(monkeypatch):
    monkeypatch.setenv(net.ALLOW_PRIVATE_ENV, "1")
    assert asyncio.run(net.public_addresses("10.0.0.5", 80)) == ["10.0.0.5"]


class _Inner(httpcore.AsyncNetworkBackend):
    def __init__(self):
        self.hosts = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.hosts.append(host)
        raise httpcore.ConnectError("test: no network")


def test_backend_connects_to_the_checked_address(monkeypatch):
    async def resolve(host, port, timeout=None):
        return ["203.0.113.7", "198.51.100.1"] if host == "site.test" else []

    monkeypatch.setattr(net, "public_addresses", resolve)
    inner = _Inner()
    backend = net._PublicOnlyBackend(inner)
    with pytest.raises(httpcore.ConnectError):
        asyncio.run(backend.connect_tcp("site.test", 443))
    # The socket goes to the addresses checked, never to the name resolved again.
    assert inner.hosts == ["203.0.113.7", "198.51.100.1"]


def test_backend_never_connects_to_internal_name():
    inner = _Inner()
    with pytest.raises(httpcore.ConnectError, match=net.BLOCKED):
        asyncio.run(net._PublicOnlyBackend(inner).connect_tcp("localhost", 80))
    assert inner.hosts == []


def test_client_refuses_internal_url_and_says_why():
    async def get():
        async with make_client(5) as client:
            await client.get("http://127.0.0.1:9/")

    with pytest.raises(httpx.ConnectError) as info:
        asyncio.run(get())
    assert "запрос не отправлен" in describe(info.value)


def test_client_transport_is_guarded():
    # Breaks loudly if httpx moves the pool's backend.
    client = make_client(5)
    transport = client._transport
    assert isinstance(transport._pool._network_backend, net._PublicOnlyBackend)
    asyncio.run(client.aclose())


class _Chunks(httpx.AsyncByteStream):
    def __init__(self, data, size=1 << 16):
        self._data, self._size = data, size

    async def __aiter__(self):
        for i in range(0, len(self._data), self._size):
            yield self._data[i : i + self._size]


def _read(body, encoding=None, extensions=None):
    async def go():
        request = httpx.Request("GET", "https://site.test/", extensions=extensions or {})
        headers = {"content-encoding": encoding} if encoding else {}
        response = httpx.Response(200, headers=headers, stream=_Chunks(body), request=request)
        await net.bound_body(response)
        return await response.aread()

    return asyncio.run(go())


def test_gzip_bomb_is_cut():
    bomb = gzip.compress(b"\0" * (net.MAX_BODY * 4))
    assert len(bomb) < net.MAX_BODY
    assert len(_read(bomb, "gzip")) == net.MAX_BODY


def test_raw_deflate_bomb_is_cut():
    packer = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    bomb = packer.compress(b"a" * (net.MAX_BODY * 3)) + packer.flush()
    assert len(_read(bomb, "deflate")) == net.MAX_BODY


def test_big_plain_body_is_cut():
    assert len(_read(b"x" * (net.MAX_BODY + 5000))) == net.MAX_BODY


def test_small_gzip_is_unpacked():
    assert _read(gzip.compress(b"<html>ok</html>"), "gzip") == b"<html>ok</html>"


def test_unknown_encoding_stays_packed():
    assert _read(b"\x1b\x00br-bytes", "br") == b"\x1b\x00br-bytes"


def test_dataset_request_may_be_bigger():
    body = b"x" * (net.MAX_BODY + 10)
    assert len(_read(body, extensions={net.MAX_BODY_KEY: net.MAX_BODY * 2})) == len(body)


def test_sitemap_stays_on_the_site():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.url.path == "/robots.txt":
            return httpx.Response(
                200,
                text="Sitemap: http://10.0.0.1/sitemap.xml\nSitemap: https://www.site.test/s.xml",
            )
        if request.url.path == "/s.xml":
            return httpx.Response(
                200,
                text="<sitemapindex><sitemap><loc>https://other.test/x.xml</loc></sitemap>"
                "<sitemap><loc>https://site.test/p.xml</loc></sitemap></sitemapindex>",
            )
        return httpx.Response(
            200, text="<urlset><url><loc>https://site.test/a</loc></url></urlset>"
        )

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await sitemap_urls(client, "https://site.test/")

    assert asyncio.run(go()) == ["https://site.test/a"]
    assert seen == [
        "https://site.test/robots.txt",
        "https://www.site.test/s.xml",
        "https://site.test/p.xml",
    ]


class _Route:
    def __init__(self, url):
        self.request = type("Request", (), {"url": url})()
        self.done = ""

    async def fallback(self):
        self.done = "fallback"

    async def abort(self, code):
        self.done = code


def test_browser_requests_to_internal_addresses_are_aborted(monkeypatch):
    from suveren.render import BrowserSession

    async def resolve(host, port, timeout=None):
        if host == "gone.test":
            raise httpcore.ConnectError("gone.test: getaddrinfo failed")
        return await net.public_addresses(host, port, timeout)

    monkeypatch.setattr("suveren.render.public_addresses", resolve)
    session = BrowserSession()

    async def go(url):
        route = _Route(url)
        await session._only_public(route)
        return route.done

    assert asyncio.run(go("http://127.0.0.1:8080/admin")) == "blockedbyclient"
    assert asyncio.run(go("http://169.254.169.254/latest/meta-data")) == "blockedbyclient"
    assert asyncio.run(go("https://93.184.216.34/app.js")) == "fallback"
    # A name that does not resolve fails in the browser by itself.
    assert asyncio.run(go("https://gone.test/")) == "fallback"


def test_browser_lets_local_schemes_through_and_files_only_for_printing():
    from suveren.render import BrowserSession

    async def go(session, url):
        route = _Route(url)
        await session._only_public(route)
        return route.done

    scan = BrowserSession()
    assert asyncio.run(go(scan, "data:image/png;base64,AAAA")) == "fallback"
    assert asyncio.run(go(scan, "about:blank")) == "fallback"
    assert asyncio.run(go(scan, "blob:https://site.ru/1-2-3")) == "fallback"
    # A scanned page may not read the operator's disk.
    assert asyncio.run(go(scan, "file:///C:/Users/me/report.html")) == "blockedbyclient"
    printing = BrowserSession(allow_files=True)
    assert asyncio.run(go(printing, "file:///C:/Users/me/report.html")) == "fallback"
    assert asyncio.run(go(printing, "file:///home/me/reports/r.html")) == "fallback"
