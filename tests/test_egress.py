"""The browser's proxy and raw sockets (TLS, WHOIS) go to public addresses only."""

import asyncio
import socket

import pytest

from suveren import net
from suveren.collect import whois_query
from suveren.egress import EgressProxy


async def _ask(proxy_url: str, head: bytes) -> bytes:
    host, port = proxy_url.removeprefix("http://").split(":")
    reader, writer = await asyncio.open_connection(host, int(port))
    writer.write(head)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), 5)
    writer.close()
    return data


async def _site(seen: list[bytes]) -> tuple[asyncio.Server, int]:
    """A local 'site' that records the request it got and answers it."""

    async def serve(reader, writer):
        seen.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


@pytest.mark.parametrize("target", ["127.0.0.1:8080", "169.254.169.254:80", "[::1]:443"])
def test_tunnel_to_internal_address_is_refused(target):
    async def go():
        async with EgressProxy(timeout=5) as proxy:
            return await _ask(proxy.url, f"CONNECT {target} HTTP/1.1\r\n\r\n".encode())

    assert asyncio.run(go()).startswith(b"HTTP/1.1 403")


def test_name_that_turns_internal_is_refused(monkeypatch):
    """DNS rebinding: the proxy resolves the name itself, at connection time."""

    async def getaddrinfo(self, host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", port))]

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", getaddrinfo)

    async def go():
        async with EgressProxy(timeout=5) as proxy:
            ws = b"CONNECT rebind.test:443 HTTP/1.1\r\n\r\n"
            page = b"GET http://rebind.test/admin HTTP/1.1\r\nHost: rebind.test\r\n\r\n"
            return await _ask(proxy.url, ws), await _ask(proxy.url, page)

    tunnel, plain = asyncio.run(go())
    assert tunnel.startswith(b"HTTP/1.1 403") and plain.startswith(b"HTTP/1.1 403")


def test_plain_http_is_forwarded_one_request_per_connection(monkeypatch):
    monkeypatch.setenv(net.ALLOW_PRIVATE_ENV, "1")
    seen: list[bytes] = []

    async def go():
        site, port = await _site(seen)
        async with site, EgressProxy(timeout=5) as proxy:
            head = (
                f"GET http://127.0.0.1:{port}/a?b=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"
            )
            return await _ask(proxy.url, head.encode())

    answer = asyncio.run(go())
    assert answer.endswith(b"\r\n\r\nok")
    request = seen[0].decode()
    assert request.startswith("GET /a?b=1 HTTP/1.1\r\n")
    assert "Proxy-Connection" not in request and "Connection: close" in request


def test_tunnel_to_allowed_address_carries_bytes(monkeypatch):
    monkeypatch.setenv(net.ALLOW_PRIVATE_ENV, "1")
    seen: list[bytes] = []

    async def go():
        site, port = await _site(seen)
        async with site, EgressProxy(timeout=5) as proxy:
            head = f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n"
            return await _ask(proxy.url, head.encode())

    answer = asyncio.run(go())
    assert answer.startswith(b"HTTP/1.1 200 Connection Established\r\n\r\nHTTP/1.1 200 OK")
    assert seen == [b"GET / HTTP/1.1\r\n\r\n"]


def test_raw_sockets_refuse_internal_addresses():
    with pytest.raises(ConnectionRefusedError, match=net.BLOCKED):
        asyncio.run(net.open_public("127.0.0.1", 443, 5))
    # A WHOIS referral to an internal server is not followed.
    with pytest.raises(OSError, match=net.BLOCKED):
        asyncio.run(whois_query("10.0.0.1", "example.ru", 5))


def test_proxy_from_environment_is_not_used(monkeypatch):
    """A proxy would resolve names itself, past the address check."""
    from suveren.collect import make_client

    monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://10.0.0.1:3128")
    client = make_client(5)
    assert not client._mounts
    asyncio.run(client.aclose())
