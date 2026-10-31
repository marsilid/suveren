"""Network limits for every HTTP client: public addresses only, bounded bodies.

A scanned site is hostile input. Without these limits a redirect to
``http://127.0.0.1:8080/`` or a name that resolves to ``10.0.0.1`` makes the
operator's machine query its own network (SSRF), and a 10 MB gzip that unpacks to
10 GB eats its memory.

The address check sits in the connection itself: the name is resolved once, every
address is checked, and the socket goes to a checked address. So each redirect hop
is covered, and a DNS answer that changes between the check and the connection
(DNS rebinding) cannot slip through. ``SUVEREN_ALLOW_PRIVATE=1`` lifts it for an
operator who audits a site in their own network on purpose.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import zlib
from collections.abc import AsyncIterator, Iterable
from typing import Any

import httpcore
import httpx

# Bytes read from the wire and bytes after unpacking, per response. A page or a
# script bundle is far smaller; a bigger answer is cut, not read to the end.
MAX_BODY = 10 * 1024 * 1024
# Request extension that raises the limit for one request (cached datasets).
MAX_BODY_KEY = "suveren_max_body"

# Only what bound_body can unpack within its limit.
ACCEPT_ENCODING = "gzip, deflate"
BLOCKED = "внутренний адрес"
ALLOW_PRIVATE_ENV = "SUVEREN_ALLOW_PRIVATE"


def is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def _allow_private() -> bool:
    return os.environ.get(ALLOW_PRIVATE_ENV) == "1"


async def public_addresses(host: str, port: int, timeout: float | None = None) -> list[str]:
    """Addresses of ``host``; refuses the whole name if any of them is not public,
    so a name cannot mix a public address with an internal one."""
    try:
        addrs = [ipaddress.ip_address(host.strip("[]"))]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout
            )
        except TimeoutError as exc:
            raise httpcore.ConnectTimeout(f"{host}: DNS не ответил вовремя") from exc
        except OSError as exc:
            raise httpcore.ConnectError(f"{host}: getaddrinfo failed ({exc})") from exc
        # An IPv6 link-local answer carries a zone ("fe80::1%3").
        addrs = list(dict.fromkeys(ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in infos))
    if not _allow_private():
        for ip in addrs:
            if not is_public(ip):
                raise httpcore.ConnectError(f"{host} ведёт на {BLOCKED} {ip}, запрос не отправлен")
    return [str(ip) for ip in addrs]


async def open_public(
    host: str, port: int, timeout: float, **kwargs: Any
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """``asyncio.open_connection`` to a checked address of ``host`` (raw sockets:
    TLS handshakes, WHOIS, the browser's proxy). TLS passes ``server_hostname``, so
    the certificate is still checked against the name. Refusals are ``OSError``."""
    try:
        addrs = await public_addresses(host, port, timeout)
    except httpcore.ConnectTimeout as exc:
        raise TimeoutError(str(exc)) from exc
    except httpcore.ConnectError as exc:
        raise ConnectionRefusedError(str(exc)) from exc
    last: Exception | None = None
    for ip in addrs:
        try:
            return await asyncio.wait_for(asyncio.open_connection(ip, port, **kwargs), timeout)
        except OSError as exc:
            last = exc
    raise last or ConnectionRefusedError(f"{host}: нет адресов")


class _PublicOnlyBackend(httpcore.AsyncNetworkBackend):
    """Resolves the name itself and connects only to checked addresses."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend) -> None:
        self._inner = inner

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        last: Exception | None = None
        for ip in await public_addresses(host, port, timeout):
            try:
                # TLS still checks the certificate against the name: httpcore
                # passes the request's host as server_hostname, not this address.
                return await self._inner.connect_tcp(
                    ip, port, timeout, local_address, socket_options
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        raise last or httpcore.ConnectError(f"{host}: нет адресов")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("unix sockets are not used")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def guarded_transport(*, verify: bool = True) -> httpx.AsyncHTTPTransport:
    transport = httpx.AsyncHTTPTransport(verify=verify, limits=httpx.Limits(max_connections=20))
    # httpx has no public way to pass a network backend; the pool keeps it here.
    pool = transport._pool
    pool._network_backend = _PublicOnlyBackend(pool._network_backend)
    return transport


class _Inflate:
    """gzip or deflate (zlib-wrapped, or raw as some servers send it), unpacked
    no further than asked."""

    def __init__(self, encoding: str) -> None:
        self._raw_fallback = encoding == "deflate"
        wbits = zlib.MAX_WBITS | 16 if encoding in ("gzip", "x-gzip") else zlib.MAX_WBITS
        self._obj = zlib.decompressobj(wbits)

    def __call__(self, data: bytes, limit: int) -> bytes:
        try:
            out = self._obj.decompress(data, limit)
        except zlib.error as exc:
            if not self._raw_fallback:
                raise httpx.DecodingError(f"сжатие повреждено ({exc})") from exc
            self._obj = zlib.decompressobj(-zlib.MAX_WBITS)
            out = self._obj.decompress(data, limit)
        self._raw_fallback = False
        return out

    @property
    def has_more(self) -> bool:
        return bool(self._obj.unconsumed_tail)


class _BoundedStream(httpx.AsyncByteStream):
    def __init__(self, inner: httpx.AsyncByteStream, inflate: _Inflate | None, limit: int):
        self._inner = inner
        self._inflate = inflate
        self._limit = limit

    async def __aiter__(self) -> AsyncIterator[bytes]:
        left_raw = left = self._limit
        async for chunk in self._inner:
            chunk = chunk[:left_raw]
            left_raw -= len(chunk)
            data = self._inflate(chunk, left) if self._inflate else chunk
            left -= len(data)
            if data:
                yield data
            if left_raw <= 0 or left <= 0 or (self._inflate and self._inflate.has_more):
                break

    async def aclose(self) -> None:
        await self._inner.aclose()


async def bound_body(response: httpx.Response) -> None:
    """Response hook: cut the body at the limit, before and after unpacking.

    Unpacking moves here from httpx so it can stop early; an encoding other than
    gzip or deflate (not asked for) is left packed rather than unpacked unbounded.
    """
    if hasattr(response, "_content"):  # already read (a test transport)
        return
    limit = response.request.extensions.get(MAX_BODY_KEY, MAX_BODY)
    encodings = [
        e.strip()
        for e in response.headers.get("content-encoding", "").lower().split(",")
        if e.strip() not in ("", "identity")
    ]
    inflate = None
    if len(encodings) == 1 and encodings[0] in ("gzip", "x-gzip", "deflate"):
        inflate = _Inflate(encodings[0])
    if isinstance(response.stream, httpx.AsyncByteStream):
        response.headers.pop("content-encoding", None)
        response.stream = _BoundedStream(response.stream, inflate, limit)
