"""A local proxy that is the browser's only way out (``--browser``).

The browser resolves names on its own, so a request check in Playwright cannot see
a DNS answer that changes between the check and the load (DNS rebinding), and it
does not see WebSocket connections at all. Behind this proxy the browser resolves
nothing: every connection, HTTPS, WebSocket and plain HTTP alike, is opened here
through ``open_public``, so it goes to a checked public address (see net.py).
"""

from __future__ import annotations

import asyncio
import contextlib
from urllib.parse import urlsplit

from suveren.net import open_public

# A request head bigger than this is not a browser's.
MAX_HEAD = 64 * 1024
# Hop-by-hop headers meant for the proxy, not for the site.
_PROXY_HEADERS = (b"proxy-connection:", b"proxy-authorization:", b"connection:", b"keep-alive:")


class EgressProxy:
    """``async with EgressProxy(timeout) as proxy`` → ``proxy.url`` for Playwright."""

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout
        self.url = ""
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    async def __aenter__(self) -> EgressProxy:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        port = self._server.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._server is not None:
            self._server.close()
        for task in list(self._tasks):
            task.cancel()
        if self._server is not None:
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        try:
            await self._handle(reader, writer)
        except (OSError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            if task is not None:
                self._tasks.discard(task)
            writer.close()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.timeout)
        if len(head) > MAX_HEAD:
            return
        line, _, rest = head.partition(b"\r\n")
        method, target, version = line.decode("latin-1").split(" ", 2)
        if method == "CONNECT":
            host, _, port = target.rpartition(":")
            upstream = await self._open(writer, host.strip("[]"), int(port))
            if upstream is None:
                return
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await _pipe(reader, writer, *upstream)
            return
        url = urlsplit(target)
        if url.scheme != "http" or not url.hostname:
            await _refuse(writer, b"400 Bad Request")
            return
        upstream = await self._open(writer, url.hostname, url.port or 80)
        if upstream is None:
            return
        # One request per connection: the browser may send the next one, for another
        # host, down the same proxy connection, so the site is asked to close.
        path = url.path or "/"
        if url.query:
            path += "?" + url.query
        headers = [h for h in rest.split(b"\r\n") if h and not h.lower().startswith(_PROXY_HEADERS)]
        out = f"{method} {path} {version}\r\n".encode("latin-1")
        out += b"".join(h + b"\r\n" for h in headers) + b"Connection: close\r\n\r\n"
        upstream[1].write(out)
        await _pipe(reader, writer, *upstream)

    async def _open(
        self, writer: asyncio.StreamWriter, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        try:
            return await open_public(host, port, self.timeout)
        except (OSError, TimeoutError):
            # The browser shows it as a failed load, as it would an unreachable host.
            await _refuse(writer, b"403 Forbidden")
            return None


async def _refuse(writer: asyncio.StreamWriter, status: bytes) -> None:
    writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    with contextlib.suppress(OSError):
        await writer.drain()


async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    up_reader: asyncio.StreamReader,
    up_writer: asyncio.StreamWriter,
) -> None:
    async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while data := await src.read(65536):
                dst.write(data)
                await dst.drain()
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError, RuntimeError):
                dst.write_eof()

    # The site's side decides: once it has closed, nothing more goes up.
    upward = asyncio.create_task(copy(reader, up_writer))
    try:
        await copy(up_reader, writer)
    finally:
        upward.cancel()
        up_writer.close()
