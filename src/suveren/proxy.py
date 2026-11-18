"""``--proxy``: the operator's HTTP proxy as the way out to the internet.

Proxies from the environment stay ignored (net.py, ``proxy_note``): a proxy resolves
names itself, past the check that keeps requests off internal addresses. An explicit
``--proxy`` keeps that check: the name is still resolved and checked here, and the
proxy is asked for a tunnel (CONNECT) to the checked address, not to the name. So the
proxy resolves nothing, and a DNS answer changed in between cannot reach an internal
address through it. TLS runs inside the tunnel and is checked against the site's name,
as without a proxy.

The proxy sees which addresses are opened and, from TLS (SNI) and plain HTTP, the
sites' names. DNS queries (the site's records, mail, DoT) do not go through it.
"""

from __future__ import annotations

import asyncio
import base64
import socket
from collections.abc import Iterable
from dataclasses import dataclass
from ssl import SSLContext
from typing import Any
from urllib.parse import unquote, urlsplit

import httpcore

# A proxy's answer to CONNECT is a status line and a few headers.
MAX_HEAD = 16 * 1024


@dataclass(frozen=True, slots=True)
class Proxy:
    host: str
    port: int
    auth: str = ""  # the Proxy-Authorization value, or ""

    @property
    def label(self) -> str:
        """host:port, never the login and password."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    def connect_request(self, ip: str, port: int) -> bytes:
        target = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        head = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
        if self.auth:
            head += f"Proxy-Authorization: {self.auth}\r\n"
        return (head + "\r\n").encode("latin-1")


def parse_proxy(url: str) -> Proxy:
    """``http://[login:password@]host:port``; ValueError with the reason in Russian."""
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    parts = urlsplit(raw)
    if parts.scheme.lower() != "http":
        raise ValueError(
            "поддерживается только HTTP-прокси вида http://узел:порт (HTTPS- и SOCKS-прокси нет)"
        )
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"неверный порт прокси в «{_safe(parts)}»") from exc
    if not parts.hostname:
        raise ValueError("в адресе прокси нет узла: нужно http://узел:порт")
    if port is None:
        raise ValueError(f"укажите порт прокси: http://{parts.hostname}:3128")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("адрес прокси — только http://узел:порт, без пути")
    auth = ""
    if parts.username is not None:
        login = f"{unquote(parts.username)}:{unquote(parts.password or '')}"
        auth = "Basic " + base64.b64encode(login.encode("utf-8")).decode("ascii")
    return Proxy(parts.hostname, port, auth)


def _safe(parts: Any) -> str:
    return str(parts.netloc).rpartition("@")[2]


_CURRENT: list[Proxy] = []


def set_proxy(url: str | None) -> Proxy | None:
    """Use ``url`` for every connection of this run; None: connect directly."""
    _CURRENT.clear()
    if url:
        _CURRENT.append(parse_proxy(url))
    return current()


def current() -> Proxy | None:
    return _CURRENT[0] if _CURRENT else None


PROBE_TIMEOUT = 5.0


def unreachable(proxy: Proxy, timeout: float = PROBE_TIMEOUT) -> str | None:
    """Why the proxy cannot be reached, or None when it accepts a connection. A dead
    --proxy made every request fail and the report blamed the site: "главная страница
    не открылась… сайт недоступен" (2026-11-19), so the run stops before it starts."""
    try:
        socket.create_connection((proxy.host, proxy.port), timeout=timeout).close()
    except OSError as exc:
        why = "не ответил вовремя" if isinstance(exc, TimeoutError) else "соединение не открылось"
        return f"прокси {proxy.label} не отвечает: {why} ({exc.strerror or exc})"
    return None


def warning(proxy: Proxy) -> str:
    """What the operator is told when a run goes through the proxy."""
    return (
        f"Все соединения идут через прокси {proxy.label}: он видит, какие адреса открываются, "
        "и имена проверяемых сайтов (в TLS и HTTP). Запросы на внутренние адреса по-прежнему "
        "не отправляются. DNS-запросы (записи сайта, почта, DNS-серверы) идут напрямую, "
        "мимо прокси."
    )


def _check_reply(head: bytes, proxy: Proxy, ip: str, port: int) -> None:
    line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
    fields = line.split(" ", 2)
    code = fields[1] if len(fields) > 1 else ""
    if code == "200":
        return
    if code == "407":
        why = "нужны логин и пароль (http://логин:пароль@узел:порт), либо они не подошли"
    elif code in ("403", "405"):
        why = (
            f"он отказал ({line[:80]}): возможно, прокси не открывает соединения по IP-адресу "
            "или на этот порт"
        )
    else:
        why = f"он ответил «{line[:80]}»"
    raise httpcore.ConnectError(f"прокси {proxy.label} не открыл соединение с {ip}:{port}: {why}")


def _unreachable(proxy: Proxy, exc: BaseException) -> httpcore.ConnectError:
    return httpcore.ConnectError(f"прокси {proxy.label} недоступен ({exc or type(exc).__name__})")


async def httpcore_tunnel(
    backend: httpcore.AsyncNetworkBackend,
    proxy: Proxy,
    ip: str,
    port: int,
    timeout: float | None,
    local_address: str | None = None,
    socket_options: Iterable[Any] | None = None,
) -> httpcore.AsyncNetworkStream:
    """A stream to the checked ``ip`` through the proxy, for httpx (net.py's backend)."""
    try:
        stream = await backend.connect_tcp(
            proxy.host, proxy.port, timeout, local_address, socket_options
        )
    except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
        raise _unreachable(proxy, exc) from exc
    try:
        await stream.write(proxy.connect_request(ip, port), timeout)
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = await stream.read(4096, timeout)
            if not chunk or len(head) + len(chunk) > MAX_HEAD:
                raise httpcore.ConnectError(f"прокси {proxy.label} не ответил на CONNECT")
            head += chunk
        if not head.endswith(b"\r\n\r\n"):
            # Bytes after the answer before anything was sent: not the site's.
            raise httpcore.ConnectError(f"прокси {proxy.label} ответил не по протоколу")
        _check_reply(head, proxy, ip, port)
    except BaseException:
        await stream.aclose()
        raise
    return stream


async def open_tunnel(
    proxy: Proxy,
    ip: str,
    port: int,
    timeout: float,
    *,
    ssl: SSLContext | None = None,
    server_hostname: str | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """``asyncio.open_connection`` to the checked ``ip`` through the proxy (raw sockets:
    TLS probes, WHOIS, the browser's own proxy). Refusals are ``OSError``."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port), timeout
        )
    except OSError as exc:
        raise ConnectionRefusedError(str(_unreachable(proxy, exc))) from exc
    try:
        writer.write(proxy.connect_request(ip, port))
        await writer.drain()
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise ConnectionRefusedError(f"прокси {proxy.label} не ответил на CONNECT") from exc
        try:
            _check_reply(head, proxy, ip, port)
        except httpcore.ConnectError as exc:
            raise ConnectionRefusedError(str(exc)) from exc
        if ssl is not None:
            await asyncio.wait_for(writer.start_tls(ssl, server_hostname=server_hostname), timeout)
    except BaseException:
        writer.close()
        raise
    return reader, writer
