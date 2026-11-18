"""--proxy: every connection goes through the operator's HTTP proxy as a tunnel to an
address checked here, so internal addresses stay off limits (net.py)."""

import asyncio

import httpx
import pytest

import suveren.cli as cli_module
from suveren import net, proxy
from suveren.cli import app
from suveren.collect import make_client
from suveren.egress import EgressProxy
from suveren.proxy import parse_proxy, set_proxy
from tests.test_release_221 import runner

PUBLIC = "93.184.215.14"


@pytest.fixture(autouse=True)
def _no_proxy_after():
    yield
    set_proxy(None)


class FakeProxy:
    """Answers CONNECT itself and then plays the site: no real network."""

    def __init__(self, status: bytes = b"200 Connection established") -> None:
        self.status = status
        self.heads: list[bytes] = []  # CONNECT heads
        self.inner: list[bytes] = []  # what came through the tunnel
        self.url = ""

    async def __aenter__(self) -> "FakeProxy":
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.url = f"http://127.0.0.1:{self._server.sockets[0].getsockname()[1]}"
        return self

    async def __aexit__(self, *exc: object) -> None:
        self._server.close()

    async def _serve(self, reader, writer) -> None:
        try:
            self.heads.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 " + self.status + b"\r\n\r\n")
            await writer.drain()
            if not self.status.startswith(b"200"):
                return
            data = await reader.readuntil(b"\r\n")
            if data.startswith((b"GET", b"HEAD")):
                data += await reader.readuntil(b"\r\n\r\n")
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
            else:
                writer.write(b"whois answer\r\n")
            self.inner.append(data)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


def test_parse_proxy():
    p = parse_proxy("http://user:p%40ss@proxy.corp:3128")
    assert (p.host, p.port, p.label) == ("proxy.corp", 3128, "proxy.corp:3128")
    assert p.auth == "Basic dXNlcjpwQHNz"  # user:p@ss
    assert parse_proxy("10.0.0.1:8080").label == "10.0.0.1:8080"
    for bad, why in (
        ("socks5://10.0.0.1:1080", "только HTTP-прокси"),
        ("https://proxy.corp:443", "только HTTP-прокси"),
        ("http://proxy.corp", "укажите порт"),
        ("http://proxy.corp:3128/path", "без пути"),
        ("http://proxy.corp:99999", "неверный порт"),
    ):
        with pytest.raises(ValueError, match=why):
            parse_proxy(bad)


def test_connect_request_names_the_address():
    p = parse_proxy("http://u:p@h:1")
    assert p.connect_request("2001:db8::1", 443).startswith(b"CONNECT [2001:db8::1]:443 HTTP/1.1")
    assert b"Proxy-Authorization: Basic dTpw\r\n" in p.connect_request(PUBLIC, 80)


async def _get(url: str) -> httpx.Response:
    async with make_client(5) as client:
        return await client.get(url)


def test_http_goes_through_the_proxy_to_the_checked_address(monkeypatch):
    async def resolve(host, port, timeout=None):
        assert host == "shop.example"
        return [PUBLIC]

    monkeypatch.setattr(net, "public_addresses", resolve)

    async def run():
        async with FakeProxy() as fake:
            set_proxy(fake.url.replace("http://", "http://user:secret@"))
            response = await _get("http://shop.example/page")
            return fake, response

    fake, response = asyncio.run(run())
    assert response.text == "hi"
    # The proxy is asked for the address checked here, never for the name.
    assert fake.heads[0].startswith(f"CONNECT {PUBLIC}:80 HTTP/1.1".encode())
    assert b"shop.example" not in fake.heads[0]
    assert b"Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=" in fake.heads[0]
    assert fake.inner[0].startswith(b"GET /page HTTP/1.1")
    assert b"Host: shop.example" in fake.inner[0]


def test_internal_addresses_stay_blocked_with_a_proxy():
    async def run():
        async with FakeProxy() as fake:
            set_proxy(fake.url)
            with pytest.raises(httpx.ConnectError, match="внутренний адрес"):
                await _get("http://10.0.0.1/")
            with pytest.raises(httpx.ConnectError, match="внутренний адрес"):
                await _get("http://127.0.0.1:8080/")
            return fake

    assert asyncio.run(run()).heads == []  # the proxy was never asked


def test_a_refusing_proxy_is_explained():
    async def run(status: bytes, match: str):
        async with FakeProxy(status) as fake:
            set_proxy(fake.url)
            with pytest.raises(httpx.ConnectError, match=match):
                await _get(f"http://{PUBLIC}/")

    asyncio.run(run(b"407 Proxy Authentication Required", "логин и пароль"))
    asyncio.run(run(b"403 Forbidden", "по IP-адресу"))


def test_an_unreachable_proxy_is_named():
    async def run():
        async with FakeProxy() as fake:
            url = fake.url
        set_proxy(url)  # closed now
        with pytest.raises(httpx.ConnectError, match=r"прокси 127\.0\.0\.1:\d+ недоступен"):
            await _get(f"http://{PUBLIC}/")

    asyncio.run(run())


def test_raw_sockets_go_through_the_proxy_too():
    """WHOIS and the TLS probes use open_public."""

    async def run():
        async with FakeProxy() as fake:
            set_proxy(fake.url)
            reader, writer = await net.open_public(PUBLIC, 43, 5)
            writer.write(b"example.ru\r\n")
            await writer.drain()
            answer = await reader.readline()
            writer.close()
            with pytest.raises(ConnectionRefusedError, match="внутренний адрес"):
                await net.open_public("10.1.2.3", 43, 5)
            return fake, answer

    fake, answer = asyncio.run(run())
    assert answer == b"whois answer\r\n"
    assert fake.heads[0].startswith(f"CONNECT {PUBLIC}:43 ".encode())
    assert fake.inner == [b"example.ru\r\n"]


def test_the_browser_goes_through_the_proxy():
    """--browser: the browser's own proxy (egress.py) opens its connections through
    open_public, so through --proxy as well."""

    async def run():
        async with FakeProxy() as fake, EgressProxy(5) as egress:
            set_proxy(fake.url)
            port = int(egress.url.rsplit(":", 1)[1])
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(f"CONNECT {PUBLIC}:443 HTTP/1.1\r\n\r\n".encode())
            await writer.drain()
            reply = await reader.readuntil(b"\r\n\r\n")
            writer.close()
            return fake, reply

    fake, reply = asyncio.run(run())
    assert reply.startswith(b"HTTP/1.1 200")
    assert fake.heads[0].startswith(f"CONNECT {PUBLIC}:443 ".encode())


def test_without_proxy_nothing_changes(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
    result = runner.invoke(app, ["scan", "not a domain"])
    assert "Прокси из окружения не используется" in result.output
    assert proxy.current() is None


def test_scan_says_where_it_goes_with_a_proxy(monkeypatch):
    monkeypatch.setattr(cli_module, "proxy_unreachable", lambda p: None)  # it answers
    monkeypatch.setenv("HTTPS_PROXY", "http://10.9.9.9:3128")
    result = runner.invoke(
        app, ["scan", "not a domain", "--proxy", "http://user:secret@10.0.0.1:3128"]
    )
    assert "через прокси 10.0.0.1:3128" in result.output
    assert "мимо прокси" in result.output
    assert "secret" not in result.output
    assert "Прокси из окружения" not in result.output
    # The next command without --proxy goes directly again.
    runner.invoke(app, ["scan", "not a domain"])
    assert proxy.current() is None


def test_a_dead_proxy_stops_the_run_instead_of_blaming_the_site(monkeypatch):
    # 2026-11-19: with a proxy that did not answer the report said "главная страница не
    # открылась… сайт недоступен" and gave a grade.
    def refuse(address, timeout):
        assert address == ("10.0.0.1", 3128) and timeout == proxy.PROBE_TIMEOUT
        raise ConnectionRefusedError(10061, "No connection could be made")

    monkeypatch.setattr(proxy.socket, "create_connection", refuse)
    result = runner.invoke(app, ["scan", "example.ru", "--proxy", "http://10.0.0.1:3128"])
    assert result.exit_code == 2
    assert "прокси 10.0.0.1:3128 не отвечает" in result.output
    assert "Общая оценка" not in result.output
    assert proxy.current() is None

    def slow(address, timeout):
        raise TimeoutError("timed out")

    monkeypatch.setattr(proxy.socket, "create_connection", slow)
    why = proxy.unreachable(proxy.parse_proxy("http://10.0.0.1:3128"))
    assert why and "не ответил вовремя" in why


def test_a_bad_proxy_address_stops_the_command():
    result = runner.invoke(app, ["company", "7707083893", "--proxy", "socks5://10.0.0.1:1080"])
    assert result.exit_code == 2
    assert "--proxy" in result.output and "только HTTP-прокси" in result.output


@pytest.mark.parametrize("command", ["scan", "batch", "company", "research", "doctor", "watch"])
def test_network_commands_take_proxy(command):
    assert "--proxy" in runner.invoke(app, [command, "--help"]).output
