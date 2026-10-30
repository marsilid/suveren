"""What a user reads when a request fails: words, not Python class names."""

import asyncio
import socket

import httpx
import pytest

from suveren.errors import ModuleError, describe

URL = "https://antifilter.download/list/domains.lst"


def status_error(code):
    request = httpx.Request("GET", URL)
    return httpx.HTTPStatusError(
        "x", request=request, response=httpx.Response(code, request=request)
    )


@pytest.mark.parametrize(
    ("exc", "said"),
    [
        (status_error(503), "сервер ответил кодом 503"),
        (status_error(429), "слишком много запросов, сервер просит подождать"),
        (httpx.ConnectError("All connection attempts failed"), "нет связи с сервером"),
        (httpx.ReadTimeout("timed out"), "сервер не ответил вовремя"),
        (TimeoutError(), "сервер не ответил вовремя"),
        (httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]"), "не удалось установить "
         "защищённое соединение"),
        (socket.gaierror(11001, "getaddrinfo failed"), "имя сервера не найдено в DNS"),
        (httpx.RemoteProtocolError("Server disconnected"), "сервер оборвал соединение"),
        (ConnectionResetError(), "сервер оборвал соединение"),
        (ValueError("Expecting value"), "ответ в неожиданном формате"),
        (ModuleError("реестр недоступен"), "реестр недоступен"),
    ],
)  # fmt: skip
def test_describe_says_what_happened(exc, said):
    assert describe(exc) == said


def test_a_download_error_names_no_class(tmp_path, monkeypatch):
    # The report said "не удалось скачать antifilter.download (HTTPStatusError)".
    from suveren.cache import fetch_cached

    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))

    async def go():
        transport = httpx.MockTransport(lambda r: httpx.Response(503))
        async with httpx.AsyncClient(transport=transport) as client:
            await fetch_cached(client, URL, "x.lst")

    with pytest.raises(ModuleError) as caught:
        asyncio.run(go())
    assert str(caught.value) == f"не удалось скачать {URL} (сервер ответил кодом 503)"
