"""Exception hierarchy used across Suveren."""

import asyncio
import socket
import ssl

import httpx


class SuverenError(Exception):
    """Base class for all expected Suveren errors."""


class InvalidTargetError(SuverenError, ValueError):
    """The user supplied something that is not a valid domain."""


class TargetNotFoundError(SuverenError):
    """The domain does not exist in DNS (NXDOMAIN)."""


class ModuleError(SuverenError):
    """A data source could not be queried; the message is shown to the user as-is."""


# asyncio.wait_for raises asyncio.TimeoutError, which only became the built-in
# TimeoutError in Python 3.11; catch both so 3.10 behaves the same.
TIMEOUTS: tuple[type[TimeoutError], type[asyncio.TimeoutError]] = (
    TimeoutError,
    asyncio.TimeoutError,
)


def describe(exc: BaseException) -> str:
    """Why a request failed, in words a user can act on. Reports said
    "(HTTPStatusError)" and "(ConnectError)": the name of a Python class."""
    if isinstance(exc, SuverenError):
        return str(exc)
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return "слишком много запросов, сервер просит подождать" if code == 429 else (
            f"сервер ответил кодом {code}"
        )  # fmt: skip
    if isinstance(exc, (httpx.TimeoutException, *TIMEOUTS)):
        return "сервер не ответил вовремя"
    text = str(exc).lower()
    if isinstance(exc, ssl.SSLError) or "certificate" in text or "ssl" in text:
        return "не удалось установить защищённое соединение"
    if isinstance(exc, socket.gaierror) or "getaddrinfo" in text or "name or service" in text:
        return "имя сервера не найдено в DNS"
    if isinstance(exc, (httpx.ConnectError, ConnectionRefusedError)):
        return "нет связи с сервером"
    if isinstance(exc, (httpx.RemoteProtocolError, httpx.ReadError, ConnectionError)):
        return "сервер оборвал соединение"
    if isinstance(exc, httpx.TooManyRedirects):
        return "слишком много перенаправлений"
    if isinstance(exc, (httpx.HTTPError, OSError)):
        return "ошибка сети"
    if isinstance(exc, (ValueError, KeyError, TypeError)):
        return "ответ в неожиданном формате"
    return f"непредвиденная ошибка ({type(exc).__name__})"
