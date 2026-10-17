import asyncio

import httpx

from suveren.doctor import _timed
from suveren.errors import ModuleError

RKN = "Реестр операторов ПДн (РКН)"


def _fails_with(exc: BaseException, cause: BaseException | None = None):
    async def probe() -> str:
        if cause is not None:
            raise exc from cause
        raise exc

    return probe


def _run(name: str, probe, *, abroad: bool):
    return asyncio.run(_timed(name, probe, abroad=abroad))


def test_timeout_of_russian_source_is_broken_at_home():
    error = ModuleError("реестр Роскомнадзора недоступен (ConnectTimeout)")
    probe = _fails_with(error, httpx.ConnectTimeout("timed out"))
    assert _run(RKN, probe, abroad=False).ok is False


def test_timeout_of_russian_source_is_not_checked_abroad():
    error = ModuleError("реестр Роскомнадзора недоступен (ConnectTimeout)")
    result = _run(RKN, _fails_with(error, httpx.ConnectTimeout("timed out")), abroad=True)
    assert result.ok is None
    assert "из-за границы" in result.details


def test_wrong_answer_is_broken_even_abroad():
    error = ModuleError("Сбербанк не найден в реестре: изменилась вёрстка?")
    assert _run(RKN, _fails_with(error), abroad=True).ok is False


def test_other_sources_still_fail_abroad():
    probe = _fails_with(httpx.ConnectTimeout("timed out"))
    assert _run("Санкции: США (OFAC SDN)", probe, abroad=True).ok is False
