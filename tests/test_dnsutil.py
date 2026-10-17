import asyncio

import dns.nameserver
import pytest

from suveren import dnsutil
from suveren.dnsutil import (
    NOTE_DOH,
    NOTE_DOT,
    DohResolver,
    DotResolver,
    SystemResolver,
    create_resolver,
    parse_doh_answer,
)


@pytest.fixture(autouse=True)
def fresh_health(monkeypatch):
    """Health answers are cached per process; every test starts from scratch."""
    monkeypatch.setattr(dnsutil, "_system_healthy", None)
    monkeypatch.setattr(dnsutil, "_dot_healthy", None)


def _health(monkeypatch, *, system: bool, dot: bool) -> None:
    async def healthy(self) -> bool:
        return dot if isinstance(self, DotResolver) else system

    monkeypatch.setattr(SystemResolver, "is_healthy", healthy)


def _pick(mode: str = "auto"):
    return asyncio.run(create_resolver(mode, 5.0, client=None))  # type: ignore[arg-type]


def test_auto_keeps_a_working_system_resolver(monkeypatch):
    _health(monkeypatch, system=True, dot=True)
    resolver, note = _pick()
    assert type(resolver) is SystemResolver
    assert note is None


def test_auto_falls_back_to_yandex_dot(monkeypatch):
    _health(monkeypatch, system=False, dot=True)
    resolver, note = _pick()
    assert isinstance(resolver, DotResolver)
    assert note == NOTE_DOT


def test_auto_uses_foreign_doh_last_and_says_so(monkeypatch):
    _health(monkeypatch, system=False, dot=False)
    resolver, note = _pick()
    assert isinstance(resolver, DohResolver)
    assert note == NOTE_DOH
    assert "--dns ru" in note


def test_ru_mode_never_falls_back_abroad(monkeypatch):
    _health(monkeypatch, system=False, dot=False)
    resolver, note = _pick("ru")
    assert isinstance(resolver, DotResolver)
    assert note is None


def test_dot_resolver_talks_to_yandex_over_tls():
    servers = DotResolver(5.0)._resolver.nameservers
    assert {s.address for s in servers} == {"77.88.8.8", "77.88.8.1"}
    assert all(isinstance(s, dns.nameserver.DoTNameserver) for s in servers)
    assert all(s.hostname == "common.dot.dns.yandex.net" for s in servers)


def test_parse_doh_answer_joins_txt_parts():
    payload = {"Status": 0, "Answer": [{"type": 16, "data": '"v=spf1 " "-all"'}]}
    assert parse_doh_answer(payload, "TXT") == ["v=spf1 -all"]
