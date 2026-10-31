"""How render.py starts the browser: with the sandbox, through the checked proxy."""

import asyncio
import sys
import types

import pytest

from suveren import render
from suveren.errors import ModuleError
from suveren.render import BrowserSession, launch_options


def test_launch_options_keep_the_sandbox_and_the_proxy():
    opts = launch_options("msedge", "http://127.0.0.1:5555")
    assert opts["chromium_sandbox"] is True
    assert opts["headless"] is True and opts["channel"] == "msedge"
    assert opts["proxy"] == {"server": "http://127.0.0.1:5555"}
    assert "--no-sandbox" not in opts["args"]


class _Error(Exception):
    pass


def _fake_playwright(launched: list[dict], fail: bool = False):
    """A stand-in for playwright.async_api that records the launch arguments."""

    class Chromium:
        async def launch(self, **kwargs):
            launched.append(kwargs)
            if fail:  # what Chromium does when its sandbox cannot start (root, no userns)
                raise _Error("Failed to launch: No usable sandbox!")
            return types.SimpleNamespace(new_context=self.context, close=self.close)

        async def context(self, **kwargs):
            async def route(*args):
                return None

            async def close():
                return None

            return types.SimpleNamespace(route=route, close=close)

        async def close(self):
            return None

    class Manager:
        async def __aenter__(self):
            return types.SimpleNamespace(chromium=Chromium())

        async def __aexit__(self, *exc):
            return None

    module = types.ModuleType("playwright.async_api")
    module.Error = _Error
    module.async_playwright = Manager
    return module


@pytest.fixture
def fake(monkeypatch):
    def install(fail=False):
        launched: list[dict] = []
        monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
        monkeypatch.setitem(sys.modules, "playwright.async_api", _fake_playwright(launched, fail))
        return launched

    return install


def test_the_browser_is_launched_with_the_sandbox(fake):
    launched = fake()

    async def go():
        async with BrowserSession() as session:
            return session.browser_name

    assert asyncio.run(go()) == render.CHANNELS[0]
    assert launched and all(k["chromium_sandbox"] is True for k in launched)
    assert all("--no-sandbox" not in k["args"] for k in launched)


def test_a_browser_without_a_sandbox_is_not_used(fake):
    launched = fake(fail=True)

    async def go():
        async with BrowserSession():
            pass

    with pytest.raises(ModuleError, match="не найден браузер") as err:
        asyncio.run(go())
    assert "песочниц" in str(err.value) and "root" in str(err.value)
    assert len(launched) == len(render.CHANNELS)


def test_docker_image_does_not_run_as_root():
    """The sandbox does not start as root, so --browser in Docker needs another user."""
    from pathlib import Path

    lines = (Path(__file__).parent.parent / "Dockerfile").read_text("utf-8").splitlines()
    users = [line.split()[1] for line in lines if line.startswith("USER ")]
    entry = next(i for i, line in enumerate(lines) if line.startswith("ENTRYPOINT"))
    last_user = max(i for i, line in enumerate(lines) if line.startswith("USER "))
    assert users and users[-1] not in ("root", "0") and last_user < entry
