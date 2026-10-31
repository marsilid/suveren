"""Checks written by others, run inside a scan: Suveren's answer to Nmap's NSE.

A plugin is a Python file (or an importable module) that defines:

    NAME = "security.txt"                       # shown when it fails
    async def run(ctx: PluginContext) -> list[Check]: ...

It gets what the scan already collected (the home page, its headers, the domain, the
services found) and an HTTP client, and returns ordinary checks. Their IDs must have
the plugin's own prefix, "VENDOR-AREA-001", never "SUV-", so they cannot shadow or
be mistaken for Suveren's checks; an ID that breaks the rule turns into a "not
checked" verdict that says why.

Plugins run only when named: ``suveren scan site.ru --plugin path/to/check.py``.
Loading one runs its code, as importing any Python module does; run only plugins you
trust, as you would any other program. A plugin that raises, calls ``sys.exit`` or
hangs, even in a blocking call such as ``time.sleep``, costs only its own verdict: it
runs in its own thread with its own event loop and HTTP client, so the scan goes on
and the report says what happened.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import importlib.util
import inspect
import re
import sys
import threading
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx

from suveren.checks import Check, Status
from suveren.errors import SuverenError

GROUP_PLUGINS = "Проверки из плагинов"
TIMEOUT = 60.0  # seconds per plugin
PLUGIN_ID = re.compile(r"^(?!SUV-)[A-Z][A-Z0-9]{1,15}-[A-Z0-9]{1,15}-[0-9]{3}$")


class PluginError(SuverenError):
    """A plugin could not be loaded."""


@dataclass(frozen=True, slots=True)
class PluginContext:
    """What a plugin may read. The page and headers are those the scan saw."""

    host: str
    domain: str
    final_url: str | None
    html: str
    headers: dict[str, str]
    services: list[dict[str, Any]] = field(default_factory=list)  # Dependency.to_dict()
    client: httpx.AsyncClient | None = None


@dataclass(frozen=True, slots=True)
class Plugin:
    name: str
    source: str
    module: ModuleType


def load(spec: str) -> Plugin:
    """A plugin from a file path ("checks/sec_txt.py") or a module name ("acme.checks")."""
    path = Path(spec)
    try:
        if path.suffix == ".py":
            if not path.is_file():
                raise PluginError(f"плагин {spec} не найден")
            module_spec = importlib.util.spec_from_file_location(
                f"suveren_plugin_{path.stem}", path
            )
            if module_spec is None or module_spec.loader is None:
                raise PluginError(f"плагин {spec} не загружается")
            module = importlib.util.module_from_spec(module_spec)
            # dataclasses and typing look the module up by name while it loads.
            sys.modules[module_spec.name] = module
            try:
                module_spec.loader.exec_module(module)
            except BaseException:
                sys.modules.pop(module_spec.name, None)
                raise
        else:
            module = importlib.import_module(spec)
    except PluginError:
        raise
    except (Exception, SystemExit) as exc:  # a plugin's import error must say where it came from
        raise PluginError(f"плагин {spec} не загрузился: {exc!r:.200}") from exc
    run = getattr(module, "run", None)
    if not callable(run) or not inspect.iscoroutinefunction(run):
        raise PluginError(f"в плагине {spec} нет функции async def run(ctx)")
    return Plugin(str(getattr(module, "NAME", path.stem or spec)), spec, module)


class PluginCrashed(Exception):
    """A plugin ended with a BaseException that is not an Exception (SystemExit,
    KeyboardInterrupt, CancelledError): raised as is into the scan's loop, it would stop
    or cancel the whole scan. ``str()`` is the original's repr."""

    def __init__(self, original: BaseException) -> None:
        super().__init__(repr(original))


def _broken(plugin: Plugin, why: str) -> Check:
    return Check(
        GROUP_PLUGINS,
        f"Плагин «{plugin.name}»",
        Status.UNKNOWN,
        f"Не проверено: {why}.",
        id="PLUGIN-ERROR-000",
    )


async def _in_thread(plugin: Plugin, ctx: PluginContext, timeout: float) -> Any:
    """``run(ctx)`` in a daemon thread with its own loop and client: a plugin that
    blocks cannot stall the scan, and one left hanging does not hold up the exit."""
    from suveren import collect

    loop = asyncio.get_running_loop()
    done: asyncio.Future[Any] = loop.create_future()

    def settle(result: Any, error: BaseException | None) -> None:
        if done.done():
            return
        if error is None:
            done.set_result(result)
        else:
            done.set_exception(error)

    async def go() -> Any:
        async with collect.make_client(min(timeout, 30.0)) as client:
            return await plugin.module.run(replace(ctx, client=client))

    def report(result: Any, error: BaseException | None) -> None:
        # A plugin cut by the timeout may finish after the scan closed its loop:
        # nobody waits for that answer any more.
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(settle, result, error)

    def target() -> None:
        try:
            result = asyncio.run(go())
        except Exception as exc:
            report(None, exc)
        except BaseException as exc:  # SystemExit, Ctrl+C, cancel: they end this thread only
            report(None, PluginCrashed(exc))
        else:
            report(result, None)

    threading.Thread(target=target, name=f"plugin {plugin.name}", daemon=True).start()
    return await done


async def run_plugin(plugin: Plugin, ctx: PluginContext, timeout: float = TIMEOUT) -> list[Check]:
    try:
        result = await asyncio.wait_for(_in_thread(plugin, ctx, timeout), timeout)
    except TimeoutError:
        return [_broken(plugin, f"плагин не уложился в {timeout:.0f} с")]
    except PluginCrashed as exc:
        return [_broken(plugin, f"плагин завершился с ошибкой {exc!s:.200}")]
    except Exception as exc:  # isolate the plugin: its bug is not the scan's
        return [_broken(plugin, f"плагин завершился с ошибкой {exc!r:.200}")]
    if not isinstance(result, list) or not all(isinstance(c, Check) for c in result):
        return [_broken(plugin, "плагин вернул не список проверок Check")]
    checks = []
    for check in result:
        if not PLUGIN_ID.match(check.id or ""):
            checks.append(
                _broken(
                    plugin,
                    f"ID «{check.id}» не по правилу: свой префикс, например ACME-WEB-001, "
                    "и никогда SUV-",
                )
            )
            continue
        checks.append(check)
    return checks


async def run_plugins(plugins: list[Plugin], ctx: PluginContext) -> list[Check]:
    checks: list[Check] = []
    for plugin in plugins:
        checks += await run_plugin(plugin, ctx)
    return checks
