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
trust, as you would any other program. A plugin that raises or hangs costs only its
own verdict: the scan goes on and the report says what happened.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import inspect
import re
from dataclasses import dataclass, field
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
            module_spec.loader.exec_module(module)
        else:
            module = importlib.import_module(spec)
    except PluginError:
        raise
    except Exception as exc:  # a plugin's own import error must say where it came from
        raise PluginError(f"плагин {spec} не загрузился: {exc!r:.200}") from exc
    run = getattr(module, "run", None)
    if not callable(run) or not inspect.iscoroutinefunction(run):
        raise PluginError(f"в плагине {spec} нет функции async def run(ctx)")
    return Plugin(str(getattr(module, "NAME", path.stem or spec)), spec, module)


def _broken(plugin: Plugin, why: str) -> Check:
    return Check(
        GROUP_PLUGINS,
        f"Плагин «{plugin.name}»",
        Status.UNKNOWN,
        f"Не проверено: {why}.",
        id="PLUGIN-ERROR-000",
    )


class PluginCrashed(Exception):
    """A plugin ended with a BaseException that is not an Exception (SystemExit,
    KeyboardInterrupt, CancelledError): left as is, it would stop or cancel the whole
    scan. ``str()`` is the original's repr."""

    def __init__(self, original: BaseException) -> None:
        super().__init__(repr(original))


async def _guarded(plugin: Plugin, ctx: PluginContext) -> Any:
    """``run(ctx)`` with its BaseExceptions turned into PluginCrashed inside the
    coroutine: a KeyboardInterrupt that leaves a task stops the event loop itself."""
    try:
        return await plugin.module.run(ctx)
    except asyncio.CancelledError as exc:
        task = asyncio.current_task()
        if task is not None and task.cancelling():
            raise  # the timeout or the scan itself cancels the plugin: not its fault
        raise PluginCrashed(exc) from None
    except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
        raise PluginCrashed(exc) from None


async def run_plugin(plugin: Plugin, ctx: PluginContext, timeout: float = TIMEOUT) -> list[Check]:
    try:
        result = await asyncio.wait_for(_guarded(plugin, ctx), timeout)
    except TimeoutError:
        return [_broken(plugin, f"плагин не уложился в {timeout:.0f} с")]
    except PluginCrashed as exc:
        return [_broken(plugin, f"плагин завершился с ошибкой {exc!s:.200}")]
    except Exception as exc:  # isolate the plugin: its bug is not the scan's failure
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
