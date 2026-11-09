"""--verbose: one line per network step as it starts and ends, with timings.

Off by default. The lines name the host and the step, never a query string, a token or
a header: a user behind a blocked network sees what is being waited for, and can paste
the lines in an issue without leaking anything.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit

Sink = Callable[[str], None]

_sink: Sink | None = None
_started = 0.0


def enable(sink: Sink) -> None:
    global _sink, _started
    _sink, _started = sink, time.perf_counter()


def disable() -> None:
    global _sink
    _sink = None


def enabled() -> bool:
    return _sink is not None


def say(text: str) -> None:
    if _sink is not None:
        _sink(f"{time.perf_counter() - _started:7.1f} с  {text}")


@contextmanager
def step(name: str, answers: dict[type[BaseException], str] | None = None) -> Iterator[None]:
    """ "→ name" when it starts, "← name: 1.2 с" or "✗ name: why, 1.2 с" when it ends.
    ``answers``: exceptions that are an answer, not a failure (NXDOMAIN), and their words."""
    if _sink is None:
        yield
        return
    say(f"→ {name}")
    started = time.perf_counter()
    try:
        yield
    except BaseException as exc:
        said = next((w for t, w in (answers or {}).items() if isinstance(exc, t)), None)
        if said is not None:
            ended(name, said, started)
        else:
            failed(name, exc, started)
        raise
    say(f"← {name}: {time.perf_counter() - started:.1f} с")


def ended(name: str, outcome: str, started: float) -> None:
    say(f"← {name}: {outcome}, {time.perf_counter() - started:.1f} с")


def failed(name: str, exc: BaseException, started: float) -> None:
    say(f"✗ {name}: {_why(exc)}, {time.perf_counter() - started:.1f} с")


# Path segments that may carry a secret: a Telegram bot token (bot123:AA...), long
# random ids, anything with "=" or "@".
_SECRET_SEGMENT = re.compile(r"(?i)^bot\d+:|[=@:]|^[A-Za-z0-9_\-]{24,}$")


def safe_url(url: str) -> str:
    """Host and path, without the query, the fragment, a user or a secret-looking part."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port:
        host += f":{parts.port}"
    segments = ["…" if _SECRET_SEGMENT.search(s) else s for s in parts.path.split("/")]
    path = "/".join(segments)
    if len(path) > 60:
        path = path[:57] + "…"
    return host + path


def _why(exc: BaseException) -> str:
    text = type(exc).__name__
    detail = str(exc).splitlines()[0] if str(exc) else ""
    # Exceptions from httpx can repeat the URL with its query; keep only the class then.
    if detail and "?" not in detail and "://" not in detail:
        text += f" ({detail[:80]})"
    return text
