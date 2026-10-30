"""Example Suveren plugin: is there a security.txt (RFC 9116)?

A security.txt tells a researcher who found a vulnerability where to report it. RFC
9116 (section 3) puts it at /.well-known/security.txt over HTTPS, as text/plain, with
at least one Contact field and exactly one Expires field that is not in the past.

    suveren scan site.ru --plugin examples/plugins/security_txt.py

A plugin defines NAME and async run(ctx) returning a list of Check; IDs use the
plugin's own prefix (here EX-SEC-001), never SUV-. See docs/plugins.md.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx

from suveren.checks import Check, Status
from suveren.plugins import GROUP_PLUGINS, PluginContext

NAME = "security.txt (RFC 9116)"
TITLE = "security.txt: куда сообщить об уязвимости"
ID = "EX-SEC-001"


def fields(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and not line.startswith("#"):
            out.setdefault(key.strip().lower(), []).append(value.strip())
    return out


def verdict(status: int | None, content_type: str, text: str, now: datetime) -> Check:
    def check(st: Status, details: str, fix: str = "") -> Check:
        return Check(GROUP_PLUGINS, TITLE, st, details, fix, id=ID, law="RFC 9116")

    fix = (
        "Опубликуйте https://ваш-сайт/.well-known/security.txt с полями Contact (почта или "
        "форма для сообщений об уязвимостях) и Expires (дата, до которой файл актуален)."
    )
    if status not in (200, 404, 410):
        # 403 or 503 is usually a bot wall: the file may well be there.
        return check(Status.UNKNOWN, f"Не проверено: сайт ответил кодом {status}.")
    if status != 200:
        return check(
            Status.WARN,
            "Файла security.txt нет: исследователю некуда сообщить о найденной уязвимости.",
            fix,
        )
    if not content_type.lower().startswith("text/plain"):
        return check(
            Status.WARN,
            f"security.txt отдаётся как {content_type or 'без типа'}, а не text/plain.",
            fix,
        )
    f = fields(text)
    problems = []
    if not f.get("contact"):
        problems.append("нет поля Contact")
    expires = f.get("expires", [])
    if len(expires) != 1:
        problems.append("поле Expires должно быть ровно одно")
    else:
        try:
            # RFC 3339 (section 5.6) allows "t" and "z" in lower case: Google writes them so.
            value = expires[0].upper().replace("Z", "+00:00")
            when = datetime.fromisoformat(value)
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
            if when < now:
                problems.append(f"срок в Expires истёк {when:%d.%m.%Y}")
        except ValueError:
            problems.append(f"Expires не дата: «{expires[0][:40]}»")
    if problems:
        return check(Status.WARN, "security.txt есть, но: " + "; ".join(problems) + ".", fix)
    return check(
        Status.OK, "security.txt опубликован: контакт для сообщений об уязвимостях указан."
    )


async def run(ctx: PluginContext) -> list[Check]:
    url = f"https://{ctx.host}/.well-known/security.txt"
    if ctx.client is None:
        return []
    try:
        resp = await ctx.client.get(url)
    except httpx.HTTPError:
        return [
            Check(GROUP_PLUGINS, TITLE, Status.UNKNOWN, "Не проверено: сайт не ответил.", id=ID)
        ]
    return [
        verdict(
            resp.status_code,
            resp.headers.get("content-type", ""),
            resp.text[:20_000],
            datetime.now(UTC),
        )
    ]
