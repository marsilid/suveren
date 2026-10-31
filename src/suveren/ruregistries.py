"""Russian registers of counterparties: who is on the lists a Russian company checks.

Connected: the list of terrorists and extremists of Росфинмониторинг (fedsfm.ru). It is
a long public page; Suveren downloads it once a day and looks for the company's ИНН and
ОГРН and for the full name of its head in its text. Searching the text, not the layout,
keeps the answer right when the page is redesigned.

Not connected yet, and named in the report as not checked: foreign agents (Минюст,
published as PDF), disqualified persons, unreliable data and mass addresses (ФНС),
bankruptcies (ЕФРСБ), unfair suppliers (ЕИС). Their formats could not be checked from
outside Russia (the sites answer only Russian addresses), and a parser written blind
would say "not found" when it simply did not understand the file.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field

import httpx

from suveren.cache import fetch_cached
from suveren.checks import Check, Status, copy_of
from suveren.errors import ModuleError

GROUP = "Проверка компании"
TITLE = "Перечень террористов и экстремистов"

FEDSFM_URL = "https://www.fedsfm.ru/documents/terrorists-catalog-portal-act"
FEDSFM_NAME = "Перечень террористов и экстремистов Росфинмониторинга (fedsfm.ru)"

# What is not checked, for the report: the register and why.
NOT_CONNECTED = (
    ("Реестр иностранных агентов (Минюст)", "публикуется в PDF, разбор не сверен"),
    ("Реестр дисквалифицированных лиц (ФНС)", "нужен российский IP"),
    ("Недостоверность сведений и массовый адрес (ФНС)", "нужен российский IP"),
    ("ЕФРСБ (Федресурс)", "нужен российский IP"),
    ("Реестр недобросовестных поставщиков (ЕИС)", "нужен российский IP"),
)


def normalize(text: str) -> str:
    """Page text for searching: no tags, upper case, Ё as Е, one space between words."""
    text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    return " ".join(text.upper().replace("Ё", "Е").replace("*", " ").split())


@dataclass(slots=True)
class ListMatch:
    by: str  # "ИНН", "ОГРН" or "ФИО"
    value: str
    excerpt: str  # the text around the match

    @property
    def strong(self) -> bool:
        return self.by != "ФИО"


def find(text: str, ids: dict[str, str], person: str | None) -> list[ListMatch]:
    """``ids``: {"ИНН": "...", "ОГРН": "..."}. A person is matched only by the full
    name (three words): a surname and a first name match too many people."""
    found = []
    for by, value in ids.items():
        if not value:
            continue
        for m in re.finditer(rf"(?<!\d){re.escape(value)}(?!\d)", text):
            found.append(ListMatch(by, value, text[max(0, m.start() - 80) : m.end() + 40]))
            break
    if person:
        name = normalize(person)
        if len(name.split()) >= 3:
            at = text.find(name)
            if at >= 0:
                found.append(ListMatch("ФИО", person, text[max(0, at - 20) : at + 120]))
    return found


@dataclass(slots=True)
class RuScreening:
    matches: list[ListMatch] = field(default_factory=list)
    source: str | None = None  # the copy used and its date
    error: str | None = None


async def screen(
    client: httpx.AsyncClient, ids: dict[str, str], person: str | None, *, refresh: bool = False
) -> RuScreening:
    try:
        path, _ = await fetch_cached(
            client, FEDSFM_URL, "ru/fedsfm.html", refresh=refresh, html=True
        )
        text = normalize(path.read_text("utf-8", "replace"))
    except (ModuleError, OSError) as exc:
        return RuScreening(error=str(exc))
    if "ТЕРРОРИСТ" not in text and "ЭКСТРЕМИСТ" not in text:
        # A stub or a block page, not the list: "not found" in it would mean nothing.
        return RuScreening(error="вместо перечня пришла другая страница")
    return RuScreening(find(text, ids, person), copy_of(FEDSFM_NAME, path))


def not_connected_note() -> str:
    names = "; ".join(f"{n} — {why}" for n, why in NOT_CONNECTED)
    return f"Российские реестры, которые Suveren пока не проверяет: {names}."


def list_check(result: RuScreening, *, asked: bool) -> Check:
    if not asked:
        return Check(
            GROUP,
            TITLE,
            Status.UNKNOWN,
            "Не проверено: нет ни ИНН, ни ОГРН, ни руководителя, искать нечего.",
        )
    if result.error:
        return Check(
            GROUP,
            TITLE,
            Status.UNKNOWN,
            f"Не проверено: перечень Росфинмониторинга не загрузился ({result.error}). "
            "Сайт fedsfm.ru часто отвечает только российским адресам.",
            "Повторите проверку с российского IP или найдите компанию на fedsfm.ru.",
        )
    strong = [m for m in result.matches if m.strong]
    if strong:
        what = ", ".join(f"{m.by} {m.value}" for m in strong)
        return Check(
            GROUP,
            TITLE,
            Status.FAIL,
            f"В перечне Росфинмониторинга найдено совпадение: {what} («{strong[0].excerpt}»).",
            "Сделки с лицами из перечня запрещены или ограничены (115-ФЗ, ст. 7): сверьте "
            "запись на fedsfm.ru и обратитесь к юристу.",
        )
    if result.matches:
        m = result.matches[0]
        return Check(
            GROUP,
            TITLE,
            Status.WARN,
            f"В перечне Росфинмониторинга есть человек с тем же ФИО, что у руководителя: "
            f"{m.value} («{m.excerpt}»). Это может быть тёзка: сверьте дату и место рождения.",
            "Сверьте запись на fedsfm.ru: дата рождения в перечне указана.",
        )
    return Check(
        GROUP,
        TITLE,
        Status.OK,
        "В перечне Росфинмониторинга нет ни ИНН и ОГРН компании, ни руководителя по полному ФИО.",
    )
