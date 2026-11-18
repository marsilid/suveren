"""Advertising labels (38-ФЗ «О рекламе», ст. 18.1): what is seen, without verdicts.

Article 18.1 (ред. от 04.08.2026, checked on consultant.ru 2026-11-19): an internet ad
must carry the mark «реклама» and name its advertiser or link to a page about it (part
16), and may run only once an ad data operator has given it an identifier, the erid
token (part 17). Suveren reports the tokens it sees and the pages where a token stands
without the word «реклама» anywhere, and never calls anything a violation: whether a
block is an ad at all is a legal question it can't answer, and the mark may be an image
or be drawn by a script.
"""

from __future__ import annotations

import re

from suveren.checks import GROUP_LAWS, Check, Status
from suveren.utils import visible_text

TITLE = "Маркировка интернет-рекламы"
# A token in a link (?erid=, #erid=), in text ("erid: …") or in markup and data
# (data-erid="…", "erid":"…").
_ERID = re.compile(
    r"(?i)[?&;#]erid=([A-Za-z0-9]{6,40})|\berid[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9]{6,40})"
)
_AD_WORD = re.compile(r"(?i)(?<![а-яё])реклама(?![а-яё])")


def erids(pages: list[str]) -> list[str]:
    found: dict[str, None] = {}
    for html in pages:
        for m in _ERID.finditer(html):
            found.setdefault(m.group(1) or m.group(2), None)
    return list(found)


def ad_marking_check(pages: list[tuple[str, str]]) -> Check | None:
    """``pages``: (where, HTML). Only when tokens are seen: then which ones, and "not
    clear" as the verdict. A token seen says nothing about the ads without one, nor about
    the register entry behind it, so "в порядке" would claim what was not checked.
    Nothing is said about pages without tokens (no ads, or unlabelled ads: Suveren can't
    tell)."""
    found = erids([html for _, html in pages])
    if not found:
        return None
    shown = ", ".join(found[:5]) + (f" и ещё {len(found) - 5}" if len(found) > 5 else "")
    unmarked = [
        where for where, html in pages if erids([html]) and not _AD_WORD.search(visible_text(html))
    ]
    unmarked_note = (
        f" {'На странице' if len(unmarked) == 1 else 'На страницах'} "
        f"({', '.join(unmarked[:5])}) токен есть, а слова «реклама» в тексте страницы нет. "
        "Пометка часто нарисована на самой картинке баннера, поэтому это не вывод о "
        "нарушении: посмотрите на баннеры глазами (ч. 16 ст. 18.1 требует пометку "
        "«реклама» и указание на рекламодателя)."
        if unmarked
        else ""
    )
    return Check(
        GROUP_LAWS,
        TITLE,
        Status.UNKNOWN,
        f"На страницах найдена маркировка рекламы (erid): {shown}.{unmarked_note} Не "
        "проверялось: вся ли реклама на сайте промаркирована, указан ли рекламодатель и "
        "зарегистрированы ли эти токены в ЕРИР. Что считать рекламой — вопрос толкования "
        "38-ФЗ, ст. 18.1, ч. 16–17.",
        "Сверьте со своим списком рекламных размещений, что у каждого есть токен erid и "
        "пометка «Реклама» с указанием рекламодателя.",
        law="38-ФЗ, ст. 18.1",
    )
