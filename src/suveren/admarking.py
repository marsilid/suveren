"""Advertising labels (38-ФЗ «О рекламе», ст. 18.1): a frame without verdicts.

Internet ads in Russia carry a token (erid) from the ad register and the word
«Реклама» with the advertiser. The law's current text could not be checked against
the primary source when this was written (consultant.ru did not open from the cloud,
2026-10-31), so Suveren only reports the labels it sees and never calls anything a
violation: whether a block is an ad at all is a legal question it can't answer.
"""

from __future__ import annotations

import re

from suveren.checks import GROUP_LAWS, Check, Status

TITLE = "Маркировка интернет-рекламы"
_ERID = re.compile(r"(?i)[?&;#]erid=([A-Za-z0-9]{6,40})|\berid\s*[:=]\s*([A-Za-z0-9]{6,40})")


def erids(pages: list[str]) -> list[str]:
    found: dict[str, None] = {}
    for html in pages:
        for m in _ERID.finditer(html):
            found.setdefault(m.group(1) or m.group(2), None)
    return list(found)


def ad_marking_check(pages: list[str]) -> Check | None:
    """Only when labels are seen: then which ones, and "not clear" as the verdict. A label
    seen says nothing about the ads without one, nor about the register entry behind the
    token, so "в порядке" would claim what was not checked. Nothing is said about pages
    without labels (no ads, or unlabelled ads: Suveren can't tell)."""
    found = erids(pages)
    if not found:
        return None
    shown = ", ".join(found[:5]) + (f" и ещё {len(found) - 5}" if len(found) > 5 else "")
    return Check(
        GROUP_LAWS,
        TITLE,
        Status.UNKNOWN,
        f"На страницах найдена маркировка рекламы (erid): {shown}. Не проверялось: вся ли "
        "реклама на сайте промаркирована, есть ли рядом пометка «Реклама» с рекламодателем "
        "и зарегистрированы ли эти токены в ЕРИР. Что считать рекламой — вопрос толкования "
        "38-ФЗ, ст. 18.1.",
        "Сверьте со своим списком рекламных размещений, что у каждого есть токен erid и "
        "пометка «Реклама» с указанием рекламодателя.",
        law="38-ФЗ, ст. 18.1",
    )
