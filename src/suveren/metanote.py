"""Links to Instagram and Facebook without a note that Meta is banned in Russia.

Meta Platforms Inc. was declared an extremist organisation and banned in Russia by the
Тверской районный суд of Moscow on 21.03.2022 (upheld on appeal 20.06.2022). Since then
the media must say so whenever they name it, and site owners often add the note next to
their Instagram or Facebook links; prosecutors and courts have treated a bare link or logo
in various ways. Suveren could not check the current practice against primary sources
when this was written (2026-10-31, the legal databases did not open from the cloud), so
it only warns, explains the risk and names no fine.

The note is looked for on the same page as the link (the footer is part of the page), in
the usual wordings: "Meta … признана экстремистской", "запрещена в РФ/России",
"деятельность … запрещена".
"""

from __future__ import annotations

import html as htmllib
import re

from suveren.checks import GROUP_LAWS, Check, Evidence, Status

TITLE = "Ссылки на Instagram и Facebook без пометки о Meta"

_LINK = re.compile(
    r"""(?i)href\s*=\s*["']?(?:https?:)?//(?:[a-z0-9-]+\.)*"""
    r"""(instagram\.com|instagr\.am|facebook\.com|fb\.com|fb\.me|m\.me)\b"""
)
_NAMES = r"(?:\bmeta\b|\bмета\b|instagram|facebook|инстаграм\w*|фейсбук\w*)"
# Only a ban in Russia counts: "копирование запрещено" next to a Facebook link is no note.
_BANNED = (
    r"(?:экстремист\w*|"
    r"запрещ\w*\s+(?:к\s+использованию\s+)?(?:на\s+территории\s+|в\s+)?(?:рф|росси\w*)\b|"
    r"деятельность\s+\w+\s+запрещена)"
)
# The name and the ban within one sentence-sized stretch, either way round.
_NOTE = re.compile(rf"(?is){_NAMES}.{{0,200}}?{_BANNED}|{_BANNED}.{{0,200}}?{_NAMES}")


def page_text(page: str) -> str:
    text = re.sub(r"(?is)<(script|style)\b.*?</\1\s*>", " ", page)
    text = htmllib.unescape(re.sub(r"<[^>]+>", " ", text))
    return " ".join(text.replace("Ё", "Е").replace("ё", "е").split())


def meta_links(page: str) -> list[str]:
    return sorted({m.group(1).lower() for m in _LINK.finditer(page)})


def has_note(page: str) -> bool:
    return bool(_NOTE.search(page_text(page)))


def meta_note_check(pages: list[tuple[str, str]]) -> Check | None:
    """``pages``: (where, html). No check when no page links to Instagram or Facebook."""
    linked = [(where, html) for where, html in pages if meta_links(html)]
    if not linked:
        return None
    bare = [where for where, html in linked if not has_note(html)]
    services = sorted({s for _, html in linked for s in meta_links(html)})
    if not bare:
        return Check(
            GROUP_LAWS,
            TITLE,
            Status.OK,
            f"Ссылки на {', '.join(services)} сопровождаются пометкой о том, что Meta признана "
            "экстремистской организацией и запрещена в России.",
        )
    check = Check(
        GROUP_LAWS,
        TITLE,
        Status.WARN,
        f"На страницах ({', '.join(bare[:5])}) есть ссылки на {', '.join(services)}, а пометки "
        "о том, что Meta признана экстремистской организацией и запрещена в России, рядом не "
        "видно. Практика применения к обычным сайтам неоднородна; ссылку или логотип без "
        "пометки могут счесть демонстрацией символики запрещённой организации.",
        "Добавьте рядом со ссылками (или в подвале) пометку: «Instagram и Facebook принадлежат "
        "компании Meta, признанной экстремистской организацией и запрещённой в РФ», либо "
        "уберите ссылки.",
    )
    check.evidence = [
        Evidence("html", f"Ссылка без пометки (страница {where})", m.group(0))
        for where, html in linked
        if where in bare
        for m in [_LINK.search(html)]
        if m
    ][:10]
    return check
