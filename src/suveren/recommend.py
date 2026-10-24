"""Recommendation technologies (149-ФЗ, ст. 10.2-2): rules a site must publish.

Since 01.10.2023 the owner of a site that shows information chosen from users'
preferences must publish a document with the rules of these technologies, an email
for legally significant messages and its name (ч. 1 п. 3). Not publishing them is
КоАП ст. 13.56 ч. 3 since 07.07.2026. Whether a site really personalises what it
shows cannot be seen from outside, so the answer is at most a warning.
"""

from __future__ import annotations

import html as htmllib
import re

from suveren.checks import GROUP_LAWS, Check, Evidence, Status
from suveren.page import parse_page

TITLE = "Рекомендательные технологии"
LAW = "149-ФЗ, ст. 10.2-2"
LINK = "https://www.consultant.ru/document/cons_doc_LAW_61798/2a69c627d62738291fe0a0fd4c1253385e730784/"

# A block whose heading says the choice is made for this visitor. Only headings: in
# running text "персональные рекомендации консультанта" or "рекомендуем вам проверить
# браузер" is not a feed. "Похожие товары" or "популярное" may be the same for everyone.
_PERSONAL = re.compile(
    r"^(?:персональн\w+ (?:рекомендац|подборк|лент)\w*|рекомендации для вас|"
    r"рекомендуем для вас|подобрали для вас|подборка для вас|специально для вас|"
    r"вам может понравиться|вы недавно смотрели|недавно просмотренные|"
    r"на основе ваших \w+|лента рекомендаций|моя лента)\b",
    re.I,
)
_HEADING = re.compile(r"<h[1-6][^>]*>(.*?)</h[1-6]>", re.I | re.S)
_TAG = re.compile(r"<[^>]+>")
_RULES = re.compile(r"рекомендательн\w* технолог", re.I)
_RULES_HREF = re.compile(
    r"recommend\w*[-_/]?(?:rule|technolog|polic)|rekomendat\w*[-_]?(?:tehnolog|tekhnolog)", re.I
)


def find_rules(htmls: list[str]) -> str | None:
    """Text of the link to the rules document, or a mention of the technologies."""
    pages = [parse_page(h) for h in htmls]
    for page in pages:
        for link in page.links:
            if _RULES.search(link.text) or _RULES_HREF.search(link.href):
                return link.text.strip() or link.href
    for page in pages:
        match = _RULES.search(page.text)
        if match:
            return f"на странице сказано: {match.group(0)}"
    return None


def find_personal(htmls: list[str]) -> str | None:
    for html in htmls:
        for raw in _HEADING.findall(html[:3_000_000]):
            heading = " ".join(htmllib.unescape(_TAG.sub(" ", raw)).split())
            if len(heading) <= 60 and _PERSONAL.search(heading):
                return heading
    return None


def recommendation_check(htmls: list[str]) -> Check | None:
    """None when the pages show neither personal recommendations nor the rules."""
    rules = find_rules(htmls)
    if rules:
        return Check(
            GROUP_LAWS,
            TITLE,
            Status.OK,
            f"Правила применения рекомендательных технологий размещены («{rules[:80]}»).",
            law=LAW,
            link=LINK,
        )
    personal = find_personal(htmls)
    if not personal:
        return None
    return Check(
        GROUP_LAWS,
        TITLE,
        Status.WARN,
        f"На сайте есть блок «{personal}», а ссылки на правила применения рекомендательных "
        "технологий не нашлось. Если подборка строится по интересам посетителя, закон "
        "требует опубликовать эти правила, адрес почты для юридически значимых сообщений и "
        "наименование владельца.",
        "Разместите в подвале ссылку на документ «Правила применения рекомендательных "
        "технологий» на русском языке: какие сведения о посетителях используются, откуда "
        "они берутся и как подбирается показ. Если подборка одинакова для всех, правила не "
        "нужны. Неразмещение — штраф для организации от 500 до 700 тыс. ₽ (КоАП, ст. 13.56 "
        "ч. 3, с 07.07.2026).",
        law=LAW,
        link=LINK,
        evidence=[Evidence("html", "Заголовок блока на странице", personal)],
    )
