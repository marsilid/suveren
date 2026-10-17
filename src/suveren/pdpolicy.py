"""What the privacy policy says, and whether consent is a separate document.

Sources, checked 2026-10-17:
- Roskomnadzor's recommendations on the operator's policy of 31.07.2017, sections
  3.1–3.6 (general provisions, purposes, legal grounds, data and subjects, how and how
  long data is processed, correction, destruction and answers to requests):
  https://www.garant.ru/products/ipo/prime/doc/71634598/
- 152-ФЗ, ст. 18.1 ч. 1 п. 2: the policy covers purposes, categories of data and
  subjects, ways and terms of processing, the order of destruction:
  https://www.consultant.ru/document/cons_doc_LAW_61801/eeeebe22bf738fd65bb66b95cc278911ae2525ee/
- 152-ФЗ, ст. 9 ч. 1 as amended by 156-ФЗ of 24.06.2025, in force since 01.09.2025:
  consent "must be drawn up separately from other information and/or documents that
  the subject confirms and/or signs":
  https://www.consultant.ru/document/cons_doc_LAW_61801/6c94959bc017ac80140621762d2ac59f6006b08c/
  https://www.garant.ru/news/1850806/

Both are keyword heuristics over the text: they point at sections to look at, they
don't judge whether a section is written well. Nothing here is a "fail".
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from suveren.checks import GROUP_152, Check, Status
from suveren.page import Form, Link

RKN_RECOMMENDATIONS = "https://www.garant.ru/products/ipo/prime/doc/71634598/"

# (section, pattern over the lowercased text with ё → е). Each pattern looks for the
# wording policies actually use, not for one exact heading.
POLICY_SECTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "сведения об операторе (наименование, ИНН или адрес)",
        re.compile(r"\bинн\b|\bогрн\b|\bогрнип\b|юридическ\w* адрес|местонахождени|адрес:"),
    ),
    (
        "цели обработки",
        re.compile(
            r"цел\w*\s+(?:сбора|обработки)|в (?:следующих |целях:|целях\s)|цел\w* персональн"
        ),
    ),
    (
        "правовые основания обработки",
        re.compile(
            r"правов\w+\s+основани|основани\w+\s+(?:для\s+)?обработк|"
            r"на\s+основании\s+(?:договор|согласи|федеральн|закон|устав|ст\.|стать|п\.\s?\d)"
        ),
    ),
    (
        "какие данные и чьи обрабатываются",
        re.compile(
            r"категори\w+\s+(?:обрабатываем\w+\s+)?(?:персональн|субъект)|"
            r"(?:перечень|состав|объем)\s+(?:обрабатываем\w+\s+)?персональн|"
            r"обрабатыва\w+\s+следующ\w+\s+(?:персональн|данн)|"
            r"(?:фамилия|ф\.\s?и\.\s?о\.|фио)[^.]{0,80}(?:телефон|почт)"
        ),
    ),
    (
        "действия и способы обработки",
        re.compile(
            r"сбор\w*,\s*запис|систематизаци|способ\w*\s+обработк|"
            r"(?:смешанн|автоматизированн)\w*\s+обработк"
        ),
    ),
    (
        "сроки обработки и хранения",
        re.compile(
            r"срок\w*\s+(?:обработки|хранения|действия согласия)|"
            r"не\s+дольше|до\s+(?:достижения|отзыва)|в течение \d+"
        ),
    ),
    ("порядок уничтожения", re.compile(r"уничтож")),
    (
        "права субъекта и отзыв согласия",
        re.compile(
            r"прав\w*\s+субъект|отзыв\w*\s+(?:своего\s+)?согласи|отозвать\s+(?:свое\s+)?согласи|"
            r"вправе\s+(?:требовать|отозвать|получ|направ|запрос)"
        ),
    ),
    (
        "как направить запрос оператору",
        re.compile(r"запрос|обращени|электронн\w+\s+почт|e-?mail|[\w.-]+@[\w-]+\.\w"),
    ),
    (
        "меры защиты данных",
        re.compile(
            r"мер\w*[^.]{0,60}(?:защит|безопасност)|(?:защит|безопасност)\w*[^.]{0,40}мер|"
            r"(?:организационн|техническ|правов)\w*\s+(?:и\s+\w+\s+)?мер"
        ),
    ),
)
_CROSS_BORDER = re.compile(r"трансграничн")
_SHORT_POLICY = 2500  # characters: a real policy with these sections is longer


def _norm(text: str) -> str:
    return " ".join(text.lower().replace("ё", "е").split())


def missing_sections(text: str, foreign: bool = False) -> list[str]:
    low = _norm(text)
    missing = [name for name, rx in POLICY_SECTIONS if not rx.search(low)]
    if foreign and not _CROSS_BORDER.search(low):
        missing.append("трансграничная передача (на сайте есть иностранные сервисы)")
    return missing


def policy_content(text: str, foreign: bool) -> Check:
    low = _norm(text)
    if len(re.findall(r"персональн", low)) < 3:
        # The link answered with the site's shell (menu, footer) and the policy itself
        # is drawn by a script, or this is not the policy at all.
        return Check(
            GROUP_152,
            "Содержание политики",
            Status.UNKNOWN,
            "Не проверено: на странице политики почти нет текста о персональных данных. "
            "Вероятно, сам текст подгружается скриптом.",
            "Проверьте страницу политики вручную или запустите проверку с параметром --browser.",
        )
    missing = missing_sections(text, foreign)
    mentions = len(re.findall(r"персональн", low))
    if len(missing) >= 7 and mentions * 1500 < len(low):
        # A long page that hardly speaks of personal data and has none of the sections:
        # a page that links to the policy (often a PDF), not the policy (banki.ru).
        return Check(
            GROUP_152,
            "Содержание политики",
            Status.UNKNOWN,
            "Не проверено: по ссылке открылась страница, похожая на указатель, а не на текст "
            "политики (например, со ссылкой на PDF).",
            "Проверьте содержание политики вручную.",
        )
    short = len(low) < _SHORT_POLICY
    if not missing:
        return Check(
            GROUP_152,
            "Содержание политики",
            Status.OK,
            "В политике есть все разделы из рекомендаций Роскомнадзора: цели, основания, "
            "данные, сроки, уничтожение, права субъекта, меры защиты.",
        )
    total = len(POLICY_SECTIONS) + (1 if foreign else 0)
    note = (
        " Текст политики очень короткий: возможно, это не сама политика, а страница со "
        "ссылкой на неё."
        if short
        else ""
    )
    return Check(
        GROUP_152,
        "Содержание политики",
        Status.WARN,
        f"Не найдено {len(missing)} из {total} разделов, которые Роскомнадзор рекомендует "
        f"включать в политику: {', '.join(missing)}.{note}",
        "Дополните политику недостающими разделами (152-ФЗ, ст. 18.1; рекомендации "
        f"Роскомнадзора от 31.07.2017: {RKN_RECOMMENDATIONS}). Проверка ищет ключевые слова: "
        "если раздел есть под другим названием, всё в порядке.",
    )


# --- Consent drawn up separately (152-ФЗ, ст. 9 ч. 1, since 01.09.2025) ----------------

CONSENT_TITLE = "Отдельное согласие на обработку"
_CONSENT_HREF = re.compile(r"soglas|consent|agreement|personal|pdn|152|pd[-_]", re.I)
_CONSENT_DOC = re.compile(r"^(?:я\s+)?(?:даю\s+)?согласи\w*\s+(?:на|с)\s+обработк", re.I)
# "согласие на обработку", "согласие Пользователя на обработку".
_CONSENT_TO = r"соглас\w*(?:\s+[\w-]+){0,3}?\s+(?:на|с)\s+обработк"
_PROCESSING = re.compile(
    rf"{_CONSENT_TO}|соглас\w*\s+на\s+сбор|обработк\w*\s+(?:моих\s+)?персональн"
)
# Documents a visitor accepts, unlike the policy, which only informs.
_OTHER_DOC = re.compile(
    r"оферт|пользовательск\w*\s+соглашени|лицензионн\w*\s+соглашени|"
    r"услови\w*\s+(?:использования|пользования|договора|оферты|сервиса|участия|акции|доставки)|"
    r"правил\w*\s+(?:сайта|сервиса|пользования|программы|акции)|договор\w*\s+(?:оферты|оказания)",
)
_SENTENCE = re.compile(r"[^.!?]+")
# The document says using the site, registering or sending a form *is* consent:
# "Использование сайта означает согласие на обработку..." or "Согласие считается
# данным с момента регистрации...".
_ACTION = (
    r"(?:использовани\w*|посещени\w*)\s+(?:сайта|сервиса|ресурса)|регистраци\w+|"
    r"акцепт\w*|приняти\w+\s+(?:условий|настоящ)|заполнени\w+\s+(?:форм|анкет)|"
    r"отправк\w+\s+(?:форм|заявк|данных|сообщени)|оформлени\w+\s+заказ"
)
_IMPLIED = (
    re.compile(
        rf"(?:{_ACTION})[^.;]{{0,150}}?(?:означа\w+|явля\w+|счита\w+|призна\w+|подтвержда\w+|"
        rf"выража\w+)[^.;]{{0,120}}?{_CONSENT_TO}"
    ),
    re.compile(
        rf"{_CONSENT_TO}[^.;]{{0,150}}?(?:счита\w+|призна\w+)\s+"
        rf"(?:данн|предоставленн|полученн)\w*[^.;]{{0,80}}?(?:{_ACTION})"
    ),
)


@dataclass(slots=True)
class ConsentFinding:
    where: str
    quote: str
    kind: str  # "form": consent and another document in one statement; "doc": implied


def _quote(sentence: str, limit: int = 160) -> str:
    s = " ".join(sentence.split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def bundled_in_form(form: Form) -> str | None:
    """The statement where consent to processing is given together with accepting an
    offer or user agreement ("принимаю условия оферты и даю согласие на обработку")."""
    for statement in form.statements or [form.text]:
        found = bundled_in_text(statement)
        if found:
            return found
    return None


def bundled_in_text(text: str) -> str | None:
    """The same, in a short sentence of a page ("При входе вы принимаете условия
    использования сайта и соглашаетесь на обработку персональных данных")."""
    for sentence in _SENTENCE.findall(text):
        low = _norm(sentence)
        if len(low) <= 300 and _PROCESSING.search(low) and _OTHER_DOC.search(low):
            return _quote(sentence)
    return None


def implied_in_document(text: str) -> str | None:
    """A sentence where using the site or accepting the document counts as consent."""
    for sentence in _SENTENCE.findall(text):
        low = _norm(sentence)
        if len(low) > 600 or not re.search(_CONSENT_TO, low):
            continue
        if re.search(r"cookie|куки", low):
            continue  # a cookie banner's wording, a different question
        if any(rx.search(low) for rx in _IMPLIED):
            return _quote(sentence)
    return None


def consent_doc_link(links: list[Link]) -> Link | None:
    """A link to a separate consent text: "Согласие на обработку персональных данных"."""
    for link in links:
        text = " ".join(link.text.split())
        href = link.href.strip(" #")
        if not href or href.startswith("javascript:"):
            continue
        if len(text) <= 120 and _CONSENT_DOC.search(text):
            return link
        # "Я даю <a>согласие</a> на обработку...": only the word is a link.
        if text.lower() in ("согласие", "согласия", "согласием") and _CONSENT_HREF.search(href):
            return link
    return None


def consent_check(findings: list[ConsentFinding], separate: str | None, forms: int) -> Check | None:
    """``separate`` is the URL of a separate consent document; ``forms`` is how many
    forms with personal data were found. None when there is nothing to say."""
    fix = (
        "С 1 сентября 2025 года согласие на обработку персональных данных оформляется "
        "отдельно от других документов, которые посетитель принимает или подписывает "
        "(152-ФЗ, ст. 9 ч. 1 в ред. 156-ФЗ). Сделайте отдельный текст согласия и отдельный "
        "чекбокс для него, не объединяя его с офертой, пользовательским соглашением или "
        "согласием на рассылку."
    )
    if findings:
        shown = findings[:2]
        parts = [
            (
                f"в форме ({f.where}) согласие дают вместе с принятием другого документа: "
                if f.kind == "form"
                else f"в документе ({f.where}) согласием считается само действие посетителя: "
            )
            + f"«{f.quote}»"
            for f in shown
        ]
        return Check(
            GROUP_152,
            CONSENT_TITLE,
            Status.WARN,
            "Согласие, возможно, оформлено не отдельно: " + "; ".join(parts) + ".",
            fix,
        )
    if separate:
        return Check(
            GROUP_152,
            CONSENT_TITLE,
            Status.OK,
            "Текст согласия на обработку персональных данных опубликован отдельным документом.",
            link=separate,
        )
    if forms:
        return Check(
            GROUP_152,
            CONSENT_TITLE,
            Status.UNKNOWN,
            "Отдельного документа «Согласие на обработку персональных данных» на проверенных "
            "страницах не найдено. Если полный текст согласия стоит у чекбокса формы, это "
            "допустимо.",
            fix,
        )
    return None
