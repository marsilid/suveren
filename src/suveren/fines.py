"""Fines for what the checks found: an estimate of the maximum risk, not legal advice.

Amounts are from the Code of Administrative Offences (КоАП), checked 2026-10-17
against the consolidated text as amended on 04.08.2026:
- ст. 13.11 (personal data):
  https://www.consultant.ru/document/cons_doc_LAW_34661/1f421640c6775ff67079ebde06a7d2f6d17b96db/
- ст. 13.55 (sign-in through foreign services, in force since 07.07.2026):
  https://www.consultant.ru/document/cons_doc_LAW_34661/eecaf3bcdcd8f21011f025127298179a3bfd8877/
- note to ст. 2.4: a sole trader (ИП) is fined as an official unless the article
  names sole traders separately:
  https://www.consultant.ru/document/cons_doc_LAW_34661/de33c73dc4e364406642dc44f280f59154201a2e/
- notes to ст. 13.11 (checked 2026-10-20): under parts 1.1 and 8–18 a sole trader is
  fined as a legal entity (note 1); in parts 10–18 an "official" is one of a state
  body or a non-profit only (note 2).

Every problem ("fail") that matches a part of an article goes into the total, one
article counted once. Where the qualification depends on facts Suveren can't see
(was consent needed at all?), the row says so. A warning with an article is listed
and not added up; "not checked" is never counted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from suveren.checks import Check, Status

DISCLAIMER = (
    "Оценка максимального риска по найденным признакам, а не юридическое заключение. "
    "Размер штрафа назначает суд или Роскомнадзор с учётом обстоятельств. В сумму входят "
    "найденные проблемы, по одной статье на нарушение; «внимание» и «не проверено» — нет."
)
CHECKED = "2026-10-17"

Range = tuple[int, int]

KOAP_1311 = "https://www.consultant.ru/document/cons_doc_LAW_34661/1f421640c6775ff67079ebde06a7d2f6d17b96db/"
KOAP_1355 = "https://www.consultant.ru/document/cons_doc_LAW_34661/eecaf3bcdcd8f21011f025127298179a3bfd8877/"
KOAP_1356 = "https://www.consultant.ru/document/cons_doc_LAW_34661/32b1d73e2b548ee988d4c3d446900ed78bc161f0/"


@dataclass(frozen=True, slots=True)
class Fine:
    article: str
    url: str
    legal: Range  # юридическое лицо
    official: Range  # должностное лицо
    citizen: Range  # гражданин
    entrepreneur: Range | None = None  # ИП, when the article names them; else as official
    repeat_legal: Range | None = None  # a repeated offence, if the article has a part for it
    repeat_article: str | None = None

    @property
    def sole_trader(self) -> Range:
        return self.entrepreneur or self.official


# КоАП, ст. 13.11 ч. 3: the policy is not published.
POLICY_NOT_PUBLISHED = Fine(
    "КоАП, ст. 13.11 ч. 3",
    KOAP_1311,
    legal=(30_000, 60_000),
    official=(6_000, 12_000),
    citizen=(1_500, 3_000),
    entrepreneur=(10_000, 20_000),
)
# ч. 1: processing in cases not provided by law (e.g. without a needed consent).
UNLAWFUL_PROCESSING = Fine(
    "КоАП, ст. 13.11 ч. 1",
    KOAP_1311,
    legal=(150_000, 300_000),
    official=(50_000, 100_000),
    citizen=(10_000, 15_000),
    repeat_legal=(300_000, 500_000),
    repeat_article="ч. 1.1",
)
# ч. 8: data of Russian citizens not stored in databases located in Russia.
LOCALISATION = Fine(
    "КоАП, ст. 13.11 ч. 8",
    KOAP_1311,
    legal=(1_000_000, 6_000_000),
    official=(100_000, 200_000),
    citizen=(30_000, 50_000),
    entrepreneur=(1_000_000, 6_000_000),  # note 1: as a legal entity
    repeat_legal=(6_000_000, 18_000_000),
    repeat_article="ч. 9",
)
# ч. 10: no notification to Roskomnadzor about processing personal data.
NO_NOTIFICATION = Fine(
    "КоАП, ст. 13.11 ч. 10",
    KOAP_1311,
    legal=(100_000, 300_000),
    official=(30_000, 50_000),  # note 2: officials of state bodies and non-profits only
    citizen=(5_000, 10_000),
    entrepreneur=(100_000, 300_000),  # note 1: as a legal entity
)
# ст. 13.55: sign-in for users in Russia not by the methods 149-ФЗ allows.
FOREIGN_SIGN_IN = Fine(
    "КоАП, ст. 13.55",
    KOAP_1355,
    legal=(500_000, 700_000),
    official=(30_000, 50_000),
    citizen=(10_000, 20_000),
)
# ст. 13.56 ч. 3 (199-ФЗ, since 07.07.2026): the rules of recommendation technologies, an
# email for legally significant messages or the owner's name are not published.
RECOMMENDATION_RULES = Fine(
    "КоАП, ст. 13.56 ч. 3",
    KOAP_1356,
    legal=(500_000, 700_000),
    official=(30_000, 50_000),
    citizen=(10_000, 20_000),
    repeat_legal=(1_000_000, 1_400_000),
    repeat_article="ч. 4",
)

# (check ID from catalog.py, status) -> (fine, note). The note says when the finding
# is not by itself the offence that part describes.
RULES: dict[tuple[str, Status], tuple[Fine, str | None]] = {
    ("SUV-PD-001", Status.FAIL): (POLICY_NOT_PUBLISHED, None),  # policy not published
    ("SUV-PD-007", Status.FAIL): (  # server outside Russia
        LOCALISATION,
        "если заявки с сайта хранятся на этом сервере",
    ),
    ("SUV-LAW-001", Status.FAIL): (  # sign-in through foreign services
        FOREIGN_SIGN_IN,
        "если владелец сайта — российская компания или гражданин",
    ),
    # A lead form may be processed without consent to answer the request (152-ФЗ,
    # ст. 6 ч. 1 п. 5), so missing consent is not always an offence: listed as possible,
    # never added to the total.
    ("SUV-PD-003", Status.WARN): (
        UNLAWFUL_PROCESSING,
        "если для этой обработки нужно согласие",
    ),
    # Whether the feed is built from the visitor's interests can't be seen from outside.
    ("SUV-LAW-002", Status.WARN): (
        RECOMMENDATION_RULES,
        "если подборка строится по интересам посетителя",
    ),
    # Some operators may process data without notifying (152-ФЗ, ст. 22 ч. 2).
    ("SUV-PD-009", Status.WARN): (
        NO_NOTIFICATION,
        "если компания не освобождена от уведомления; штраф для должностного лица — "
        "только в госорганах и некоммерческих организациях",
    ),
}


@dataclass(frozen=True, slots=True)
class FineItem:
    title: str
    fine: Fine
    note: str | None
    counted: bool  # a problem ("fail"): goes into the total

    def to_dict(self) -> dict[str, Any]:
        f = self.fine
        return {
            "check": self.title,
            "article": f.article,
            "url": f.url,
            "counted": self.counted,
            "condition": self.note,
            "legal_entity": list(f.legal),
            "official": list(f.official),
            "sole_trader": list(f.sole_trader),
            "citizen": list(f.citizen),
            "repeat_legal_entity": list(f.repeat_legal) if f.repeat_legal else None,
        }


@dataclass(frozen=True, slots=True)
class FineEstimate:
    items: tuple[FineItem, ...]

    @property
    def counted(self) -> list[FineItem]:
        return [i for i in self.items if i.counted]

    @property
    def listed(self) -> list[FineItem]:
        """Warnings with an article: shown, not added up."""
        return [i for i in self.items if not i.counted]

    def total(self, who: str = "legal") -> int:
        """Sum of the maximum fines for the problems. ``who``: legal, sole_trader,
        official or citizen."""
        return sum(getattr(i.fine, who)[1] for i in self.counted)

    def __bool__(self) -> bool:
        return bool(self.items)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_max_legal_entity": self.total("legal"),
            "total_max_sole_trader": self.total("sole_trader"),
            "items": [i.to_dict() for i in self.items],
            "disclaimer": DISCLAIMER,
            "checked": CHECKED,
        }


# A rule that fits only one of the check's answers with that status, told by its text.
# PD-003 also warns about consent shown only on a later step, outside the form or
# pre-ticked: consent is there, so no part of ст. 13.11 is about it.
ONLY_WHEN: dict[tuple[str, Status], str] = {
    ("SUV-PD-003", Status.WARN): "не найдено согласия",
}


def estimate(checks: list[Check]) -> FineEstimate:
    items: list[FineItem] = []
    seen: set[str] = set()
    for check in checks:
        key = (check.id, check.status)
        rule = RULES.get(key)
        if key in ONLY_WHEN and ONLY_WHEN[key] not in check.details:
            continue
        if rule and rule[0].article not in seen:
            seen.add(rule[0].article)
            items.append(FineItem(check.title, rule[0], rule[1], check.status is Status.FAIL))
    return FineEstimate(tuple(items))


def rub(amount: int) -> str:
    """1500000 -> "1,5 млн ₽", 60000 -> "60 тыс. ₽"."""
    if amount >= 1_000_000:
        value = f"{amount / 1_000_000:.2f}".rstrip("0").rstrip(".").replace(".", ",")
        return f"{value} млн ₽"
    if amount >= 1_000:
        value = f"{amount / 1_000:.1f}".rstrip("0").rstrip(".").replace(".", ",")
        return f"{value} тыс. ₽"
    return f"{amount} ₽"


def span(r: Range) -> str:
    return f"{rub(r[0])} – {rub(r[1])}".replace(" ₽ –", " –")
