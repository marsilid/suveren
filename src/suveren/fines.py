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

Only problems ("fail") that match one part of an article go into the total. A
warning, or a problem whose legal qualification depends on facts Suveren can't see
(was consent needed at all? is the company exempt from notifying?), is listed as
"possible" with its article, and is not added up.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from suveren.checks import Check, Status

DISCLAIMER = (
    "Оценка максимального риска по найденным признакам, а не юридическое заключение. "
    "Размер штрафа назначает суд или Роскомнадзор с учётом обстоятельств; в сумму входят "
    "только явные проблемы, по одной статье на нарушение."
)
CHECKED = "2026-10-17"

Range = tuple[int, int]

KOAP_1311 = "https://www.consultant.ru/document/cons_doc_LAW_34661/1f421640c6775ff67079ebde06a7d2f6d17b96db/"
KOAP_1355 = "https://www.consultant.ru/document/cons_doc_LAW_34661/eecaf3bcdcd8f21011f025127298179a3bfd8877/"


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
    repeat_legal=(6_000_000, 18_000_000),
    repeat_article="ч. 9",
)
# ч. 10: no notification to Roskomnadzor about processing personal data.
NO_NOTIFICATION = Fine(
    "КоАП, ст. 13.11 ч. 10",
    KOAP_1311,
    legal=(100_000, 300_000),
    official=(30_000, 50_000),
    citizen=(5_000, 10_000),
)
# ст. 13.55: sign-in for users in Russia not by the methods 149-ФЗ allows.
FOREIGN_SIGN_IN = Fine(
    "КоАП, ст. 13.55",
    KOAP_1355,
    legal=(500_000, 700_000),
    official=(30_000, 50_000),
    citizen=(10_000, 20_000),
)

# (check title, status) -> (fine, certain). "certain" means the finding itself is
# the offence described by that part; otherwise it is a possible qualification.
RULES: dict[tuple[str, Status], tuple[Fine, bool]] = {
    ("Политика обработки персональных данных", Status.FAIL): (POLICY_NOT_PUBLISHED, True),
    ("Хранение данных в России", Status.FAIL): (LOCALISATION, True),
    ("Вход через иностранные сервисы", Status.FAIL): (FOREIGN_SIGN_IN, True),
    # A lead form may be processed without consent to answer the request (152-ФЗ,
    # ст. 6 ч. 1 п. 5), so missing consent is not always an offence.
    ("Согласие на обработку в формах", Status.FAIL): (UNLAWFUL_PROCESSING, False),
    # Some operators may process data without notifying (152-ФЗ, ст. 22 ч. 2).
    ("Реестр операторов персональных данных", Status.WARN): (NO_NOTIFICATION, False),
}


@dataclass(frozen=True, slots=True)
class FineItem:
    title: str
    fine: Fine
    certain: bool

    def to_dict(self) -> dict[str, Any]:
        f = self.fine
        return {
            "check": self.title,
            "article": f.article,
            "url": f.url,
            "certain": self.certain,
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
    def certain(self) -> list[FineItem]:
        return [i for i in self.items if i.certain]

    @property
    def possible(self) -> list[FineItem]:
        return [i for i in self.items if not i.certain]

    def total(self, who: str = "legal") -> int:
        """Sum of the maximum fines for the certain items. ``who``: legal, sole_trader,
        official or citizen."""
        return sum(getattr(i.fine, who)[1] for i in self.certain)

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


def estimate(checks: list[Check]) -> FineEstimate:
    items: list[FineItem] = []
    seen: set[str] = set()
    for check in checks:
        rule = RULES.get((check.title, check.status))
        if rule and rule[0].article not in seen:
            seen.add(rule[0].article)
            items.append(FineItem(check.title, *rule))
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
