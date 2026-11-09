"""Russian company identifiers: ИНН and ОГРН, with checksum validation."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable

# Requisites are mostly written "ИНН/КПП: 7707083893/770701001", "ИНН (КПП)" or
# "ИНН организации"; the ИНН is the first number after the label.
_INN_RE = re.compile(
    r"(?:инн|inn)(?:\s*[/(-]?\s*(?:кпп|kpp)\)?|\s+(?:организации|компании|оператора))?"
    r"[\s:№#./-]{0,6}(\d{10}|\d{12})(?!\d)",
    re.IGNORECASE,
)
_OGRN_RE = re.compile(r"(?:огрнип|огрн|ogrn)[\s:№#./-]{0,6}(\d{13}|\d{15})(?!\d)", re.IGNORECASE)


def _weighted(digits: str, weights: tuple[int, ...]) -> int:
    return sum(int(d) * w for d, w in zip(digits, weights, strict=False)) % 11 % 10


def is_valid_inn(value: str) -> bool:
    if not value.isdigit():
        return False
    if len(value) == 10:
        return _weighted(value, (2, 4, 10, 3, 5, 9, 4, 6, 8)) == int(value[9])
    if len(value) == 12:
        first = _weighted(value, (7, 2, 4, 10, 3, 5, 9, 4, 6, 8))
        second = _weighted(value, (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8))
        return first == int(value[10]) and second == int(value[11])
    return False


def is_valid_ogrn(value: str) -> bool:
    if not value.isdigit():
        return False
    if len(value) == 13:
        return int(value[:12]) % 11 % 10 == int(value[12])
    if len(value) == 15:  # ОГРНИП
        return int(value[:14]) % 13 % 10 == int(value[14])
    return False


def classify(value: str) -> str | None:
    """'inn' / 'ogrn' for a valid identifier, otherwise None."""
    value = value.strip()
    if is_valid_inn(value):
        return "inn"
    if is_valid_ogrn(value):
        return "ogrn"
    return None


def _clean(text: str) -> str:
    # Strip tags and collapse whitespace so "ИНН&nbsp;7707083893" and
    # "<b>ИНН</b> 7707083893" still match.
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.replace("&nbsp;", " ").replace("\xa0", " ")
    return re.sub(r"\s+", " ", text)


# An ad label under 38-ФЗ names the advertiser: "Реклама. ООО «X», ИНН …, erid: …".
# That ИНН is someone else's, not the site owner's.
_AD_LABEL = re.compile(r"\berid\b", re.I)
# So is a partner's in a document: rbc.ru's offer names "партнер Администрации ООО
# «Тривиум» (ОГРН …, ИНН 7806297293)", the operator of a course platform.
_PARTNER = re.compile(r"партн[её]р", re.I)


# A bank or a payment service named next to its ИНН: "Платежи принимает АО «Альфа-Банк»
# ИНН …". It may recur in the payment blocks more often than the owner in the footer.
_PAYER = re.compile(r"банк|bank|эквайр|эквайер|плат[её]ж|оплат|страхов", re.I)


def find_inns(text: str, *, first: bool = False) -> list[str]:
    """Valid ИНН mentioned in the text, most frequent first (``first``: in the order
    they first appear); advertisers' ИНН from ad labels and partners' from documents
    are left out, banks' and payment services' go after the rest."""
    clean = _clean(text)
    counts: Counter[str] = Counter()
    plain: set[str] = set()
    previous = 0
    for m in _INN_RE.finditer(clean):
        # The context starts after the previous ИНН, so one company's words do not
        # spill onto the next.
        value, before = m.group(1), max(previous, m.start() - 80)
        previous = m.end()
        if not is_valid_inn(value):
            continue
        if _AD_LABEL.search(clean, max(0, m.start() - 40), m.end() + 80):
            continue
        if _PARTNER.search(clean, max(0, m.start() - 120), m.start()):
            continue
        counts[value] += 1
        if not _PAYER.search(clean, before, m.start()):
            plain.add(value)
    order = list(counts) if first else [inn for inn, _ in counts.most_common()]
    # Named only as a payer, it goes last; a bank's own site still has its ИНН first.
    return sorted(order, key=lambda v: v not in plain)


# ИНН of services whose widgets and documents sit on other people's sites: a VK widget
# shows "ООО «ВК», ИНН 7842349892", a policy lists Яндекс and Google among third parties.
# On a site of its own the ИНН is the owner's; anywhere else it is not.
THIRD_PARTY_INNS: dict[str, tuple[str, ...]] = {
    "7842349892": ("vk.com", "vk.ru", "vk.company", "vkontakte.ru", "mail.ru", "ok.ru"),  # ООО «ВК»
    "7736207543": ("yandex.ru", "ya.ru", "yandex.com", "yandex.net"),  # ООО «Яндекс»
    "7704582421": ("google.com", "google.ru"),  # ООО «Гугл»
}


def drop_third_party(inns: list[str], own: Iterable[str]) -> list[str]:
    """``inns`` without those of known services, unless the site (``own``: its host
    names or registrable domains) is the service's own."""

    def theirs(host: str, domains: tuple[str, ...]) -> bool:
        return any(host == d or host.endswith("." + d) for d in domains)

    hosts = [h.lower().rstrip(".") for h in own]
    return [
        inn
        for inn in inns
        if inn not in THIRD_PARTY_INNS or any(theirs(h, THIRD_PARTY_INNS[inn]) for h in hosts)
    ]


# The advertiser's name, quoted, just before the ИНН: "Реклама АО «МегаФон Ритейл» ИНН".
_QUOTED = re.compile(r"[«\"“]([^«»\"“”]{2,60})[»\"”]")
_TRANSLIT = str.maketrans(
    {
        "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh",
        "з": "z", "и": "i", "й": "i", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o",
        "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "h", "ц": "c",
        "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu",
        "я": "ya",
    }
)  # fmt: skip


def own_ad_inns(text: str, domain: str) -> list[tuple[str, str]]:
    """(ИНН, advertiser) from ad labels whose advertiser carries the site's name.

    find_inns leaves ad labels out, as they name someone else; but a shop advertising
    itself names the site's owner, and that may be the only ИНН on the page:
    metro-cc.ru has "Реклама. ООО «МЕТРО Кэш энд Керри», ИНН 7704218694", megafon.ru
    "Реклама АО «МегаФон Ритейл» ИНН: 7825695758". A word of the name, in Latin
    letters, must be a label of the domain (metro, megafon)."""
    labels = {p for p in re.split(r"[.-]", domain.lower()) if len(p) >= 4}
    clean = _clean(text)
    found: Counter[tuple[str, str]] = Counter()
    for m in _INN_RE.finditer(clean):
        value = m.group(1)
        if not is_valid_inn(value):
            continue
        if not _AD_LABEL.search(clean, max(0, m.start() - 40), m.end() + 80):
            continue
        names = _QUOTED.findall(clean, max(0, m.start() - 80), m.start())
        if not names:
            continue
        words = re.findall(r"\w{4,}", names[-1].lower().translate(_TRANSLIT))
        if labels & set(words):
            found[(value, names[-1].strip())] += 1
    return [pair for pair, _ in found.most_common()]


def find_ogrns(text: str) -> list[str]:
    counts = Counter(m for m in _OGRN_RE.findall(_clean(text)) if is_valid_ogrn(m))
    return [o for o, _ in counts.most_common()]
