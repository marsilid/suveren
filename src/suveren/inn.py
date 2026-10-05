"""Russian company identifiers: ИНН and ОГРН, with checksum validation."""

from __future__ import annotations

import re
from collections import Counter

_INN_RE = re.compile(r"(?:инн|inn)[\s:№#./-]{0,6}(\d{10}|\d{12})(?!\d)", re.IGNORECASE)
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


def find_inns(text: str) -> list[str]:
    """Valid ИНН mentioned in the text, most frequent first."""
    counts = Counter(m for m in _INN_RE.findall(_clean(text)) if is_valid_inn(m))
    return [inn for inn, _ in counts.most_common()]


def find_ogrns(text: str) -> list[str]:
    counts = Counter(m for m in _OGRN_RE.findall(_clean(text)) if is_valid_ogrn(m))
    return [o for o, _ in counts.most_common()]
