"""Sanctions screening against the official US, EU and UK lists.

The raw files are downloaded once a day and reduced to a compact index
(names, identifiers, programmes). Matching is done three ways:

* by ИНН/ОГРН found in the list entry — a reliable match;
* by the full company name after transliteration — a likely match;
* by a person's surname and first name — a possible match that a human must
  confirm (namesakes are common).
"""

from __future__ import annotations

import csv
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from suveren.cache import cache_dir, fetch_cached
from suveren.errors import ModuleError
from suveren.inn import classify

INDEX_VERSION = 1  # bump when the cached index format changes


@dataclass(frozen=True)
class Source:
    key: str
    title: str
    url: str
    filename: str


SOURCES = (
    Source(
        "us",
        "США (OFAC SDN)",
        "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML",
        "sanctions-us-sdn.xml",
    ),
    Source(
        "eu",
        "ЕС (сводный санкционный список)",
        "https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList_1_1/"
        "content?token=dG9rZW4tMjAxNw",
        "sanctions-eu.csv",
    ),
    Source(
        "uk",
        "Великобритания (UK Sanctions List)",
        "https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv",
        "sanctions-uk.csv",
    ),
)
SOURCE_TITLES = {s.key: s.title for s in SOURCES}


# --- Names --------------------------------------------------------------------------

_TRANSLIT = str.maketrans(
    {
        "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh",
        "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o",
        "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "kh", "ц": "ts",
        "ч": "ch", "ш": "sh", "щ": "shch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu",
        "я": "ya", "і": "i", "ї": "i", "є": "e", "ґ": "g",
    }
)  # fmt: skip
_SPELLING = (
    ("shch", "sh"), ("sch", "sh"), ("tch", "ch"), ("kh", "h"), ("ks", "x"), ("zh", "z"),
    ("ts", "c"), ("tz", "c"), ("ph", "f"), ("w", "v"), ("ck", "k"), ("q", "k"), ("h", "g"),
)  # fmt: skip
_VOWELS = re.compile(r"[aeiouy]")

# Legal forms and filler words, compared after transliteration.
_STOP = frozenset(
    """
    obshchestvo ogranichennoy ogranichennoi otvetstvennostyu aktsionernoe publichnoe
    nepublichnoe zakrytoe otkrytoe ooo oao zao pao ao nao ip gup fgup mup ano nko
    federalnoe gosudarstvennoe unitarnoe munitsipalnoe predpriyatie uchrezhdenie
    kompaniya korporatsiya gruppa limited liability company joint stock public open
    closed llc jsc pjsc ojsc cjsc ltd inc co the of and i a imeni named after
    """.split()  # noqa: SIM905 - long word list reads better as text
)


def translit(text: str) -> str:
    return text.lower().translate(_TRANSLIT)


def skeleton(word: str) -> str:
    """Spelling-insensitive key: 'Сбербанк' and 'SBERBANK' give the same result.

    Transliterate, unify common spelling variants, then keep the first letter and
    the consonants. Different romanisations (Dmitriy/Dmitry/Dmitrii) collapse.
    """
    w = re.sub(r"[^a-z0-9]", "", translit(word))
    for src, dst in _SPELLING:
        w = w.replace(src, dst)
    if not w:
        return ""
    key = w[0] + _VOWELS.sub("", w[1:])
    return re.sub(r"(.)\1+", r"\1", key)


def soft(word: str) -> str:
    """Gentler key for personal names: keeps vowels, so Lyubimov != Lyubimova.

    Unifies romanisation variants only: Dmitriy/Dmitry/Dmitrii, Yevgeny/Evgeny,
    Herman/German.
    """
    w = re.sub(r"[^a-z0-9]", "", translit(word))
    for src, dst in _SPELLING:
        w = w.replace(src, dst)
    w = w.replace("y", "i").replace("j", "i")
    w = re.sub(r"^ie", "e", w)
    return re.sub(r"(.)\1+", r"\1", w)


def tokens(name: str) -> list[str]:
    words = re.findall(r"[0-9a-zа-яёіїєґ]+", name.lower())
    return [w for w in words if translit(w) not in _STOP]


def name_key(name: str) -> frozenset[str]:
    return frozenset(k for w in tokens(name) if len(k := skeleton(w)) >= 2)


def brand(name: str) -> str | None:
    """Innermost quoted part of a Russian company name.

    'ООО "Ромашка"' -> 'Ромашка'; 'ПАО "НК "РОСНЕФТЬ"' -> 'РОСНЕФТЬ'. Only a single
    distinctive word (6+ letters) qualifies, otherwise matching would be too noisy.
    """
    parts = re.split(r"[\"«»“”„]", name)
    if len(parts) < 2:
        return None
    candidate = next((p.strip() for p in reversed(parts) if re.search(r"\w", p)), "")
    words = tokens(candidate)
    return candidate if len(words) == 1 and len(words[0]) >= 6 else None


# --- Index ------------------------------------------------------------------------------


@dataclass(slots=True)
class Entry:
    source: str
    ref: str
    kind: str  # "entity" | "person"
    names: list[str]
    ids: list[str]
    programs: str

    def to_json(self) -> list[Any]:
        return [self.source, self.ref, self.kind, self.names, self.ids, self.programs]

    @classmethod
    def from_json(cls, row: list[Any]) -> Entry:
        return cls(*row)


def extract_ids(*texts: str) -> list[str]:
    """Valid ИНН/ОГРН mentioned anywhere in the given strings."""
    found = []
    for text in texts:
        for digits in re.findall(r"(?<!\d)(\d{10}|\d{12}|\d{13}|\d{15})(?!\d)", text or ""):
            if classify(digits) and digits not in found:
                found.append(digits)
    return found


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_ofac_xml(path: Path) -> Iterator[Entry]:
    for _, elem in ET.iterparse(path, events=("end",)):
        if _local(elem.tag) != "sdnEntry":
            continue
        fields: dict[str, str] = {}
        names: list[str] = []
        ids: list[str] = []
        programs: list[str] = []
        for child in elem:
            tag = _local(child.tag)
            if tag in ("uid", "sdnType", "lastName", "firstName", "remarks"):
                fields[tag] = (child.text or "").strip()
            elif tag == "programList":
                programs = [(p.text or "").strip() for p in child]
            elif tag == "akaList":
                for aka in child:
                    parts = {_local(x.tag): (x.text or "").strip() for x in aka}
                    alias = " ".join(filter(None, (parts.get("firstName"), parts.get("lastName"))))
                    if alias:
                        names.append(alias)
            elif tag == "idList":
                for item in child:
                    parts = {_local(x.tag): (x.text or "").strip() for x in item}
                    ids += extract_ids(parts.get("idNumber", ""))
        elem.clear()
        kind = {"Entity": "entity", "Individual": "person"}.get(fields.get("sdnType", ""))
        if kind is None:
            continue
        main = " ".join(filter(None, (fields.get("firstName"), fields.get("lastName"))))
        ids += [i for i in extract_ids(fields.get("remarks", "")) if i not in ids]
        yield Entry("us", fields.get("uid", ""), kind, [main, *names], ids, ", ".join(programs))


def _grouped_csv(rows: Iterable[dict[str, str]], key: str) -> Iterator[list[dict[str, str]]]:
    group: list[dict[str, str]] = []
    current = None
    for row in rows:
        if row.get(key) != current and group:
            yield group
            group = []
        current = row.get(key)
        group.append(row)
    if group:
        yield group


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(v.strip() for v in values if v and v.strip()))


def parse_eu_csv(path: Path) -> Iterator[Entry]:
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh, delimiter=";")
        for group in _grouped_csv(reader, "Entity_LogicalId"):
            first = group[0]
            subject = first.get("Entity_SubjectType_ClassificationCode") or first.get(
                "Entity_SubjectType", ""
            )
            kind = {"person": "person", "P": "person", "enterprise": "entity", "E": "entity"}.get(
                subject
            )
            if kind is None:
                continue
            names = _unique(r.get("NameAlias_WholeName", "") for r in group)
            ids = extract_ids(
                *(r.get("Identification_Number", "") for r in group), first.get("Entity_Remark", "")
            )
            programs = ", ".join(_unique(r.get("Entity_Regulation_Programme", "") for r in group))
            ref = first.get("Entity_EU_ReferenceNumber") or first.get("Entity_LogicalId", "")
            yield Entry("eu", ref, kind, names, ids, programs)


def parse_uk_csv(path: Path) -> Iterator[Entry]:
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    with path.open(encoding="utf-8-sig", newline="") as fh:
        first_line = fh.readline()
        if first_line.startswith("Last Updated"):  # no "Report Date" preamble
            fh.seek(0)
        reader = csv.DictReader(fh)
        for group in _grouped_csv(reader, "Unique ID"):
            first = group[0]
            kind = {"Individual": "person", "Entity": "entity"}.get(
                first.get("Designation Type", "")
            )
            if kind is None:
                continue
            names = []
            for r in group:
                given = " ".join(r.get(f"Name {i}", "") for i in range(1, 6))
                names.append(" ".join(f"{given} {r.get('Name 6', '')}".split()))
                names.append(r.get("Name non-latin script", ""))
            ids = extract_ids(
                *(r.get("National Identifier number", "") for r in group),
                *(r.get("Business registration number (s)", "") for r in group),
                first.get("Other Information", ""),
            )
            yield Entry(
                "uk", first.get("Unique ID", ""), kind, _unique(names), ids,
                first.get("Regime Name", ""),
            )  # fmt: skip


PARSERS = {"us": parse_ofac_xml, "eu": parse_eu_csv, "uk": parse_uk_csv}


class SanctionsIndex:
    def __init__(self, entries: list[Entry], notes: list[str] | None = None) -> None:
        self.entries = entries
        self.notes = notes or []
        self.sources = sorted({e.source for e in entries})
        self.by_id: dict[str, list[Entry]] = {}
        self.by_key: dict[frozenset[str], list[Entry]] = {}
        self.by_token: dict[str, list[Entry]] = {}
        self.by_person: dict[str, list[Entry]] = {}
        for entry in entries:
            if entry.kind == "person":
                for word in {soft(w) for n in entry.names for w in tokens(n)}:
                    if len(word) >= 2:
                        self.by_person.setdefault(word, []).append(entry)
            for ident in entry.ids:
                self.by_id.setdefault(ident, []).append(entry)
            for name in entry.names:
                key = name_key(name)
                if not key:
                    continue
                self.by_key.setdefault(key, []).append(entry)
                for tok in key:
                    bucket = self.by_token.setdefault(tok, [])
                    if not bucket or bucket[-1] is not entry:
                        bucket.append(entry)


@dataclass(slots=True)
class Hit:
    entry: Entry
    how: str  # "id" | "name" | "partial" | "person"
    matched: str

    @property
    def how_ru(self) -> str:
        return {
            "id": "совпадение по ИНН/ОГРН",
            "name": "совпадение по названию",
            "partial": "похожее название",
            "person": "возможное совпадение по ФИО",
        }[self.how]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.entry.source,
            "source_title": SOURCE_TITLES.get(self.entry.source, self.entry.source),
            "ref": self.entry.ref,
            "name": self.entry.names[0] if self.entry.names else "",
            "how": self.how,
            "matched": self.matched,
            "programs": self.entry.programs,
        }


def screen_company(
    index: SanctionsIndex, ids: Iterable[str], names: Iterable[str], max_partial: int = 5
) -> list[Hit]:
    hits: list[Hit] = []
    seen: set[int] = set()

    def add(entry: Entry, how: str, matched: str) -> None:
        if id(entry) not in seen and entry.kind == "entity":
            seen.add(id(entry))
            hits.append(Hit(entry, how, matched))

    for ident in ids:
        for entry in index.by_id.get(ident, []):
            add(entry, "id", ident)
    names = [n for n in names if n]
    if hits:  # identifier matches are exact; same-name entries would only add noise
        return hits
    for name in names:
        key = name_key(name)
        if len(key) >= 1 and sum(len(k) for k in key) >= 4:
            for entry in index.by_key.get(key, []):
                add(entry, "name", name)
    if not hits:
        partial = 0
        for name in names:
            mark = brand(name)
            if not mark:
                continue
            tok = skeleton(mark)
            for entry in index.by_token.get(tok, []):
                if partial >= max_partial:
                    break
                if entry.kind == "entity" and any(len(name_key(n)) <= 3 for n in entry.names):
                    add(entry, "partial", mark)
                    partial += 1
    return hits


def screen_person(index: SanctionsIndex, full_name: str) -> list[Hit]:
    """'Фамилия Имя Отчество' — surname and first name must both match."""
    words = [w for w in re.findall(r"[^\s]+", full_name) if len(w) >= 2]
    if len(words) < 2:
        return []
    surname, given = soft(words[0]), soft(words[1])
    hits = []
    for entry in index.by_person.get(surname, []):
        for name in entry.names:
            key = {soft(w) for w in tokens(name)}
            if surname in key and given in key:
                hits.append(Hit(entry, "person", full_name))
                break
    return hits


async def load_index(client: httpx.AsyncClient, *, refresh: bool = False) -> SanctionsIndex:
    """Download (if stale) and parse all lists; a failed source is skipped with a note."""
    entries: list[Entry] = []
    notes: list[str] = []
    for source in SOURCES:
        try:
            raw, note = await fetch_cached(client, source.url, source.filename, refresh=refresh)
        except ModuleError as exc:
            notes.append(f"{source.title}: {exc}")
            continue
        if note:
            notes.append(f"{source.title}: {note}")
        entries += _cached_entries(source, raw, notes)
    if not entries:
        raise ModuleError("не удалось загрузить ни один санкционный список")
    return SanctionsIndex(entries, notes)


def _cached_entries(source: Source, raw: Path, notes: list[str]) -> list[Entry]:
    index_path = cache_dir() / f"{source.filename}.index.json"
    if index_path.exists() and index_path.stat().st_mtime >= raw.stat().st_mtime:
        try:
            data = json.loads(index_path.read_text(encoding="utf-8"))
            if data.get("version") == INDEX_VERSION:
                return [Entry.from_json(row) for row in data["entries"]]
        except (OSError, ValueError, KeyError, TypeError):
            pass
    try:
        entries = list(PARSERS[source.key](raw))
    except (OSError, ET.ParseError, csv.Error, UnicodeDecodeError) as exc:
        notes.append(f"{source.title}: файл не разобран ({type(exc).__name__})")
        return []
    index_path.write_text(
        json.dumps(
            {"version": INDEX_VERSION, "entries": [e.to_json() for e in entries]},
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return entries
