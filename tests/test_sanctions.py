from pathlib import Path

import pytest

from suveren.sanctions import (
    SanctionsIndex,
    brand,
    extract_ids,
    name_key,
    parse_eu_csv,
    parse_ofac_xml,
    parse_uk_csv,
    screen_company,
    screen_person,
    skeleton,
    soft,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def index():
    entries = [
        *parse_ofac_xml(FIXTURES / "sdn_sample.xml"),
        *parse_eu_csv(FIXTURES / "eu_sample.csv"),
        *parse_uk_csv(FIXTURES / "uk_sample.csv"),
    ]
    return SanctionsIndex(entries)


def test_ofac_parser():
    entries = {e.ref: e for e in parse_ofac_xml(FIXTURES / "sdn_sample.xml")}
    assert set(entries) == {"17018", "34796", "40001", "50001"}  # vessel skipped
    sber = entries["17018"]
    assert sber.kind == "entity"
    assert sber.ids == ["1027700132195", "7707083893"]
    assert "SBERBANK ROSSII" in sber.names
    assert entries["34796"].names[0] == "Herman Oskarovich GREF"
    assert entries["34796"].kind == "person"


def test_eu_parser_groups_rows():
    entries = {e.ref: e for e in parse_eu_csv(FIXTURES / "eu_sample.csv")}
    assert entries["EU.8537.32"].names == ["Sberbank", "Сбербанк"]
    assert entries["EU.8537.32"].ids == ["1027700132195"]
    assert entries["EU.7889.11"].kind == "person"
    assert entries["EU.9999.1"].ids == []  # bad checksum is ignored


def test_uk_parser_skips_preamble_and_reads_cyrillic():
    entries = {e.ref: e for e in parse_uk_csv(FIXTURES / "uk_sample.csv")}
    sber = entries["RUS0256"]
    assert "ПАО Сбербанк" in sber.names
    assert set(sber.ids) == {"7707083893", "1027700132195"}
    assert entries["RUS1057"].names[0] == "Herman Oskarovich GREF"


def test_extract_ids():
    assert extract_ids("Tax ID No. 7707083893; Reg 1027700132195; tel 79001234567") == [
        "7707083893",
        "1027700132195",
    ]


def test_name_keys_match_across_scripts():
    assert name_key('ПУБЛИЧНОЕ АКЦИОНЕРНОЕ ОБЩЕСТВО "СБЕРБАНК РОССИИ"') == name_key(
        "Public Joint Stock Company Sberbank of Russia"
    )
    assert skeleton("Дмитрий") == skeleton("Dmitry") == skeleton("Dmitrii")


def test_soft_keeps_gender_endings():
    assert soft("Любимов") != soft("LYUBIMOVA")
    assert soft("Олег") != soft("Olga")
    assert soft("Герман") == soft("Herman")
    assert soft("Евгений") == soft("Yevgeniy") == soft("Evgeny")


def test_brand():
    assert brand('ПАО "НК "РОСНЕФТЬ"') == "РОСНЕФТЬ"
    assert brand('ООО "Ромашка"') == "Ромашка"
    assert brand('ООО "Мир"') is None  # too short to be distinctive
    assert brand("ПАО СБЕРБАНК") is None


def test_screen_by_id_finds_all_lists(index):
    hits = screen_company(index, ["7707083893"], ["ПАО СБЕРБАНК"])
    assert {h.entry.source for h in hits} == {"us", "uk"}
    assert all(h.how == "id" for h in hits)


def test_screen_by_name(index):
    hits = screen_company(index, [], ['ПУБЛИЧНОЕ АКЦИОНЕРНОЕ ОБЩЕСТВО "СБЕРБАНК РОССИИ"'])
    assert {h.how for h in hits} == {"name"}
    assert "us" in {h.entry.source for h in hits}


def test_exact_name_beats_partial(index):
    hits = screen_company(index, [], ['ООО "РОМАШКА"'])
    assert [(h.entry.ref, h.how) for h in hits] == [("EU.9999.1", "name")]


def test_screen_partial_brand(index):
    hits = screen_company(index, [], ['АО "ТД "РОМАШКА"'])
    assert {h.entry.ref for h in hits} == {"50001", "EU.9999.1"}
    assert all(h.how == "partial" for h in hits)


def test_clean_company(index):
    assert screen_company(index, ["7810962785"], ['АО "СЕЛЕКТЕЛ"']) == []


def test_screen_person(index):
    hits = screen_person(index, "Греф Герман Оскарович")
    assert {h.entry.source for h in hits} == {"us", "eu", "uk"}


def test_screen_person_rejects_feminine_namesake(index):
    assert screen_person(index, "Любимов Олег Игоревич") == []


def test_screen_person_uses_the_patronymic():
    from suveren.sanctions import Entry, SanctionsIndex

    index = SanctionsIndex(
        [
            Entry("eu", "1", "person", ["Sergei Viktorovich IVANOV"], [], "RUS"),
            Entry("uk", "2", "person", ["IVANOV, Sergei"], [], "Russia"),
        ]
    )
    # Another patronymic: the EU entry is another man; the UK one has none, so it stays.
    other = screen_person(index, "Иванов Сергей Петрович")
    assert [(h.entry.source, h.how) for h in other] == [("uk", "person")]
    same = screen_person(index, "Иванов Сергей Викторович")
    assert {(h.entry.source, h.how) for h in same} == {("eu", "person_full"), ("uk", "person")}
    assert same[0].how_ru
    # Without a patronymic on our side nothing is ruled out.
    assert len(screen_person(index, "Иванов Сергей")) == 2


def test_a_list_that_parses_to_nothing_is_not_counted(tmp_path, monkeypatch):
    # A source in a new format gave 0 entries without a word, and the check still said
    # "Не найдена в списках" as if every list had been searched.
    import asyncio

    import suveren.sanctions as sanctions
    from suveren.sanctions import Entry, load_index

    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))

    async def fetch_cached(client, url, name, *, refresh=False):
        path = tmp_path / name
        path.write_text("data", encoding="utf-8")
        return path, None

    one = Entry("us", "1", "entity", ["ROMASHKA"], ["7707083893"], "RUSSIA-EO14024")
    monkeypatch.setattr(sanctions, "fetch_cached", fetch_cached)
    monkeypatch.setattr(
        sanctions, "PARSERS", {"us": lambda p: [one], "eu": lambda p: [], "uk": lambda p: []}
    )
    index = asyncio.run(load_index(None))  # type: ignore[arg-type]
    assert index.sources == ["us"]
    assert sum("ни одной записи" in n for n in index.notes) == 2


def test_same_consonants_are_not_the_same_name():
    # The consonant key is only the lookup: «Гранит» and GARANTIYA share "grnt",
    # «Арсенал» and «5 ARSENAL» differ only by a number the key drops.
    from suveren.sanctions import Entry, same_name

    assert not same_name("ООО «Гранит»", "LIMITED LIABILITY COMPANY GARANTIYA")
    assert not same_name("ООО «Арсенал»", "JOINT STOCK COMPANY 5 ARSENAL")
    assert same_name("ООО «Арсенал»", "LLC ARSENAL")
    assert same_name("ПАО «Сбербанк России»", "PUBLIC JOINT STOCK COMPANY SBERBANK OF RUSSIA")
    entries = [
        Entry("us", "1", "entity", ["LIMITED LIABILITY COMPANY GARANTIYA"], [], "RUSSIA"),
        Entry("us", "2", "entity", ["JOINT STOCK COMPANY 5 ARSENAL"], [], "RUSSIA"),
    ]
    index = SanctionsIndex(entries)
    assert screen_company(index, [], ["ООО «Гранит»"]) == []
    # «5 ARSENAL» is still a similar name worth a look, not the same one.
    assert {h.how for h in screen_company(index, [], ["ООО «Арсенал»"])} == {"partial"}


def test_a_listed_entry_with_other_ids_is_another_organisation():
    from suveren.sanctions import Entry

    index = SanctionsIndex([
        Entry("us", "1", "entity", ["LLC ARSENAL"], ["2465316804"], "RUSSIA"),
        Entry("uk", "2", "entity", ["LLC ARSENAL"], ["1142468044179"], "RUS"),
    ])  # fmt: skip
    hits = {h.entry.ref: h.how for h in screen_company(index, ["7812345675"], ["ООО «Арсенал»"])}
    # Our ИНН against the entry's ИНН: other. Our ИНН against an ОГРН alone: can't tell.
    assert hits == {"1": "other", "2": "name"}
    both = screen_company(index, ["7812345675", "1027700132195"], ["ООО «Арсенал»"])
    assert {h.how for h in both} == {"other"}
    assert {h.how for h in screen_company(index, [], ["ООО «Арсенал»"])} == {"name"}
