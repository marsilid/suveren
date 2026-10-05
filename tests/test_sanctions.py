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
