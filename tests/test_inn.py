import pytest

from suveren.inn import classify, find_inns, find_ogrns, is_valid_inn, is_valid_ogrn


@pytest.mark.parametrize("inn", ["7707083893", "7810962785", "7801451618", "500100732259"])
def test_valid_inn(inn):
    assert is_valid_inn(inn)


@pytest.mark.parametrize("inn", ["7707083894", "1234567890", "77070838", "abcdefghij"])
def test_invalid_inn(inn):
    assert not is_valid_inn(inn)


def test_valid_ogrn():
    assert is_valid_ogrn("1027700132195")
    assert not is_valid_ogrn("1027700132196")


def test_classify():
    assert classify("7707083893") == "inn"
    assert classify(" 1027700132195 ") == "ogrn"
    assert classify("123") is None


def test_find_inns_in_markup():
    html = (
        "<footer>ООО «Ромашка»<br><b>ИНН</b>&nbsp;7707083893, КПП 773601001, "
        "ОГРН 1027700132195. Телефон 7707083894</footer>"
    )
    assert find_inns(html) == ["7707083893"]
    assert find_ogrns(html) == ["1027700132195"]


def test_find_inns_ignores_bad_checksum():
    assert find_inns("ИНН: 1234567890") == []
