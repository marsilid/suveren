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


def test_advertiser_inn_in_an_ad_label_is_not_the_site_owner():
    from suveren.inn import find_inns

    html = (
        "<div>Реклама. ООО «Рекламодатель», ИНН 7736207543. erid: 2SDnjeL1abc</div>"
        "<p>Каталог курсов, отзывы студентов и расписание занятий.</p>"
        "<footer>ООО «Сайт», ИНН 7707083893</footer>"
    )
    assert find_inns(html) == ["7707083893"]


def test_a_shop_advertising_itself_names_its_own_inn():
    from suveren.inn import own_ad_inns

    # metro-cc.ru and megafon.ru: the only ИНН on the page is in their own ad labels.
    metro = "<div>Реклама. ООО «МЕТРО Кэш энд Керри», ИНН 7704218694. &amp;erid=2VSb5wwGR6A</div>"
    assert own_ad_inns(metro, "metro-cc.ru") == [("7704218694", "МЕТРО Кэш энд Керри")]
    megafon = "Реклама АО «МегаФон Ритейл» ИНН: 7825695758 Смартфоны Erid: LjN8KA3JG"
    assert own_ad_inns(megafon, "www.megafon.ru") == [("7825695758", "МегаФон Ритейл")]
    # Someone else's ad on the site is not the owner's.
    other = "<div>Реклама. ООО «Рекламодатель», ИНН 7736207543. erid: 2SDnjeL1abc</div>"
    assert own_ad_inns(other, "hse.ru") == []
    # A footer ИНН is not an ad label: find_inns takes it, not this.
    assert own_ad_inns("ООО «МЕТРО Кэш энд Керри», ИНН 7704218694", "metro-cc.ru") == []


def test_a_partner_named_in_a_document_is_not_the_site_owner():
    from suveren.inn import find_inns

    # rbc.ru's offer: the course platform belongs to a partner, not to the site.
    offer = (
        "Доступ к услуге осуществляется посредством платформы productstar.ru, оператором "
        "которой является партнер Администрации ООО «Тривиум» (ОГРН 1187847013133, "
        "ИНН 7806297293), при этом процесс оказания услуг не подразумевает…"
    )
    assert find_inns(offer) == []
    assert find_inns(offer + " АО «Сайт», ИНН 7707083893") == ["7707083893"]


@pytest.mark.parametrize(
    "text",
    ["ИНН/КПП: 7707083893/770701001", "ИНН / КПП 7707083893 / 770701001",
     "ИНН (КПП): 7707083893 (770701001)", "ИНН-КПП 7707083893-770701001",
     "ИНН организации 7707083893", "INN/KPP 7707083893/770701001"],
)  # fmt: skip
def test_find_inns_in_requisites_with_kpp(text):
    assert find_inns(text) == ["7707083893"]


def test_bank_named_more_often_does_not_outrank_the_owner():
    html = (
        "<footer>ООО «Ромашка», ИНН 7707083893</footer>"
        "<div>Платежи принимает АО «Альфа-Банк» ИНН 7728168971</div>"
        "<p>Оплата картой через АО «Альфа-Банк», ИНН 7728168971</p>"
    )
    assert find_inns(html) == ["7707083893", "7728168971"]
    assert find_inns(html, first=True) == ["7707083893", "7728168971"]


def test_bank_own_site_keeps_its_inn():
    assert find_inns("© ПАО Сбербанк, ИНН 7707083893") == ["7707083893"]
    # The owner's footer right after a payment block is still the owner's.
    text = "Оплата картой АО «Альфа-Банк» ИНН 7728168971. ООО «Ромашка», ИНН 7707083893"
    assert find_inns(text)[0] == "7707083893"
