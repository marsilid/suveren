from pathlib import Path

from suveren.checks import Status
from suveren.compliance import ComplianceInput, PolicyInfo, evaluate
from suveren.page import parse_page
from suveren.pdpolicy import (
    CONSENT_TITLE,
    bundled_in_form,
    consent_doc_link,
    implied_in_document,
    missing_sections,
    policy_content,
)

FIXTURES = Path(__file__).parent / "fixtures" / "policies"
BASE = "https://example.ru/"


def text(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def run(html, policy=None):
    data = ComplianceInput(
        final_url=BASE, page=parse_page(html), deps=[], policy=policy or PolicyInfo()
    )
    return evaluate(data, html)


def find(checks, title):
    return next((c for c in checks if c.title == title), None)


def test_full_policy_has_every_section():
    assert missing_sections(text("full.txt")) == []
    assert policy_content(text("full.txt"), foreign=False).status is Status.OK


def test_full_policy_without_cross_border_when_site_uses_foreign_services():
    assert missing_sections(text("full.txt"), foreign=True) == [
        "трансграничная передача (на сайте есть иностранные сервисы)"
    ]


def test_partial_policy_lists_missing_sections():
    missing = missing_sections(text("partial.txt"))
    assert "цели обработки" in missing
    assert "правовые основания обработки" in missing
    assert "порядок уничтожения" in missing
    # The e-mail for requests is there.
    assert "как направить запрос оператору" not in missing
    check = policy_content(text("partial.txt"), foreign=False)
    assert check.status is Status.WARN
    assert "очень короткий" in check.details
    assert "71634598" in check.recommendation


def test_consent_hidden_in_offer_is_found_but_cookie_wording_is_not():
    quote = implied_in_document(text("offer_with_consent.txt"))
    assert quote and quote.startswith("Регистрация на Сайте означает согласие")
    assert (
        implied_in_document("Продолжая пользоваться сайтом, вы соглашаетесь на обработку cookie.")
        is None
    )
    # Consent described as a separate act is fine.
    assert implied_in_document(text("full.txt")) is None


def test_form_bundles_consent_with_offer():
    html = (
        '<form action="/order"><input type="tel" name="phone">'
        '<label><input type="checkbox" name="agree"> Я принимаю условия публичной оферты '
        "и даю согласие на обработку персональных данных</label></form>"
    )
    form = parse_page(html).forms[0]
    assert "условия публичной оферты" in bundled_in_form(form)
    check = find(run(html), CONSENT_TITLE)
    assert check.status is Status.WARN
    assert "вместе с другим документом или согласием" in check.details
    assert check.law == "152-ФЗ, ст. 9 ч. 1"


def test_form_with_two_checkboxes_is_not_bundled():
    html = (
        '<form action="/order"><input type="tel" name="phone">'
        '<label><input type="checkbox" name="offer"> Я принимаю условия оферты.</label>'
        '<label><input type="checkbox" name="pd"> Я даю <a href="/soglasie">согласие на '
        "обработку персональных данных</a>.</label></form>"
    )
    assert bundled_in_form(parse_page(html).forms[0]) is None
    check = find(run(html), CONSENT_TITLE)
    assert check.status is Status.OK
    assert check.link == "https://example.ru/soglasie"


def test_consent_with_policy_only_is_not_bundled():
    """The policy only informs; agreeing with it in the same checkbox is not flagged."""
    html = (
        '<form><input type="email" name="email"><input type="checkbox"> Я согласен с '
        "политикой конфиденциальности и даю согласие на обработку персональных данных</form>"
    )
    assert bundled_in_form(parse_page(html).forms[0]) is None


def test_forms_without_separate_consent_document_are_unknown():
    html = (
        '<form action="/lead"><input type="tel" name="phone"><input type="checkbox"> '
        "Согласен на обработку персональных данных</form>"
    )
    assert find(run(html), CONSENT_TITLE).status is Status.UNKNOWN


def test_no_forms_and_nothing_found_adds_no_check():
    assert find(run("<p>Привет</p>"), CONSENT_TITLE) is None


def test_consent_in_agreement_used_as_policy():
    policy = PolicyInfo(
        url=BASE + "terms",
        fetched=True,
        text=text("offer_with_consent.txt"),
        indirect_label="Пользовательское соглашение",
    )
    check = find(run("<p>x</p>", policy), CONSENT_TITLE)
    assert check.status is Status.WARN
    assert "«Пользовательское соглашение»" in check.details


def test_consent_link_text():
    links = parse_page(
        '<a href="/policy">Политика конфиденциальности</a>'
        '<a href="/consent">Согласие на обработку персональных данных</a>'
    ).links
    assert consent_doc_link(links).href == "/consent"
    assert consent_doc_link(parse_page('<a href="#">Согласие на обработку</a>').links) is None


def test_separate_labels_in_one_form_are_separate_statements():
    """Skillbox-like: a consent checkbox, a button, and a note about the site rules."""
    html = (
        '<form><input type="tel" name="phone"><label><input type="checkbox"> Я соглашаюсь '
        "на обработку персональных данных</label><button>Получить консультацию</button>"
        "<p>Нажимая на кнопку, я соглашаюсь с правилами сайта</p></form>"
    )
    form = parse_page(html).forms[0]
    assert len(form.statements) >= 3
    assert bundled_in_form(form) is None


def test_policy_page_that_is_only_the_site_shell_is_unknown():
    shell = "Каталог Вклады Кредиты Ипотека Войти Скачать приложение О компании Контакты " * 30
    check = policy_content(shell, foreign=False)
    assert check.status is Status.UNKNOWN
    assert "подгружается скриптом" in check.details


def test_consent_word_link_with_matching_href():
    links = parse_page(
        'Я даю <a href="/legal/agreement_lc_mail/">согласие</a> на обработку данных'
        '<a href="/promo">согласие</a>'
    ).links
    assert consent_doc_link(links).href == "/legal/agreement_lc_mail/"


def test_page_that_links_to_a_pdf_policy_is_unknown():
    page = (
        "Политика в отношении обработки персональных данных. Действующая политика по обработке "
        "персональных данных в формате PDF. Политика обработки персональных данных. "
        + "Вклады Кредиты Ипотека Калькуляторы Страхование Новости Отзывы Рейтинги "
        * 120
    )
    check = policy_content(page, foreign=False)
    assert check.status is Status.UNKNOWN
    assert "указатель" in check.details


def test_policy_link_and_bundled_consent_on_the_sign_in_page():
    """drom.ru: the home page has no policy link, the sign-in page does."""
    import asyncio

    import httpx

    from suveren.compliance import run_compliance

    home = '<a href="/">Главная</a><a href="https://my.example.ru/sign">Вход и регистрация</a>'
    home += "<p>Объявления о продаже автомобилей.</p>" * 100
    sign = (
        '<form action="/sign"><input name="login"><input type="password" name="password">'
        "<button>Войти</button></form><div>При входе вы принимаете "
        '<a href="https://www.example.ru/rules/">условия использования</a> сайта и соглашаетесь '
        "на обработку персональных данных согласно "
        '<a href="https://my.example.ru/help/personal_data">политике конфиденциальности</a>.</div>'
    )

    def handler(request):
        if request.url.path == "/sign":
            return httpx.Response(200, html=sign)
        if request.url.path == "/help/personal_data":
            return httpx.Response(200, html="<p>" + text("full.txt") + "</p>")
        return httpx.Response(404)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await run_compliance(client, BASE, home, [])

    checks = asyncio.run(go())
    policy = find(checks, "Политика обработки персональных данных")
    assert policy.status is Status.OK
    assert policy.link == "https://my.example.ru/help/personal_data"
    consent = find(checks, CONSENT_TITLE)
    assert consent.status is Status.WARN
    assert "на странице входа (my.example.ru/sign)" in consent.details


def test_bundled_consent_in_page_text_without_full_stops():
    from suveren.pdpolicy import bundled_in_text

    page = (
        "Телефон Пароль Войти с паролем восстановить доступ "
        * 10
        + "При входе вы принимаете условия использования сайта и соглашаетесь на обработку "
        "персональных данных согласно политике конфиденциальности ."
    )
    quote = bundled_in_text(page)
    assert quote.startswith("При входе вы принимаете условия использования")
    assert bundled_in_text("Я соглашаюсь на обработку персональных данных. " * 3) is None


def test_separate_documents_in_footer_or_checkboxes_are_not_bundled():
    from suveren.pdpolicy import bundled_in_text

    footer = (
        "Войти Пароль Пользовательское соглашение | Политика конфиденциальности | "
        "Согласие на обработку персональных данных © 2026"
    )
    assert bundled_in_text(footer) is None
    assert bundled_in_text(footer.replace(" |", "")) is None
    boxes = "Я принимаю условия оферты Я даю согласие на обработку персональных данных"
    assert bundled_in_text(boxes) is None
    # One statement in a checkbox label is still found.
    label = "Согласен с условиями оферты и обработкой персональных данных"
    assert bundled_in_text(label) == label


def test_policy_against_what_the_site_does():
    from suveren.checks import Status
    from suveren.pdpolicy import policy_reality

    text = (
        "Оператор не передает персональные данные третьим лицам. "
        "Трансграничная передача персональных данных не осуществляется. "
        "Сайт не использует файлы cookie."
    )
    check = policy_reality(text, ["Google Analytics"], ["Google Analytics"], ["Google Analytics"])
    assert check.id == "SUV-PD-011" and check.status is Status.WARN
    assert "«Оператор не передает персональные данные третьим лицам»" in check.details
    assert "трансграничная" in check.details.lower() and "cookies ставят" in check.details
    # Nothing on the site that contradicts it.
    assert policy_reality(text, [], [], []).status is Status.OK


def test_conditional_claims_are_not_contradictions():
    from suveren.checks import Status
    from suveren.pdpolicy import policy_reality

    text = (
        "Оператор не передает персональные данные третьим лицам, за исключением случаев, "
        "предусмотренных законом. Мы не передаем данные третьим лицам без вашего согласия."
    )
    assert policy_reality(text, ["Яндекс Метрика"], [], []).status is Status.OK
    # A purpose narrows the claim (hh.ru): not "no cookies at all".
    scoped = "Мы не используем файлы cookie для установления вашей личности."
    assert policy_reality(scoped, [], [], ["Яндекс Метрика"]).status is Status.OK
