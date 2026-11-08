from suveren.checks import Status
from suveren.cms import cms_check, detect_cms

BASE = "https://shop.ru/"


def found(html: str, where: str = "главная"):
    return detect_cms([(where, html)], BASE, "shop.ru")


def test_wordpress_version_from_the_generator_tag_any_attribute_order():
    cms = found('<meta content="WordPress 6.4.3" name=generator>')
    assert [(c.name, c.version) for c in cms] == [("wordpress", "6.4.3")]
    check = cms_check(cms)
    assert check is not None and check.status is Status.UNKNOWN
    assert "WordPress 6.4.3" in check.details and "уязвим" in check.details
    assert "уязвима" not in check.details.lower().replace("уязвимости", "")
    assert check.evidence[0].value == "WordPress 6.4.3"
    assert "wordpress.org/download/releases" in check.recommendation


def test_wordpress_version_from_its_own_core_files_only():
    html = (
        '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
        "<link rel=stylesheet href='https://shop.ru/wp-includes/css/dist/block-library/"
        "style.min.css?ver=6.5.2'>"
    )
    cms = found(html)
    assert [(c.name, c.version) for c in cms] == [("wordpress", "6.5.2")]
    assert cms[0].signs[0].value.endswith("style.min.css?ver=6.5.2")


def test_bundled_library_version_is_not_wordpress():
    cms = found('<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1&amp;x=1"></script>')
    assert [(c.name, c.version) for c in cms] == [("wordpress", None)]
    check = cms_check(cms)
    assert "версия снаружи не видна" in check.details and "не указан" in check.details


def test_bitrix_by_its_paths_on_any_page():
    cms = detect_cms(
        [
            ("главная", "<p>нет</p>"),
            ("/catalog", '<script src="/bitrix/js/main/core/core.min.js?1700000000"></script>'),
        ],
        BASE,
        "shop.ru",
    )
    assert [(c.name, c.version) for c in cms] == [("bitrix", None)]
    check = cms_check(cms)
    assert check.status is Status.UNKNOWN and "1С-Битрикс" in check.details
    assert "Обновление платформы" in check.recommendation
    assert check.evidence[0].what == "Путь 1С-Битрикс (страница /catalog)"


def test_bitrix_generator_tag():
    cms = found('<meta name="generator" content="1C-Bitrix 23.0">')
    assert [(c.name, c.version) for c in cms] == [("bitrix", "23.0")]


def test_other_sites_and_hosted_wordpress_are_not_the_sites_cms():
    html = (
        '<img src="https://blog.other.ru/wp-content/uploads/a.png">'
        '<a href="https://www.1c-bitrix.ru/bitrix/templates/">Сайт на 1С-Битрикс</a>'
        '<meta name="generator" content="WordPress.com">'
        '<meta name="generator" content="WooCommerce 8.0.1">'
    )
    assert found(html) == []
    assert cms_check([]) is None


def test_signs_are_few_and_unique_but_the_version_is_kept():
    html = "".join(f'<img src="/wp-content/uploads/{i}.png">' for i in range(6))
    html += '<img src="/wp-content/uploads/0.png">'
    html += '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.4.3"></script>'
    (wp,) = found(html)
    assert wp.version == "6.4.3" and len(wp.signs) == 4
    assert "wp-emoji-release" in wp.signs[0].value
