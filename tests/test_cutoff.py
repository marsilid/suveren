from suveren.checks import Status
from suveren.cutoff import (
    HostInfo,
    compare,
    infra_check,
    known_service,
    page_check,
    render_blocking,
    third_party_hosts,
)
from suveren.models import Category, Dependency, Severity
from suveren.plan import Profile, make_plan

FONTS = HostInfo("fonts.googleapis.com", "Google Fonts", "US")
CAPTCHA = HostInfo("www.google.com", "Google reCAPTCHA", "US")
CDN = HostInfo("img.example-cdn.net", "Cloudflare", "US", via_network=True)


def dom(controls=(), frames=(), broken=0, fonts=(), forms=(), text=5000):
    return {
        "controls": list(controls),
        "frames": list(frames),
        "broken": broken,
        "images": 10,
        "fonts": list(fonts),
        "forms": list(forms),
        "text": text,
    }


def run(base1, base2, cut, blocked, hosts=None, errors=((), (), ()), **kw):
    hosts = hosts or {h.host: h for h in (FONTS, CAPTCHA, CDN)}
    return compare(
        base1,
        base2,
        cut,
        errors1=list(errors[0]),
        errors2=list(errors[1]),
        errors_cut=list(errors[2]),
        hosts=hosts,
        blocked_hosts=set(blocked),
        **kw,
    )


def test_only_what_is_stable_in_both_normal_loads_counts():
    base1 = dom(["Купить", "Карта", "Новость дня А", "5 минут назад", "+14"], fonts=["Roboto"])
    base2 = dom(["Купить", "Карта", "Новость дня Б", "5 минут назад", "+14"], fonts=["Roboto"])
    cut = dom(["Купить"], fonts=[])
    r = run(base1, base2, cut, {"fonts.googleapis.com"})
    # The rotating headline and the relative time are noise, not breakage.
    assert r.gone_controls == ["Карта"]
    assert r.lost_fonts == ["Roboto"]
    assert [h.host for h in r.blocked] == ["fonts.googleapis.com"]


def test_new_js_errors_and_vanished_frames():
    base = dom(frames=["www.youtube.com", "yandex.ru"])
    cut = dom(frames=["yandex.ru"])
    r = run(
        base,
        base,
        cut,
        {"www.youtube.com"},
        errors=(["old"], [], ["old", "ReferenceError: jQuery is not defined"]),
    )
    assert r.new_errors == ["ReferenceError: jQuery is not defined"]
    assert r.gone_frames == ["www.youtube.com"]


def test_captcha_forms_text_drop_and_visual_change_beyond_noise():
    base = dom(forms=[{"fields": 3, "captcha": "recaptcha"}], text=10000)
    cut = dom(forms=[{"fields": 3, "captcha": "recaptcha"}], text=6000)
    r = run(base, base, cut, {"www.google.com"}, noise=0.04, change=0.34)
    assert r.captcha_forms == 1
    assert round(r.text_drop, 2) == 0.4
    assert round(r.visual_change, 2) == 0.3
    check = page_check(r, {})
    assert check.status is Status.FAIL and check.id == "SUV-CUT-002"
    assert "капчей" in check.details and "40% текста" in check.details


def test_nothing_visible_is_ok_and_nothing_foreign_is_ok():
    base = dom(["Купить"])
    r = run(base, base, base, {"fonts.googleapis.com"}, noise=0.01, change=0.02)
    check = page_check(r, {})
    assert check.status is Status.OK and "Заметных изменений нет" in check.details
    empty = run(base, base, base, set())
    assert "отключать нечего" in page_check(empty, {}).details


def test_render_blocking_resources_in_head_only():
    html = (
        "<html><head>"
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">'
        '<script src="https://cdn.example.com/a.js" async></script>'
        '<script src="//img.example-cdn.net/lib.js"></script>'
        '</head><body><script src="https://fonts.googleapis.com/late.js"></script></body></html>'
    )
    foreign = {"fonts.googleapis.com", "img.example-cdn.net", "cdn.example.com"}
    assert render_blocking(html, "https://site.ru/", foreign) == [
        "fonts.googleapis.com",
        "img.example-cdn.net",
    ]


def test_render_blocking_alone_is_a_warning():
    base = dom(["Купить"])
    r = run(base, base, base, {"fonts.googleapis.com"})
    r.render_blocking = ["fonts.googleapis.com"]
    check = page_check(r, {})
    assert check.status is Status.WARN and "останется белой" in check.details


def test_labels_and_hosts():
    assert CDN.label() == "img.example-cdn.net (через Cloudflare, США)"
    assert FONTS.label() == "Google Fonts (США)"
    assert HostInfo("x.io", None, None).label() == "x.io"
    urls = [
        "https://site.ru/a.js",
        "https://cdn.site.ru/b.css",
        "https://fonts.googleapis.com/css",
        "data:image/png;base64,xx",
        "https://fonts.googleapis.com/other",
    ]
    assert third_party_hosts(urls, "site.ru") == ["fonts.googleapis.com"]
    assert known_service("https://fonts.googleapis.com/css2?family=Inter").country == "US"


def test_infra_level():
    def dep(category, service, country):
        return Dependency(category, service, country, "", Severity.HIGH)

    bad = infra_check([dep(Category.DNS, "Cloudflare", "US"), dep(Category.MAIL, "Gmail", "US")])
    assert bad.status is Status.FAIL and bad.id == "SUV-CUT-001"
    assert "целиком" in bad.details and "почта" in bad.details
    mail_only = infra_check([dep(Category.MAIL, "Gmail", "US")])
    assert mail_only.status is Status.WARN
    assert infra_check([dep(Category.DNS, "Selectel", "RU")]).status is Status.OK


def test_cutoff_runs_on_request_or_in_deep_profile():
    assert "cutoff" not in make_plan().modules
    assert "cutoff" in make_plan(cutoff=True).modules
    assert "cutoff" in make_plan(Profile.deep).modules
    assert make_plan(checks="cutoff").modules == frozenset({"cutoff"})


def test_captcha_counts_only_when_its_own_provider_is_blocked():
    own = dom(forms=[{"fields": 3, "captcha": ""}])  # the site's own or Yandex captcha
    assert run(own, own, own, {"fonts.googleapis.com", "www.google.com"}).captcha_forms == 0
    google = dom(forms=[{"fields": 3, "captcha": "recaptcha"}])
    # Fonts from Google say nothing about reCAPTCHA.
    assert run(google, google, google, {"fonts.googleapis.com"}).captcha_forms == 0
    assert run(google, google, google, {"www.gstatic.com"}).captcha_forms == 1


def test_print_stylesheets_are_not_render_blocking():
    html = (
        '<head><link rel="stylesheet" href="https://fonts.googleapis.com/a.css" media="print" '
        'onload="this.media=\'all\'"><link rel="stylesheet" media="all" '
        'href="https://fonts.googleapis.com/b.css"></head>'
    )
    assert render_blocking(html, "https://site.ru/", {"fonts.googleapis.com"}) == [
        "fonts.googleapis.com"
    ]
    only_print = html.split('<link rel="stylesheet" media="all"')[0] + "</head>"
    assert render_blocking(only_print, "https://site.ru/", {"fonts.googleapis.com"}) == []


def test_a_domain_the_site_redirected_to_is_its_own():
    urls = ["https://example.ru/a.js", "https://cdn.example.ru/b.js", "https://x.io/c.js"]
    assert third_party_hosts(urls, "example.com", ("www.example.ru",)) == ["x.io"]


def test_foreign_tag_does_not_start_the_browser_experiment():
    assert "cutoff" not in make_plan(checks="foreign").modules
