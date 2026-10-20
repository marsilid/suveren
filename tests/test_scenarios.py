from suveren.catalog import BY_ID
from suveren.checks import Check, Status
from suveren.models import Category, Dependency, Severity
from suveren.scenarios import build


def check(check_id, status):
    spec = BY_ID[check_id]
    title = "Можно ли подделать письмо от имени @a.ru" if spec.pattern else spec.title
    return Check(spec.group, title, status)


def dep(category, service="X", country="US"):
    return Dependency(category, service, country, "", Severity.MEDIUM)


def titles(found):
    return {c.title: c.status for c in found}


def test_phishing_needs_spoofable_mail_and_somewhere_to_send_people():
    mail = check("SUV-MAIL-001", Status.FAIL)
    forms = check("SUV-PD-003", Status.OK)
    found = build([mail, forms], [], "a.ru")
    assert titles(found) == {"Фишинг от имени компании": Status.FAIL}
    assert found[0].id == "SUV-ATK-001"
    assert "@a.ru" in found[0].details and "SUV-MAIL-001" in found[0].details
    assert "DMARC" in found[0].recommendation
    # No forms and no payments: nothing to phish for.
    no_forms = check("SUV-PD-003", Status.UNKNOWN)
    assert build([mail, no_forms], [], "a.ru") == []
    # Partly spoofable: a warning; payments are enough instead of forms.
    partly = build([check("SUV-MAIL-001", Status.WARN)], [dep(Category.PAYMENTS)], "a.ru")
    assert titles(partly) == {"Фишинг от имени компании": Status.WARN}
    assert "оплаты" in partly[0].details


def test_third_party_code_from_an_abandoned_domain_or_unprotected_cdn():
    abandoned = build([check("SUV-WEB-002", Status.FAIL)], [], "a.ru")
    assert titles(abandoned) == {"Чужой код у всех посетителей": Status.FAIL}
    cdn = [
        check("SUV-WEB-003", Status.WARN),
        check("SUV-WEB-004", Status.WARN),
        check("SUV-PD-003", Status.WARN),
    ]
    found = build(cdn, [], "a.ru")
    assert titles(found) == {"Чужой код у всех посетителей": Status.WARN}
    assert "polyfill.io" in found[0].details and "SUV-WEB-004" in found[0].details
    # With a CSP the CDN chain is not complete.
    assert build([cdn[0], check("SUV-WEB-004", Status.OK), cdn[2]], [], "a.ru") == []


def test_takeover_first_visit_and_leaked_key():
    found = build(
        [
            check("SUV-SUB-002", Status.FAIL),
            check("SUV-WEB-007", Status.WARN),
            check("SUV-WEB-005", Status.WARN),
            check("SUV-PD-003", Status.FAIL),
            check("SUV-WEB-009", Status.FAIL),
        ],
        [],
        "a.ru",
    )
    assert titles(found) == {
        "Захват поддомена": Status.FAIL,
        "Перехват при первом заходе": Status.WARN,
        "Утёкший ключ": Status.FAIL,
    }
    takeover = next(c for c in found if c.title == "Захват поддомена")
    assert "SUV-WEB-007" in takeover.details
    # A public Google key (a warning) is not a leaked secret.
    assert build([check("SUV-WEB-009", Status.WARN)], [], "a.ru") == []


def test_cutoff_scenario_from_dependencies():
    deps = [dep(Category.DNS, "Cloudflare"), dep(Category.MAIL, "Google Workspace")]
    found = build([], deps, "a.ru")
    assert titles(found) == {"Отключение сайта и почты": Status.FAIL}
    assert "Cloudflare" in found[0].details and "Google Workspace" in found[0].details
    only_dns = build([], deps[:1], "a.ru")
    assert titles(only_dns) == {"Отключение сайта и почты": Status.WARN}
    assert build([], [dep(Category.DNS, "Selectel", "RU")], "a.ru") == []


def test_nothing_found_means_no_scenarios():
    ok = [check(i, Status.OK) for i in ("SUV-MAIL-001", "SUV-WEB-002", "SUV-SUB-002")]
    assert build(ok, [], "a.ru") == []


def test_cutoff_scenario_names_only_what_is_foreign():
    cdn_only = build(
        [], [dep(Category.CDN, "Cloudflare"), dep(Category.DNS, "Selectel", "RU")], "a.ru"
    )
    assert "почтой" not in cdn_only[0].details and "DNS" not in cdn_only[0].recommendation
    assert "cdn" in cdn_only[0].recommendation.lower()
    builder = build([], [dep(Category.BUILDER, "Wix")], "a.ru")
    assert titles(builder) == {"Отключение сайта и почты": Status.WARN}


def test_choosing_a_scenario_runs_the_modules_it_needs():
    from suveren.catalog import modules_for, select

    assert modules_for(select("SUV-ATK-001")) == {"mail", "compliance"}
    assert "cutoff" not in modules_for(select("scenario"))
