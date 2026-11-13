"""The second part of the review for confident untrue conclusions (2026-11-14): the
modules the first part did not read. Each test is the DNS, the page or the network that
fooled a check."""

import asyncio

import httpx
import pytest

from suveren.checks import Check, Status
from suveren.cutoff import HostInfo, PageCutoff, infra_check, page_check
from suveren.metanote import meta_note_check
from suveren.models import Category, Dependency, Severity
from suveren.ownsite import exposed_files_check
from suveren.psl import registrable
from suveren.ruregistries import RuScreening, list_check, searched
from suveren.scenarios import build
from suveren.subdomains import Subdomain, find_candidate, find_dangling_ns
from suveren.websec import WebFacts, hsts_check


def run(coro):
    return asyncio.run(coro)


# --- SUV-SUB-002: a name inside someone's service is not a domain for sale ---------------


class Dns:
    def __init__(self, missing=(), records=None):
        self.missing = set(missing)
        self.records = records or {}

    async def resolve(self, name, rtype):
        return list(self.records.get((name, rtype), []))

    async def exists(self, domain):
        return domain not in self.missing


def registry(free=()):
    """RDAP as the registries answer: 404 for a free domain and for any name that is
    not a second-level domain at all (they keep no record of my-lb.elb.amazonaws.com)."""

    def handler(request):
        name = request.url.path.rsplit("/", 1)[-1]
        known = name.count(".") == 1 and name not in free
        return httpx.Response(200 if known else 404, json={})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def candidate(target, missing, free=()):
    async def go():
        async with registry(free) as client:
            sub = Subdomain("old.site.ru", cnames=[target])
            return await find_candidate(Dns(missing), client, sub, "site.ru")

    return run(go())


def test_registrable_domain_at_the_registry_level():
    assert registrable("foo.azurewebsites.net") == "foo.azurewebsites.net"
    assert registrable("foo.azurewebsites.net", private=False) == "azurewebsites.net"
    assert registrable("a.b.example.co.uk", private=False) == "example.co.uk"
    assert registrable("my-lb-1.eu-west-1.elb.amazonaws.com", private=False) == "amazonaws.com"


def test_a_deleted_load_balancer_is_not_a_domain_anyone_can_buy():
    # The name is gone from DNS and the registry answers 404 for it, as for any name it
    # does not sell; a load balancer's name has random digits and cannot be claimed.
    target = "my-lb-1234567890.eu-west-1.elb.amazonaws.com"
    assert candidate(target, missing={target}) is None


def test_a_deleted_app_is_a_possible_takeover_not_a_free_domain():
    target = "oldshop.azurewebsites.net"
    found = candidate(target, missing={target})
    assert found is not None and not found.certain
    assert "не зарегистрирован" not in found.reason and "Azure" in found.reason


def test_an_expired_domain_is_still_a_certain_takeover():
    found = candidate("shop.expired-shop.com", {"expired-shop.com"}, free={"expired-shop.com"})
    assert found is not None and found.certain
    assert "expired-shop.com не зарегистрирован" in found.reason


def test_name_servers_inside_a_service_are_not_a_free_domain():
    async def go():
        dns = Dns(
            missing={"ns1.oldzone.azurewebsites.net"},
            records={("site.ru", "NS"): ["ns1.oldzone.azurewebsites.net."]},
        )
        async with registry() as client:
            return await find_dangling_ns(dns, client, ["site.ru"], "site.ru")

    assert run(go()) == []


# --- SUV-OWN-001: the files are looked for where the site really is -----------------------


def own_files(handler):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await exposed_files_check(client, "a.ru")

    return run(go())


def test_service_files_are_found_behind_the_redirect_to_www():
    def handler(request):
        if request.url.host == "a.ru":
            return httpx.Response(301, headers={"location": f"https://www.a.ru{request.url.path}"})
        if request.url.path == "/.env":
            return httpx.Response(200, text="DB_PASSWORD=s3cret\n")
        return httpx.Response(404)

    check = own_files(handler)
    assert check.status is Status.FAIL
    assert check.evidence[0].value == "https://www.a.ru/.env"


def test_a_redirect_to_another_site_is_not_followed():
    asked = []

    def handler(request):
        asked.append(request.url.host)
        if request.url.host == "a.ru":
            return httpx.Response(302, headers={"location": "https://parking.example/.env"})
        return httpx.Response(200, text="DB_PASSWORD=s3cret\n")

    assert own_files(handler).status is Status.OK
    assert set(asked) == {"a.ru"}


def test_a_redirect_loop_ends():
    def handler(request):
        return httpx.Response(301, headers={"location": str(request.url)})

    assert own_files(handler).status is Status.OK


# --- scenarios say what the check they rest on says ---------------------------------------


def scenario_check(check_id, status, details=""):
    from suveren.catalog import BY_ID

    spec = BY_ID[check_id]
    title = "Можно ли подделать письмо от имени @a.ru" if spec.pattern else spec.title
    return Check(spec.group, title, status, details)


def test_phishing_scenario_does_not_overstate_a_partial_dmarc():
    forms = scenario_check("SUV-PD-003", Status.OK)
    partial = build([scenario_check("SUV-MAIL-001", Status.WARN), forms], [], "a.ru")
    assert partial[0].status is Status.WARN
    assert "не отклоняется" not in partial[0].details
    assert "Часть поддельных писем" in partial[0].details
    full = build([scenario_check("SUV-MAIL-001", Status.FAIL), forms], [], "a.ru")
    assert "не отклоняется" in full[0].details


def test_first_visit_scenario_says_no_hsts_only_when_there_is_none():
    forms = scenario_check("SUV-PD-003", Status.OK)

    def web(headers):
        return WebFacts("a.ru", True, headers, [], [], [], None)

    none = hsts_check(web({}))
    short = hsts_check(web({"strict-transport-security": "max-age=3600"}))
    assert none.status is Status.WARN and short.status is Status.WARN
    assert "Нет HSTS" in build([none, forms], [], "a.ru")[0].details
    weak = build([short, forms], [], "a.ru")[0].details
    assert "Нет HSTS" not in weak and "SUV-WEB-005" in weak


# --- SUV-LAW-004: a commented-out link is not a link ---------------------------------------


def test_a_commented_out_instagram_link_is_no_link():
    page = '<p>Мы ВКонтакте</p><!-- <a href="https://instagram.com/shop">Instagram</a> -->'
    assert meta_note_check([("главная", page)]) is None


def test_a_commented_out_note_is_no_note():
    page = (
        '<a href="https://instagram.com/shop">Instagram</a>'
        "<!-- <small>Meta признана экстремистской организацией</small> -->"
    )
    assert meta_note_check([("главная", page)]).status is Status.WARN


# --- SUV-CUT: what could not be determined is not Russian ----------------------------------


def test_hosts_of_unknown_country_are_not_called_no_foreign_services():
    hosts = {"cdn.some.io": HostInfo("cdn.some.io", None, None)}
    check = page_check(PageCutoff(unknown=["cdn.some.io"]), hosts)
    assert check.status is Status.UNKNOWN
    assert "cdn.some.io" in check.details
    assert page_check(PageCutoff(), {}).status is Status.OK


def dep(category, service, country):
    return Dependency(category, service, country, "", Severity.HIGH)


@pytest.mark.parametrize(
    "deps",
    [
        [],  # nothing was found out about the site's DNS and hosting
        [dep(Category.DNS, "Selectel", "RU"), dep(Category.HOSTING, "AS64500", "")],
        [dep(Category.DNS, "ns.example", None)],
    ],
)
def test_unknown_providers_are_not_called_russian(deps):
    check = infra_check(deps)
    assert check.status is Status.UNKNOWN
    assert "у российских провайдеров" not in check.details


def test_known_russian_providers_are_ok():
    check = infra_check([dep(Category.DNS, "Selectel", "RU"), dep(Category.HOSTING, "Beget", "RU")])
    assert check.status is Status.OK


# --- SUV-CO-008: the answer names what was looked for ---------------------------------------


def test_the_clean_answer_names_only_what_was_searched():
    only_inn = searched({"ИНН": "7707083893", "ОГРН": ""}, None)
    check = list_check(RuScreening([], "s", searched=only_inn), asked=True)
    assert check.status is Status.OK
    assert "ИНН" in check.details and "ОГРН" not in check.details
    assert "по ФИО не искали" in check.details
    everything = searched({"ИНН": "1", "ОГРН": "2"}, "Иванов Иван Иванович")
    full = list_check(RuScreening([], "s", searched=everything), asked=True).details
    assert "ИНН" in full and "ОГРН" in full and "руководителя" in full
    assert "не искали" not in full
    # A surname and a first name are not searched: too many namesakes.
    short = searched({}, "Иванов Иван")
    assert list_check(RuScreening([], "s", searched=short), asked=True).status is Status.UNKNOWN
