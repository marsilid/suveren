import asyncio

import pytest

from suveren.checks import Status
from suveren.dnsutil import DnsLookupError
from suveren.mailsec import (
    Dmarc,
    MailFacts,
    SpfResult,
    check_spf,
    collect_mail,
    evaluate,
    parse_dmarc,
    parse_mta_sts_mode,
    parse_spf,
    run_mail_checks,
    spf_check,
    verdict,
)


class FakeResolver:
    kind = "fake"

    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self.records = records

    async def resolve(self, name: str, rtype: str) -> list[str]:
        value = self.records.get((name, rtype), [])
        if value == ["SERVFAIL"]:
            raise DnsLookupError("SERVFAIL")
        return value


def facts(**kwargs) -> MailFacts:
    defaults = {
        "domain": "example.ru",
        "receives_mail": True,
        "spf": SpfResult(parse_spf("v=spf1 include:_spf.yandex.net ~all"), 1, 1, "~"),
        "dmarc": parse_dmarc("v=DMARC1; p=reject; rua=mailto:d@example.ru"),
        "dmarc_count": 1,
        "dkim": ["mail"],
    }
    defaults.update(kwargs)
    return MailFacts(**defaults)


# --- parsing --------------------------------------------------------------------------


def test_parse_spf_counts_lookups_and_reads_all():
    spf = parse_spf("v=spf1 ip4:1.2.3.4 include:a.ru include:b.ru mx a:x.ru -all")
    assert spf.all == "-"
    assert spf.includes == ["a.ru", "b.ru"]
    assert spf.lookups == 4  # two includes, mx, a


def test_parse_spf_redirect_and_default_qualifier():
    spf = parse_spf("v=spf1 redirect=_spf.yandex.ru")
    assert spf.redirect == "_spf.yandex.ru"
    assert spf.all is None
    assert spf.lookups == 1
    assert parse_spf("v=spf1 all").all == "+"


def test_parse_dmarc_tags():
    d = parse_dmarc("v=DMARC1; p=Quarantine; sp=none; pct=50; rua=mailto:x@example.ru")
    assert (d.policy, d.subdomain_policy, d.pct, d.rua) == (
        "quarantine",
        "none",
        50,
        "mailto:x@example.ru",
    )
    assert parse_dmarc("v=DMARC1; p=bogus").policy is None
    assert parse_dmarc("v=DMARC1; p=reject; pct=abc").pct == 100


def test_parse_mta_sts_mode():
    policy = "version: STSv1\nmode: enforce\nmx: mx.example.ru\nmax_age: 86400\n"
    assert parse_mta_sts_mode(policy) == "enforce"
    assert parse_mta_sts_mode("version: STSv1\n") is None


# --- SPF over DNS ---------------------------------------------------------------------


def test_spf_lookups_follow_includes_past_the_limit():
    records = {("example.ru", "TXT"): ["v=spf1 include:a.ru include:b.ru ~all"]}
    records[("a.ru", "TXT")] = [
        "v=spf1 " + " ".join(f"include:a{i}.ru" for i in range(5)) + " ~all"
    ]
    records[("b.ru", "TXT")] = ["v=spf1 " + " ".join(f"a:h{i}.b.ru" for i in range(5)) + " ~all"]
    for i in range(5):
        records[(f"a{i}.ru", "TXT")] = ["v=spf1 ip4:10.0.0.1 ~all"]
    result = asyncio.run(check_spf(FakeResolver(records), "example.ru"))
    assert result.lookups == 12  # 2 + 5 + 5
    check = spf_check(facts(spf=result))
    assert check.status is Status.FAIL
    assert "12 DNS-запросов" in check.details


def test_spf_redirect_supplies_the_all_qualifier():
    records = {
        ("example.ru", "TXT"): ["v=spf1 redirect=_spf.example.ru"],
        ("_spf.example.ru", "TXT"): ["v=spf1 ip4:10.0.0.1 -all"],
    }
    result = asyncio.run(check_spf(FakeResolver(records), "example.ru"))
    assert result.effective_all == "-"
    assert spf_check(facts(spf=result)).status is Status.OK


def test_spf_include_loops_and_macros_do_not_hang():
    records = {
        ("example.ru", "TXT"): ["v=spf1 include:a.ru exists:%{i}.spf.example.ru ~all"],
        ("a.ru", "TXT"): ["v=spf1 include:example.ru include:a.ru ~all"],
    }
    result = asyncio.run(check_spf(FakeResolver(records), "example.ru"))
    assert result.lookups == 4


def test_spf_problems():
    two = asyncio.run(
        check_spf(
            FakeResolver({("example.ru", "TXT"): ["v=spf1 -all", "v=spf1 ~all"]}), "example.ru"
        )
    )
    assert spf_check(facts(spf=two)).status is Status.FAIL
    plus = SpfResult(parse_spf("v=spf1 +all"), 1, 0, "+")
    assert spf_check(facts(spf=plus)).status is Status.FAIL
    neutral = SpfResult(parse_spf("v=spf1 ip4:10.0.0.1 ?all"), 1, 0, "?")
    assert spf_check(facts(spf=neutral)).status is Status.WARN
    missing = SpfResult(None, 0)
    assert spf_check(facts(spf=missing)).status is Status.WARN
    assert spf_check(facts(spf=missing, receives_mail=False)).status is Status.FAIL


# --- verdict --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("record", "count", "status", "starts"),
    [
        ("v=DMARC1; p=reject", 1, Status.OK, "Нет."),
        ("v=DMARC1; p=reject; sp=none", 1, Status.WARN, "Частично."),
        ("v=DMARC1; p=quarantine", 1, Status.WARN, "Частично."),
        ("v=DMARC1; p=reject; pct=20", 1, Status.WARN, "Частично."),
        ("v=DMARC1; p=none", 1, Status.FAIL, "Да:"),
        ("v=DMARC1", 1, Status.FAIL, "Да:"),
        (None, 0, Status.FAIL, "Да:"),
        ("v=DMARC1; p=reject", 2, Status.FAIL, "Да:"),
    ],
)
def test_verdict(record, count, status, starts):
    dmarc: Dmarc | None = parse_dmarc(record) if record else None
    check = verdict(facts(dmarc=dmarc, dmarc_count=count))
    assert check.status is status
    assert check.details.startswith(starts)


def test_domain_without_mail_still_needs_protection():
    check = verdict(facts(receives_mail=False, dmarc=None, dmarc_count=0))
    assert check.status is Status.FAIL
    assert "не принимает почту" in check.details
    assert '"v=spf1 -all"' in check.recommendation
    # DKIM and MTA-STS make no sense without incoming mail.
    titles = [c.title for c in evaluate(facts(receives_mail=False))]
    assert not any("DKIM" in t or "MTA-STS" in t for t in titles)


# --- collection -----------------------------------------------------------------------


def test_collect_mail_reads_every_record():
    records = {
        ("example.ru", "MX"): ["10 mx.yandex.net."],
        ("example.ru", "TXT"): ["v=spf1 include:_spf.yandex.net ~all", "yandex-verification: 1"],
        ("_spf.yandex.net", "TXT"): ["v=spf1 ip4:10.0.0.1 ~all"],
        ("_dmarc.example.ru", "TXT"): ["v=DMARC1; p=quarantine"],
        ("mail._domainkey.example.ru", "TXT"): ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB"],
        ("s1._domainkey.example.ru", "TXT"): ["v=DKIM1; p="],  # revoked key
        ("_smtp._tls.example.ru", "TXT"): ["v=TLSRPTv1; rua=mailto:tls@example.ru"],
    }
    m = asyncio.run(collect_mail(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
    assert m.receives_mail
    assert m.spf.lookups == 1
    assert m.dmarc is not None and m.dmarc.policy == "quarantine"
    assert m.dkim == ["mail"]
    assert m.mta_sts is None
    assert m.tls_rpt


def test_null_mx_means_no_incoming_mail():
    records = {("example.ru", "MX"): ["0 ."]}
    m = asyncio.run(collect_mail(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
    assert not m.receives_mail


def test_dns_failure_is_not_checked_rather_than_broken():
    records = {("example.ru", "MX"): ["SERVFAIL"]}
    checks = asyncio.run(run_mail_checks(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
    assert [c.status for c in checks] == [Status.UNKNOWN]


def test_verdict_explains_that_spf_alone_does_not_stop_forgery():
    check = verdict(facts(dmarc=None, dmarc_count=0))
    assert "от подделки защищает DMARC" in check.details
    no_spf = verdict(facts(dmarc=None, dmarc_count=0, spf=SpfResult(None, 0)))
    assert "от подделки защищает DMARC" not in no_spf.details


def test_same_advice_is_listed_once():
    from suveren.advice import priorities
    from suveren.models import Report

    report = Report(target="example.ru")
    report.checks = evaluate(facts(dmarc=None, dmarc_count=0))
    actions = [a.action for a in priorities(report)]
    assert len(actions) == len(set(actions))
    assert any("_dmarc.example.ru" in a for a in actions)


def test_spf_includes_name_real_services():
    from suveren.mailsec import SPF_INCLUDES
    from suveren.services import ALL_SERVICES

    names = {s.name for s in ALL_SERVICES}
    assert set(SPF_INCLUDES) <= names


@pytest.mark.parametrize(
    ("mx", "expected"),
    [
        (["aspmx.l.google.com", "alt1.aspmx.l.google.com"], "include:_spf.google.com"),
        (["mx.yandex.net"], "include:_spf.yandex.net"),
        (["example-ru.mail.protection.outlook.com"], "include:spf.protection.outlook.com"),
        (["mx.zoho.eu"], "include:zoho.eu"),
        (["emx.mail.ru"], "include:_spf.mail.ru"),
    ],
)
def test_spf_example_follows_the_mail_provider(mx, expected):
    check = spf_check(facts(spf=SpfResult(None, 0), mx_hosts=mx))
    assert expected in check.recommendation
    if "yandex" not in expected:
        assert "yandex" not in check.recommendation


def test_spf_example_for_unknown_provider_is_generic():
    check = spf_check(facts(spf=SpfResult(None, 0), mx_hosts=["mail.example.ru"]))
    assert '"v=spf1 mx ~all"' in check.recommendation
    assert "include:_spf" not in check.recommendation


def test_collect_mail_keeps_mx_hosts_by_priority():
    records = {("example.ru", "MX"): ["20 alt1.aspmx.l.google.com.", "10 aspmx.l.google.com."]}
    m = asyncio.run(collect_mail(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
    assert m.mx_hosts == ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]


def test_a_domain_without_mail_gets_reject_at_once():
    from suveren.mailsec import dmarc_check

    missing = SpfResult(None, 0, 0, None)
    spf = spf_check(facts(spf=missing, receives_mail=False))
    assert "в спам" not in spf.details and "любой сервер" in spf.details
    dmarc = dmarc_check(facts(receives_mail=False, dmarc=None, dmarc_count=0))
    assert "p=reject" in dmarc.recommendation and "p=none" not in dmarc.recommendation
    sending = dmarc_check(facts(dmarc=None, dmarc_count=0))
    assert "p=none" in sending.recommendation  # a domain with mail starts by watching


def test_dmarc_report_address_without_size_limit():
    from suveren.mailsec import dmarc_check

    record = "v=DMARC1; p=quarantine; rua=mailto:a@example.ru!10m,mailto:b@example.ru"
    check = dmarc_check(facts(dmarc=parse_dmarc(record)))
    assert (
        "mailto:a@example.ru, mailto:b@example.ru." in check.details and "!10m" not in check.details
    )


def test_mta_sts_warning_has_advice_and_comes_last():
    from suveren.advice import priorities
    from suveren.mailsec import transport_check
    from suveren.models import Report, Severity

    check = transport_check(facts(mta_sts=None))
    assert check.status is Status.WARN and "_mta-sts.example.ru" in check.recommendation
    report = Report(target="example.ru")
    report.checks = [check]
    # "Редкая атака, исправлять во вторую очередь": low urgency, its own topic.
    assert priorities(report)[0].severity is Severity.LOW


def test_spf_include_with_a_mailbox_gets_exact_advice():
    record = "v=spf1 include:_spf.yandex.net include:academyautoru@tbank.ru -all"
    spf = SpfResult(
        parse_spf(record), 1, 2, "-", problems=["academyautoru@tbank.ru: нет SPF-записи"]
    )
    check = spf_check(facts(spf=spf))
    # auto.ru once: a warning with nothing to do.
    assert check.status is Status.WARN
    assert "include:tbank.ru" in check.recommendation and "адрес почты" in check.recommendation
    other = SpfResult(parse_spf(record), 1, 2, "-", problems=["spf.old.ru: нет SPF-записи"])
    assert "своя SPF-запись" in spf_check(facts(spf=other)).recommendation


def test_mx_matches_follows_rfc8461_wildcards():
    from suveren.mailsec import mx_matches, parse_mta_sts_mx

    assert mx_matches("mx.yandex.net.", "mx.yandex.net")
    assert mx_matches("mx1.example.ru", "*.example.ru")
    assert not mx_matches("a.mx1.example.ru", "*.example.ru")  # one label only
    assert not mx_matches("example.ru", "*.example.ru")
    policy = "version: STSv1\r\nmode: enforce\r\nmx: mx.yandex.net\r\nmx: *.Example.ru\r\n"
    assert parse_mta_sts_mx(policy) == ["mx.yandex.net", "*.example.ru"]


def test_mta_sts_enforce_with_unlisted_mx_fails():
    from suveren.mailsec import transport_check

    check = transport_check(
        facts(mta_sts="enforce", mx_hosts=["mx.yandex.net"], mta_sts_mx=["mx.example.ru"])
    )
    assert check.status is Status.FAIL
    assert "mx.yandex.net" in check.details
    ok = transport_check(
        facts(mta_sts="enforce", mx_hosts=["mx.yandex.net"], mta_sts_mx=["mx.yandex.net"])
    )
    assert ok.status is Status.OK
