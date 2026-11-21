import asyncio
import base64
import sys
from pathlib import Path

import httpx
import pytest

from suveren.checks import Status
from suveren.dnsutil import DnsLookupError
from suveren.mailsec import (
    Dmarc,
    MailFacts,
    SpfResult,
    check_spf,
    collect_mail,
    dkim_check,
    dkim_strength_check,
    dmarc_check,
    evaluate,
    parse_dmarc,
    parse_mta_sts_mode,
    parse_spf,
    rsa_bits,
    run_mail_checks,
    spf_check,
    transport_check,
    verdict,
)

sys.path.insert(0, str(Path(__file__).parent))
from lab import dkim_key


class FakeResolver:
    kind = "fake"

    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self.records = records

    async def resolve(self, name: str, rtype: str) -> list[str]:
        value = self.records.get((name, rtype), [])
        if value == ["SERVFAIL"]:
            raise DnsLookupError("SERVFAIL")
        return value

    async def node_exists(self, name: str) -> bool | None:
        names = {n for n, _ in self.records}
        if "*." + name.partition(".")[2] in names:
            return True
        return any(n == name or n.endswith("." + name) for n in names)


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


@pytest.mark.parametrize(
    ("record", "policy", "invalid"),
    [
        # RFC 7489, 6.6.3: no valid p= but a valid rua= reads as p=none ...
        ("v=DMARC1; rua=mailto:d@example.ru", "none", "нет политики p="),
        ("v=DMARC1; p=bogus; rua=mailto:d@example.ru!10m", "none", "неверная политика p=bogus"),
        ("v=DMARC1; p=reject; sp=bad; rua=https://r.example.ru/dmarc", "none", "sp=bad"),
        # ... and without one the record is not applied at all.
        ("v=DMARC1; rua=d@example.ru", None, "нет политики p="),
        ("v=DMARC1; p=reject; sp=bad", None, "sp=bad"),
        ("v=DMARC1; p=reject; sp=none", "reject", None),
    ],
)
def test_parse_dmarc_without_valid_policy(record, policy, invalid):
    d = parse_dmarc(record)
    assert d.policy == policy
    assert (d.invalid is None) if invalid is None else (invalid in (d.invalid or ""))
    if d.invalid:
        assert d.subdomain_policy is None


def test_dmarc_with_rua_but_no_policy_is_monitoring_not_broken():
    from suveren.mailsec import dmarc_check

    check = dmarc_check(facts(dmarc=parse_dmarc("v=DMARC1; rua=mailto:d@example.ru")))
    assert check.status is Status.WARN
    assert "p=none" in check.details and "6.6.3" in check.details
    broken = dmarc_check(facts(dmarc=parse_dmarc("v=DMARC1; p=reject; sp=bad")))
    assert broken.status is Status.FAIL and "sp=" in broken.recommendation
    spoof = verdict(facts(dmarc=parse_dmarc("v=DMARC1; rua=mailto:d@example.ru")))
    assert spoof.status is Status.FAIL and "режим наблюдения" in spoof.details


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
    silent = facts(receives_mail=False, dmarc=None, dmarc_count=0, spf=SpfResult(None, 0))
    check = verdict(silent)
    assert check.status is Status.FAIL
    assert "не принимает почту" in check.details
    assert '"v=spf1 -all"' in check.recommendation
    assert "p=reject" in dmarc_check(silent).recommendation
    # DKIM and MTA-STS make no sense without incoming mail.
    titles = [c.title for c in evaluate(facts(receives_mail=False))]
    assert not any("DKIM" in t or "MTA-STS" in t for t in titles)


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 include:_spf.yandex.net ~all",
        "v=spf1 ip4:203.0.113.5 -all",
        "v=spf1 a mx ?all",
        "v=spf1 redirect=_spf.example.net",
    ],
)
def test_domain_without_mx_that_sends_mail_is_not_told_to_forbid_it(record):
    # No MX, but the SPF names senders (a shop's order letters, a mailing service):
    # "v=spf1 -all" would stop that mail.
    sender = facts(
        receives_mail=False, dmarc=None, dmarc_count=0, spf=SpfResult(parse_spf(record), 1)
    )
    check = verdict(sender)
    assert check.status is Status.FAIL
    assert "судя по SPF, отправляет" in check.details
    assert "-all" not in check.recommendation and "p=none" in check.recommendation
    assert "p=none" in dmarc_check(sender).recommendation


def test_spf_that_only_forbids_does_not_make_a_sender():
    closed = facts(
        receives_mail=False, dmarc=None, dmarc_count=0, spf=SpfResult(parse_spf("v=spf1 -all"), 1)
    )
    assert '"v=spf1 -all"' in verdict(closed).recommendation


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


def test_an_mta_sts_timeout_leaves_the_other_mail_checks():
    # kamaz.ru, 2026-10-25: one _mta-sts timeout made all of MAIL-001…005 "не проверено".
    records = {
        ("example.ru", "MX"): ["10 mx.yandex.net."],
        ("example.ru", "TXT"): ["v=spf1 include:_spf.yandex.net -all"],
        ("_spf.yandex.net", "TXT"): ["v=spf1 ip4:10.0.0.1 ~all"],
        ("_dmarc.example.ru", "TXT"): ["v=DMARC1; p=reject"],
        ("mail._domainkey.example.ru", "TXT"): ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB"],
        ("_mta-sts.example.ru", "TXT"): ["SERVFAIL"],
        ("_smtp._tls.example.ru", "TXT"): ["SERVFAIL"],
    }
    resolver = FakeResolver(records)
    checks = asyncio.run(run_mail_checks(resolver, None, "example.ru"))  # type: ignore[arg-type]
    by_id = {c.id: c for c in checks}
    assert by_id["SUV-MAIL-005"].status is Status.UNKNOWN
    assert "MTA-STS прочитать не удалось: SERVFAIL" in by_id["SUV-MAIL-005"].details
    assert all(by_id[f"SUV-MAIL-00{n}"].status is Status.OK for n in range(1, 5))


def test_dkim_node_with_unknown_selector_is_probably_configured():
    records = {
        ("example.ru", "MX"): ["10 mx.example.ru."],
        ("s2026._domainkey.example.ru", "TXT"): ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB"],
    }
    m = asyncio.run(collect_mail(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
    assert m.dkim == [] and m.dkim_node
    check = dkim_check(m)
    assert check.status is Status.OK
    assert "вероятно, настроен, селектор неизвестен" in check.details


def test_dkim_node_ignored_when_every_name_answers():
    # A wildcard (or a resolver that answers NOERROR to everything) makes _domainkey
    # exist too, so the sign proves nothing.
    records = {
        ("example.ru", "MX"): ["10 mx.example.ru."],
        ("*.example.ru", "TXT"): ["v=spf1 -all"],
    }
    m = asyncio.run(collect_mail(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
    assert not m.dkim_node
    assert dkim_check(m).status is Status.UNKNOWN


def test_dkim_without_node_stays_unknown():
    records = {("example.ru", "MX"): ["10 mx.example.ru."]}
    m = asyncio.run(collect_mail(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
    assert not m.dkim_node
    assert dkim_check(m).status is Status.UNKNOWN


def test_dmarc_reports_to_outside_domain_need_its_consent():
    # RFC 7489, section 7.1: the outside domain publishes <domain>._report._dmarc.<dest>.
    records = {
        ("example.ru", "MX"): ["10 mx.example.ru."],
        ("_dmarc.example.ru", "TXT"): [
            "v=DMARC1; p=reject; rua=mailto:d@reports.example.com,mailto:d@ok.example.net!10m;"
            " ruf=mailto:f@mail.example.ru"
        ],
        ("example.ru._report._dmarc.ok.example.net", "TXT"): ["v=DMARC1;"],
    }
    m = asyncio.run(collect_mail(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
    assert m.dmarc is not None
    assert m.dmarc.report_domains() == ["reports.example.com", "ok.example.net", "mail.example.ru"]
    assert m.dmarc_unauthorized == ["reports.example.com"]
    check = dmarc_check(m)
    assert check.status is Status.WARN
    assert "example.ru._report._dmarc.reports.example.com" in check.recommendation
    assert "RFC 7489, раздел 7.1" in check.details


def test_dmarc_reports_to_own_domain_need_no_consent():
    records = {
        ("example.ru", "MX"): ["10 mx.example.ru."],
        ("_dmarc.example.ru", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@example.ru"],
    }
    m = asyncio.run(collect_mail(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
    assert m.dmarc_unauthorized == []
    assert dmarc_check(m).status is Status.OK


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
    dmarc = dmarc_check(facts(spf=missing, receives_mail=False, dmarc=None, dmarc_count=0))
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


def test_missing_mta_sts_is_a_note_not_a_warning():
    # Most mail domains have no MTA-STS: a warning on nearly every report taught to skip it.
    for mode in (None, "none"):
        check = transport_check(facts(mta_sts=mode))
        assert check.status is Status.OK and "_mta-sts.example.ru" in check.details
    assert "mode: none" in transport_check(facts(mta_sts="none")).details


def test_mta_sts_testing_warning_has_advice_and_comes_last():
    from suveren.advice import priorities
    from suveren.models import Report, Severity

    check = transport_check(facts(mta_sts="testing"))
    assert check.status is Status.WARN and "mode: enforce" in check.recommendation
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
    # auto.ru once: an include of a mailbox is a permerror (RFC 7208, section 5.2).
    assert check.status is Status.FAIL
    assert "include:tbank.ru" in check.recommendation and "адрес почты" in check.recommendation
    other = SpfResult(parse_spf(record), 1, 2, "-", problems=["spf.old.ru: нет SPF-записи"])
    assert "нет своей SPF-записи" in spf_check(facts(spf=other)).recommendation


def test_spf_redirect_with_a_broken_target():
    # positive.com: the whole record is a redirect to a name with two SPF records.
    spf = parse_spf("v=spf1 redirect=_spf.ptsecurity.com")
    result = SpfResult(spf, 1, 1, None, problems=["_spf.ptsecurity.com: несколько SPF"])
    check = spf_check(facts(spf=result))
    assert check.status is Status.FAIL
    assert "-all" not in check.details and "~all" not in check.recommendation
    assert "из redirect" in check.recommendation and "объедините" in check.recommendation
    assert "include" not in check.recommendation


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


def test_spf_redirect_is_ignored_next_to_all():
    spf = parse_spf("v=spf1 include:_spf.yandex.net redirect=_spf.example.ru ~all")
    assert spf.redirect is None and spf.lookups == 1
    assert parse_spf("v=spf1 redirect=_spf.example.ru").redirect == "_spf.example.ru"


def test_spf_ptr_is_a_warning():
    result = SpfResult(parse_spf("v=spf1 ptr ~all"), 1, 1, "~")
    check = spf_check(facts(spf=result))
    assert check.status is Status.WARN
    assert "ptr" in check.recommendation


def test_spf_include_dns_timeout_is_only_a_warning():
    spf = SpfResult(
        parse_spf("v=spf1 include:a.ru -all"), 1, 1, "-", problems=["a.ru: DNS не ответил"]
    )
    assert spf_check(facts(spf=spf)).status is Status.WARN


def test_mta_sts_txt_without_id_or_doubled_is_no_policy():
    import suveren.mailsec as mailsec

    for txt in (["v=STSv1;"], ["v=STSv1; id=1", "v=STSv1; id=2"]):
        records = {("_mta-sts.example.ru", "TXT"): txt}
        mode = asyncio.run(mailsec._mta_sts(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
        assert mode[:2] == ("none", []) and "_mta-sts.example.ru" in (mode[2] or "")


def _policy(response=None, error=None):
    import suveren.mailsec as mailsec

    def handler(request):
        if error:
            raise error
        return response

    async def go():
        records = {("_mta-sts.example.ru", "TXT"): ["v=STSv1; id=2026"]}
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await mailsec._mta_sts(FakeResolver(records), client, "example.ru")

    return asyncio.run(go())


GOOD_POLICY = "version: STSv1\nmode: enforce\nmx: mx.example.ru\nmax_age: 86400\n"


@pytest.mark.parametrize(
    ("response", "problem"),
    [
        (httpx.Response(404), "кодом 404"),
        (httpx.Response(301, headers={"location": "https://x.ru/"}), "перенаправление"),
        (httpx.Response(200, text="version: STSv1\nmode: enforce\n"), "max_age"),
        (
            httpx.Response(200, text=GOOD_POLICY, headers={"content-type": "text/html"}),
            "text/plain",
        ),
        (httpx.Response(200, text="version: STSv1\nmode: enforce\nmax_age: 1\n"), "mx:"),
    ],
)
def test_broken_mta_sts_names_the_problem(response, problem):
    mode, _, why = _policy(response)
    assert mode == "none" and problem in (why or "")
    check = transport_check(facts(mta_sts=mode, mta_sts_problem=why))
    assert check.status is Status.WARN and "с ошибкой" in check.details


def test_mta_sts_policy_timeout_is_not_checked_rather_than_missing():
    from suveren.mailsec import PolicyUnreachable

    with pytest.raises(PolicyUnreachable):
        _policy(error=httpx.ReadTimeout("slow"))
    mode, _, why = _policy(error=httpx.ConnectError("refused"))
    assert mode == "none" and "не открывается" in (why or "")
    assert _policy(httpx.Response(200, text=GOOD_POLICY)) == ("enforce", ["mx.example.ru"], None)


def test_mta_sts_policy_timeout_in_collect_is_unknown():
    records = {
        ("example.ru", "MX"): ["10 mx.example.ru."],
        ("_mta-sts.example.ru", "TXT"): ["v=STSv1; id=1"],
    }

    def handler(request):
        raise httpx.ConnectTimeout("slow")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await collect_mail(FakeResolver(records), client, "example.ru")

    m = asyncio.run(go())
    check = transport_check(m)
    assert check.status is Status.UNKNOWN and "не ответил вовремя" in check.details


def test_dmarc_version_must_be_capitals_but_the_tag_name_need_not():
    assert parse_dmarc("v=DMARC1; p=reject").exact_version
    assert parse_dmarc("V=DMARC1; p=reject").exact_version
    assert not parse_dmarc("v=dmarc1; p=reject").exact_version
    assert not parse_dmarc("v=Dmarc1; p=reject").exact_version


def test_spf_warning_behind_dmarc_reject_is_low_and_says_why():
    from suveren.advice import priorities
    from suveren.models import Report, Severity

    spf = SpfResult(parse_spf("v=spf1 include:_spf.yandex.net ?all"), 1, 1, "?")
    for record, severity in (
        ("v=DMARC1; p=reject", Severity.LOW),
        ("v=DMARC1; p=quarantine", Severity.MEDIUM),
    ):
        m = facts(spf=spf, dmarc=parse_dmarc(record))
        report = Report(target="example.ru")
        report.checks = evaluate(m)
        spf_warn = report.checks[1]
        assert spf_warn.id == "SUV-MAIL-002" and spf_warn.status is Status.WARN
        assert ("p=reject отклоняет" in spf_warn.details) is (severity is Severity.LOW)
        mail = [a for a in priorities(report) if a.anchor.startswith("SUV-MAIL-")]
        assert max(a.severity for a in mail) is severity


def test_broken_spf_behind_dmarc_reject_stays_urgent():
    from suveren.advice import priorities
    from suveren.models import Report, Severity

    spf = SpfResult(
        parse_spf("v=spf1 include:a.ru -all"), 2, 1, "-", problems=["a.ru: нет SPF-записи"]
    )
    report = Report(target="example.ru")
    report.checks = evaluate(facts(spf=spf, dmarc=parse_dmarc("v=DMARC1; p=reject")))
    assert report.checks[1].status is Status.FAIL
    assert priorities(report)[0].severity is Severity.HIGH


# --- DKIM key strength (RFC 8301) -----------------------------------------------------


def _dkim(records: dict[str, list[str]]) -> MailFacts:
    raw = {f"TXT {s}._domainkey.example.ru": r for s, r in records.items()}
    return facts(dkim=list(records), raw=raw)


@pytest.mark.parametrize(
    ("bits", "spki", "status"),
    [
        (512, True, Status.FAIL),
        (1023, True, Status.FAIL),
        (1024, True, Status.WARN),
        (1024, False, Status.WARN),
        (2048, True, Status.OK),
        (4096, False, Status.OK),
    ],
)
def test_dkim_key_length_follows_rfc_8301(bits, spki, status):
    key = dkim_key(bits, spki=spki)
    assert rsa_bits(base64.b64decode(key)) == bits
    check = dkim_strength_check(_dkim({"mail": [f"v=DKIM1; k=rsa; p={key}"]}))
    assert check.id == "SUV-MAIL-006"
    assert check.status is status
    assert f"RSA {bits} бит" in check.details


def test_dkim_worst_key_decides_and_every_key_is_listed():
    check = dkim_strength_check(
        _dkim(
            {
                "mail": [f"v=DKIM1; p={dkim_key(512)}"],
                "selector1": [f"v=DKIM1; p={dkim_key(2048)}"],
            }
        )
    )
    assert check.status is Status.FAIL
    assert "mail: RSA 512 бит" in check.details and "selector1: RSA 2048 бит" in check.details
    assert check.details.split(". ")[1].startswith("RSA-ключ короче 1024")
    assert "новым селектором" in check.recommendation


def test_short_dkim_key_is_not_said_to_fall_in_hours_unless_it_does():
    # 2026-11-21: three domains had 768-bit keys and the report said they "fall in hours";
    # that is true of 512 bits, while 768 bits took about 2000 core-years in 2009.
    tiny = dkim_strength_check(_dkim({"mail": [f"v=DKIM1; p={dkim_key(512)}"]}))
    short = dkim_strength_check(_dkim({"mail": [f"v=DKIM1; p={dkim_key(768)}"]}))
    assert tiny.status is short.status is Status.FAIL
    assert "за часы" in tiny.details
    assert "за часы" not in short.details and "в 2009 году" in short.details


def test_dkim_key_for_sha1_only_is_invalid():
    record = f"v=DKIM1; h = sha1 ; k=RSA; p={dkim_key(2048)}"
    check = dkim_strength_check(_dkim({"mail": [record]}))
    assert check.status is Status.FAIL and "h=sha1" in check.details
    both = f"v=DKIM1; h=sha1:sha256; p={dkim_key(2048)}"
    assert dkim_strength_check(_dkim({"mail": [both]})).status is Status.OK


def test_dkim_key_with_folded_base64_is_read():
    key = dkim_key(2048)
    record = f"v=DKIM1; k=rsa; p={key[:100]} {key[100:200]}\t{key[200:]}"
    assert dkim_strength_check(_dkim({"mail": [record]})).status is Status.OK


def test_dkim_ed25519_and_unknown_keys():
    ed = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
    check = dkim_strength_check(_dkim({"mail": [ed]}))
    assert check.status is Status.OK and "Ed25519" in check.details
    short = "v=DKIM1; k=ed25519; p=QUJD"
    assert dkim_strength_check(_dkim({"mail": [short]})).status is Status.UNKNOWN
    other = f"v=DKIM1; k=dsa; p={dkim_key(2048)}"
    assert dkim_strength_check(_dkim({"mail": [other]})).status is Status.UNKNOWN


@pytest.mark.parametrize(
    "p",
    ["QUJD", "!!!notbase64", base64.b64encode(b"\x30\x82\xff").decode(), "MAMCAQE="],
)
def test_dkim_unreadable_key_is_unknown(p):
    check = dkim_strength_check(_dkim({"mail": [f"v=DKIM1; k=rsa; p={p}"]}))
    assert check.status is Status.UNKNOWN and "не читается" in check.details


def test_dkim_one_unreadable_key_does_not_hide_the_others():
    check = dkim_strength_check(
        _dkim({"mail": ["v=DKIM1; p=QUJD"], "s1": [f"v=DKIM1; p={dkim_key(1024)}"]})
    )
    assert check.status is Status.WARN


@pytest.mark.parametrize(
    "der",
    [
        b"",
        b"\x02\x01\x01",  # not a sequence
        b"\x30\x03\x02\x01",  # truncated
        b"\x30\x85\x00\x00\x00\x00\x01\x00",  # absurd length
        b"\x30\x81",  # length cut off
        b"\x30\x06\x30\x00\x03\x02\x00\x00",  # algorithm missing
        b"\x30\x03\x05\x01\x00",  # one item
    ],
)
def test_rsa_bits_rejects_what_is_not_a_key(der):
    assert rsa_bits(der) is None


def test_rsa_bits_rejects_a_key_of_another_algorithm():
    key = base64.b64decode(dkim_key(2048))
    other = key.replace(bytes.fromhex("2a864886f70d010101"), bytes.fromhex("2a8648ce3d0201ff"))
    assert rsa_bits(other) is None


def test_key_strength_runs_only_when_a_key_was_found():
    ids = {c.id for c in evaluate(facts(dkim=[]))}
    assert "SUV-MAIL-006" not in ids


def test_collect_mail_keeps_the_key_records_for_the_strength_check():
    records = {
        ("example.ru", "MX"): ["10 mx.yandex.net."],
        ("mail._domainkey.example.ru", "TXT"): [f"v=DKIM1; k=rsa; p={dkim_key(1024)}"],
    }
    m = asyncio.run(collect_mail(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
    check = next(c for c in evaluate(m) if c.id == "SUV-MAIL-006")
    assert check.status is Status.WARN
    assert [e.what for e in check.evidence] == ["TXT mail._domainkey.example.ru"]


@pytest.mark.parametrize(("bits", "severity"), [(1024, "LOW"), (512, "HIGH")])
def test_dkim_key_advice_is_its_own_and_urgent_only_when_invalid(bits, severity):
    from suveren.advice import priorities
    from suveren.models import Report, Severity

    report = Report(target="example.ru")
    report.checks = evaluate(_dkim({"mail": [f"v=DKIM1; p={dkim_key(bits)}"]}))
    actions = [a for a in priorities(report) if a.anchor == "SUV-MAIL-006"]
    assert [a.severity for a in actions] == [Severity[severity]]


def test_bimi_is_information_only():
    from suveren.mailsec import bimi_check, evaluate

    none = bimi_check(facts(bimi=[]))
    assert none.status is Status.OK and "не проблема" in none.details
    shown = bimi_check(facts(bimi=["v=BIMI1; l=https://example.ru/logo.svg; a=https://x/vmc.pem"]))
    assert shown.status is Status.OK and "логотип: https://example.ru/logo.svg." in shown.details
    assert "Логотип не покажут" not in shown.details and "VMC" not in shown.details
    no_vmc = bimi_check(facts(bimi=["v=BIMI1; l=https://example.ru/logo.svg"]))
    assert "VMC или CMC" in no_vmc.details
    weak = bimi_check(
        facts(
            bimi=["v=BIMI1; l=https://example.ru/logo.svg"], dmarc=parse_dmarc("v=DMARC1; p=none")
        )
    )
    assert weak.status is Status.OK and "Логотип не покажут" in weak.details
    partial = bimi_check(facts(bimi=["v=BIMI1;"], dmarc=parse_dmarc("v=DMARC1; p=reject; pct=50")))
    assert "без логотипа" in partial.details and "Логотип не покажут" in partial.details
    # No DNS answer: the check is left out, not reported as unknown.
    assert "SUV-MAIL-007" not in {c.id for c in evaluate(facts())}
    assert "SUV-MAIL-007" in {c.id for c in evaluate(facts(bimi=[]))}


def test_bimi_record_is_collected_with_its_evidence():
    from suveren.mailsec import evaluate

    records = {
        ("example.ru", "MX"): ["10 mx.example.ru."],
        ("default._bimi.example.ru", "TXT"): ["v=BIMI1; l=https://example.ru/l.svg", "other"],
    }
    m = asyncio.run(collect_mail(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
    assert m.bimi == ["v=BIMI1; l=https://example.ru/l.svg"]
    (check,) = [c for c in evaluate(m) if c.id == "SUV-MAIL-007"]
    assert check.evidence[0].value == "v=BIMI1; l=https://example.ru/l.svg"
    records[("default._bimi.example.ru", "TXT")] = ["SERVFAIL"]
    m = asyncio.run(collect_mail(FakeResolver(records), None, "example.ru"))  # type: ignore[arg-type]
    assert m.bimi is None


def test_spf_include_is_asked_again_once_when_dns_does_not_answer():
    class Flaky(FakeResolver):
        def __init__(self, records, fails):
            super().__init__(records)
            self.fails = fails  # name -> how many lookups time out first
            self.asked: list[str] = []

        async def resolve(self, name, rtype):
            self.asked.append(name)
            if self.fails.get(name, 0) > 0:
                self.fails[name] -= 1
                raise DnsLookupError("timeout")
            return await super().resolve(name, rtype)

    records = {
        ("example.ru", "TXT"): ["v=spf1 include:a.ru -all"],
        ("a.ru", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
    }
    once = Flaky(records, {"a.ru": 1})
    result = asyncio.run(check_spf(once, "example.ru"))
    assert result.problems == [] and once.asked.count("a.ru") == 2
    twice = Flaky(records, {"a.ru": 2})
    result = asyncio.run(check_spf(twice, "example.ru"))
    assert result.problems == ["a.ru: DNS не ответил"] and twice.asked.count("a.ru") == 2
    # The domain's own record is not retried here: its timeout is the caller's to report.
    with pytest.raises(DnsLookupError):
        asyncio.run(check_spf(Flaky(records, {"example.ru": 1}), "example.ru"))


# --- SPF and the clouds' pool addresses (SUV-MAIL-008) -----------------------------------

AWS_LIST = (
    '{"prefixes": ['
    '{"ip_prefix": "54.240.0.0/18", "service": "AMAZON"},'  # Amazon SES: not for rent
    '{"ip_prefix": "3.5.140.0/22", "service": "EC2"},'
    '{"ip_prefix": "52.0.0.0/15", "service": "EC2"}],'
    '"ipv6_prefixes": [{"ipv6_prefix": "2600:1f00::/24", "service": "EC2"}]}'
)
GCP_LIST = '{"prefixes": [{"ipv4Prefix": "34.0.0.0/15"}]}'


def cloud_mail(records: dict, *, lists: bool = True, gcp: bool = True) -> list:
    from suveren import cloud

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if lists and url == cloud.SOURCES[0].url:
            return httpx.Response(200, text=AWS_LIST)
        if lists and gcp and url == cloud.SOURCES[1].url:
            return httpx.Response(200, text=GCP_LIST)
        return httpx.Response(404)

    records = {("example.ru", "MX"): ["10 mx.yandex.net."], **records}
    records.setdefault(("_dmarc.example.ru", "TXT"), ["v=DMARC1; p=reject"])

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await run_mail_checks(FakeResolver(records), client, "example.ru")

    return asyncio.run(go())


def by_id(checks: list, check_id: str):
    return next(c for c in checks if c.id == check_id)


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))


def test_spf_networks_are_collected_through_includes_with_their_owner():
    spf = parse_spf("v=spf1 ip4:1.2.3.0/24 -ip4:5.6.7.8 ~ip6:2001:db8::/32 +ip6:2001:db8::1 -all")
    assert spf.networks == ["1.2.3.0/24", "2001:db8::1"]
    records = {
        ("example.ru", "TXT"): ["v=spf1 ip4:1.2.3.0/24 include:a.ru include:a.ru -all"],
        ("a.ru", "TXT"): ["v=spf1 ip4:3.5.140.0/22 -all"],
    }
    result = asyncio.run(check_spf(FakeResolver(records), "example.ru"))
    assert result.networks == [("1.2.3.0/24", "example.ru"), ("3.5.140.0/22", "a.ru")]


def test_mail_services_in_spf_are_not_rented_addresses(cache):
    # Amazon SES and Google Workspace send from their own ranges, not from customers' pools.
    checks = cloud_mail(
        {
            ("example.ru", "TXT"): ["v=spf1 include:amazonses.com include:_spf.google.com -all"],
            ("amazonses.com", "TXT"): ["v=spf1 ip4:54.240.0.0/18 ip4:69.169.224.0/20 -all"],
            ("_spf.google.com", "TXT"): ["v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ~all"],
        }
    )
    check = by_id(checks, "SUV-MAIL-008")
    assert check.status is Status.OK and "4 записи" in check.details
    assert by_id(checks, "SUV-MAIL-001").status is Status.OK


def test_wide_cloud_range_lets_anyone_send(cache):
    checks = cloud_mail(
        {
            ("example.ru", "TXT"): ["v=spf1 ip4:52.0.0.0/16 ip4:3.0.0.0/8 include:m.example -all"],
            ("m.example", "TXT"): ["v=spf1 ip4:34.1.0.0/16 -all"],
        }
    )
    check = by_id(checks, "SUV-MAIL-008")
    assert check.status is Status.FAIL
    # 52.0/16 + the whole 3.5.140.0/22 inside 3/8 + 34.1/16, each counted once.
    assert "AWS, Google Cloud: в SPF 132 096 таких адресов" in check.details
    assert "ip4:34.1.0.0/16 (Google Cloud, из include:m.example)" in check.details
    assert "m.example публикует сервис" in check.recommendation
    assert by_id(checks, "SUV-MAIL-001").status is Status.WARN


def test_a_block_inside_a_pool_may_be_one_customers(cache):
    checks = cloud_mail({("example.ru", "TXT"): ["v=spf1 ip4:3.5.140.8/29 ip4:3.5.141.1 -all"]})
    check = by_id(checks, "SUV-MAIL-008")
    assert check.status is Status.WARN and "(8 адресов)" in check.details
    assert "за вами;" in check.recommendation
    assert by_id(checks, "SUV-MAIL-001").status is Status.OK


def test_ipv6_only_and_many_ranges(cache):
    many = " ".join(f"ip6:2600:1f{i:02x}::/32" for i in range(7))
    check = by_id(cloud_mail({("example.ru", "TXT"): [f"v=spf1 {many} -all"]}), "SUV-MAIL-008")
    assert check.status is Status.FAIL and "общие диапазоны IPv6" in check.details
    assert "и ещё 2" in check.details
    block = by_id(
        cloud_mail({("example.ru", "TXT"): ["v=spf1 ip6:2600:1f00:1::/56 -all"]}), "SUV-MAIL-008"
    )
    assert block.status is Status.WARN and block.details.startswith("В SPF блоки адресов AWS:")


def test_own_cloud_server_is_fine_and_named(cache):
    check = by_id(
        cloud_mail({("example.ru", "TXT"): ["v=spf1 ip4:3.5.140.7 ip4:198.51.100.0/24 -all"]}),
        "SUV-MAIL-008",
    )
    assert check.status is Status.OK and "Отдельные адреса в облаке (3.5.140.7)" in check.details


def test_cloud_lists_down_or_partial(cache):
    spf = {("example.ru", "TXT"): ["v=spf1 ip4:52.0.0.0/16 -all"]}
    down = by_id(cloud_mail(spf, lists=False), "SUV-MAIL-008")
    assert down.status is Status.UNKNOWN
    partial = by_id(cloud_mail(spf, gcp=False), "SUV-MAIL-008")
    assert partial.status is Status.FAIL and "Google Cloud" in partial.details.split("Списки")[1]


def test_spf_without_networks_needs_no_lists():
    asked = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(str(request.url))
        return httpx.Response(404)

    records = {
        ("example.ru", "MX"): ["10 mx.yandex.net."],
        ("example.ru", "TXT"): ["v=spf1 include:_spf.yandex.net -all"],
        ("_dmarc.example.ru", "TXT"): ["v=DMARC1; p=reject"],
    }

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await run_mail_checks(FakeResolver(records), client, "example.ru")

    check = by_id(asyncio.run(go()), "SUV-MAIL-008")
    assert check.status is Status.OK and "нет диапазонов" in check.details
    assert not any("ip-ranges" in u for u in asked)
    no_spf = evaluate(facts(spf=SpfResult(None, 0)))
    assert not any(c.id == "SUV-MAIL-008" for c in no_spf)


def test_dkim_testing_mode_alone_warns():
    # RFC 6376, 3.6.1: t=y means verifiers treat the mail as unsigned.
    key = dkim_key(2048)
    check = dkim_check(_dkim({"mail": [f"v=DKIM1; t=y; k=rsa; p={key}"]}))
    assert check.status is Status.WARN and "t=y" in check.details and check.recommendation
    flags = dkim_check(_dkim({"mail": [f"v=DKIM1; t=s:Y; k=rsa; p={key}"]}))
    assert flags.status is Status.WARN
    mixed = dkim_check(
        _dkim({"mail": [f"v=DKIM1; t=y; p={key}"], "dkim": [f"v=DKIM1; t=s; p={key}"]})
    )
    assert mixed.status is Status.OK and "В тестовом режиме (t=y): mail" in mixed.details
