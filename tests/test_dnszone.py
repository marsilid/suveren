"""CAA (RFC 8659) and DNSSEC (RFC 4035, RFC 8624): DNS-only checks of the site's zone."""

import asyncio
import sys
from pathlib import Path

import pytest

from suveren.checks import Status
from suveren.dnsutil import DnsLookupError
from suveren.dnszone import (
    CaaResult,
    DnssecResult,
    caa_check,
    caa_names,
    dnssec_check,
    find_caa,
    matching_ds,
    parse_caa,
    run_zone_checks,
)

sys.path.insert(0, str(Path(__file__).parent))
from lab import dnskey, ds_for


class FakeResolver:
    kind = "fake"

    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self.records = records
        self.asked: list[tuple[str, str]] = []

    async def resolve(self, name: str, rtype: str) -> list[str]:
        self.asked.append((name, rtype))
        value = self.records.get((name, rtype), [])
        if value == ["SERVFAIL"]:
            raise DnsLookupError(f"DNS вернул ошибку на запрос {rtype} {name}")
        return value


def caa(records: list[str], name: str = "example.ru", *, https: bool = True):
    return caa_check(CaaResult("example.ru", name, records), https=https)


# --- CAA ------------------------------------------------------------------------------


def test_caa_names_climb_to_the_registrable_domain_without_the_tld():
    assert caa_names("www.shop.example.ru.") == ["www.shop.example.ru", "shop.example.ru",
                                                 "example.ru"]  # fmt: skip
    assert caa_names("example.ru") == ["example.ru"]


def test_caa_relevant_set_is_the_nearest_one():
    resolver = FakeResolver({("example.ru", "CAA"): ['0 issue "letsencrypt.org"']})
    result = asyncio.run(find_caa(resolver, "www.example.ru"))  # type: ignore[arg-type]
    assert result.name == "example.ru"
    assert resolver.asked == [("www.example.ru", "CAA"), ("example.ru", "CAA")]
    check = caa_check(result, https=True)
    assert check.status is Status.OK and "действует запись example.ru" in check.details
    own = FakeResolver(
        {("www.example.ru", "CAA"): ['0 issue "pki.goog"'], ("example.ru", "CAA"): ['0 issue ";"']}
    )
    assert asyncio.run(find_caa(own, "www.example.ru")).name == "www.example.ru"  # type: ignore[arg-type]


def test_caa_dns_failure_is_unknown():
    resolver = FakeResolver({("example.ru", "CAA"): ["SERVFAIL"]})
    result = asyncio.run(find_caa(resolver, "example.ru"))  # type: ignore[arg-type]
    check = caa_check(result, https=True)
    assert check.status is Status.UNKNOWN and "CAA example.ru" in check.details


def test_no_caa_is_a_note():
    check = caa_check(CaaResult("example.ru", None), https=True)
    assert check.id == "SUV-WEB-012"
    assert check.status is Status.OK and "любой центр" in check.details
    assert not check.recommendation


@pytest.mark.parametrize(
    ("record", "parsed"),
    [
        ('0 issue "letsencrypt.org"', (0, "issue", "letsencrypt.org")),
        ('128 ISSUE "ca.example; account=1"', (128, "issue", "ca.example; account=1")),
        (r"\# 20 00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f",
         (0, "issue", "letsencrypt.o")),
    ],
)  # fmt: skip
def test_parse_caa_reads_text_and_generic_forms(record, parsed):
    c = parse_caa(record)
    assert c is not None and (c.flags, c.tag, c.value) == parsed


def test_parse_caa_rejects_junk():
    assert parse_caa("issue letsencrypt.org") is None
    assert parse_caa("") is None


def test_caa_lists_authorities_wildcards_and_iodef():
    check = caa(
        [
            '0 issue "letsencrypt.org"',
            '0 issue "pki.goog; validationmethods=dns-01"',
            '0 issuewild "sectigo.com"',
            '0 iodef "mailto:sec@example.ru"',
        ]
    )
    assert check.status is Status.OK
    assert "только letsencrypt.org, pki.goog" in check.details
    assert "*.example.ru — sectigo.com" in check.details
    assert "mailto:sec@example.ru" in check.details


def test_caa_without_issue_leaves_ordinary_certificates_open():
    check = caa(['0 issuewild ";"'])
    assert check.status is Status.OK
    assert "любой центр" in check.details and "сертификаты *. запрещены" in check.details


def test_caa_critical_unknown_tag_blocks_issuance():
    check = caa(['0 issue "letsencrypt.org"', '128 tbs "x"'])
    assert check.status is Status.WARN and "tbs" in check.details
    # A known tag with the flag, or an unknown one without it, is fine.
    assert caa(['128 issue "letsencrypt.org"', '0 tbs "x"']).status is Status.OK


def test_caa_forbidding_everyone_matters_only_with_https():
    check = caa(['0 issue ";"', '0 issuewild "letsencrypt.org"'])
    assert check.status is Status.WARN
    assert check.details.endswith("Только для сертификатов на *.example.ru: letsencrypt.org.")
    assert check.recommendation
    calm = caa(['0 issue ";"'], https=False)
    assert calm.status is Status.OK and "запрещён всем" in calm.details


# --- DNSSEC ---------------------------------------------------------------------------

ZONE = "example.ru"
KEY = dnskey()


def sec(ds: list[str], keys: list[str]):
    return dnssec_check(DnssecResult(ZONE, ds, keys))


def test_ds_matches_the_key_with_every_digest():
    for digest, number in (("SHA1", 1), ("SHA256", 2), ("SHA384", 4)):
        assert matching_ds(ZONE, [ds_for(ZONE, KEY, digest)], [KEY]) == [(13, number)]


def test_ds_of_another_zone_or_algorithm_does_not_match():
    assert matching_ds(ZONE, [ds_for("other.ru", KEY)], [KEY]) == []
    other_alg = dnskey(algorithm=8)
    assert matching_ds(ZONE, [ds_for(ZONE, other_alg)], [KEY]) == []


def test_junk_records_are_skipped():
    good = ds_for(ZONE, KEY)
    assert matching_ds(ZONE, ["junk", "1 13 9 abcd", good], ["junk", KEY]) == [(13, 2)]


def test_signed_zone_is_ok_and_says_what_is_not_checked():
    check = sec([ds_for(ZONE, KEY)], [KEY])
    assert check.id == "SUV-WEB-013"
    assert check.status is Status.OK
    assert "ECDSAP256SHA256 (13)" in check.details and "подписи и их сроки" in check.details
    assert "SHA-1" not in check.details


def test_sha1_ds_is_mentioned_but_not_a_warning():
    check = sec([ds_for(ZONE, KEY, "SHA1")], [KEY])
    assert check.status is Status.OK and "SHA-1" in check.details


def test_unsigned_zone_and_island_are_notes():
    assert sec([], []).status is Status.OK
    island = sec([], [KEY])
    assert island.status is Status.OK and "DS у регистратора нет" in island.details


def test_ds_without_keys_or_with_a_stale_key_is_broken():
    assert sec([ds_for(ZONE, KEY)], []).status is Status.FAIL
    stale = sec([ds_for(ZONE, dnskey(5))], [KEY])
    assert stale.status is Status.FAIL and stale.recommendation


@pytest.mark.parametrize(("algorithm", "word"), [(5, "не рекомендуется"), (12, "запрещено")])
def test_old_algorithms_warn(algorithm, word):
    key = dnskey(algorithm=algorithm)
    check = sec([ds_for(ZONE, key)], [key])
    assert check.status is Status.WARN and word in check.details


def test_rollover_to_a_good_algorithm_is_ok():
    old = dnskey(algorithm=5)
    check = sec([ds_for(ZONE, old), ds_for(ZONE, KEY)], [old, KEY])
    assert check.status is Status.OK


def test_dnssec_dns_failure_is_unknown():
    check = dnssec_check(DnssecResult(ZONE, problem="DNS не ответил вовремя на запрос DS"))
    assert check.status is Status.UNKNOWN


# --- together -------------------------------------------------------------------------


def test_run_zone_checks_gives_evidence_from_the_dns():
    resolver = FakeResolver(
        {
            ("example.ru", "CAA"): ['0 issue "letsencrypt.org"'],
            ("example.ru", "DS"): [ds_for(ZONE, KEY)],
            ("example.ru", "DNSKEY"): [KEY],
        }
    )
    caa_c, sec_c = asyncio.run(run_zone_checks(resolver, "www.example.ru", https=True))  # type: ignore[arg-type]
    assert (caa_c.status, sec_c.status) == (Status.OK, Status.OK)
    assert [(e.what, e.value) for e in caa_c.evidence] == [
        ("CAA www.example.ru", ""),
        ("CAA example.ru", '0 issue "letsencrypt.org"'),
    ]
    assert [e.what for e in sec_c.evidence] == ["DS example.ru", "DNSKEY example.ru"]


def test_run_zone_checks_without_answers_has_no_evidence():
    resolver = FakeResolver(
        {("example.ru", "CAA"): ["SERVFAIL"], ("example.ru", "DS"): ["SERVFAIL"]}
    )
    checks = asyncio.run(run_zone_checks(resolver, "example.ru", https=True))  # type: ignore[arg-type]
    assert [c.status for c in checks] == [Status.UNKNOWN, Status.UNKNOWN]
    assert all(not c.evidence for c in checks)


def test_old_algorithm_is_low_urgency_but_broken_chain_is_urgent():
    from suveren.advice import priorities
    from suveren.models import Report, Severity

    old = dnskey(algorithm=5)
    for ds, keys, severity in (
        ([ds_for(ZONE, old)], [old], Severity.LOW),
        ([ds_for(ZONE, KEY)], [], Severity.HIGH),
    ):
        report = Report(target=ZONE)
        report.checks = [sec(ds, keys)]
        assert [a.severity for a in priorities(report)] == [severity]
