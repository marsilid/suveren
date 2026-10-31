""".suveren-ignore: accepted findings with a reason, an author and an end date."""

import json
from datetime import date

import pytest
from test_e2e import offline, run_cli  # noqa: F401  (the fixture)
from test_schema import SCHEMA, errors

from suveren.advice import overall_score, priorities
from suveren.audit import audit
from suveren.checks import GROUP_152, Check, Status
from suveren.cli import failing_checks
from suveren.ignore import IgnoreFileError, apply, parse
from suveren.models import Report
from suveren.sarif import to_sarif
from suveren.websec import GROUP_WEB

TODAY = date(2026, 11, 1)
FILE = """
# ID          сайт         до          автор    причина
SUV-PD-001    example.ru   2027-01-31  ivanov   Политику публикуем вместе с новым сайтом
SUV-WEB-004   *            2026-10-01  petrova  CSP готовим в задаче WEB-123
"""


def report_with(*checks):
    report = Report(target="example.ru")
    report.checks = list(checks)
    return report


def policy(status=Status.FAIL):
    return Check(
        GROUP_152, "Политика обработки персональных данных", status, "Нет.", "Опубликуйте."
    )


def test_parse_reads_every_field():
    first, second = parse(FILE)
    assert (first.check_id, first.site, first.until, first.author) == (
        "SUV-PD-001",
        "example.ru",
        date(2027, 1, 31),
        "ivanov",
    )
    assert first.reason == "Политику публикуем вместе с новым сайтом"
    assert second.site == "*" and second.line == 4


@pytest.mark.parametrize(
    ("line", "said"),
    [
        ("SUV-PD-001 example.ru 2027-01-31 ivanov", "пять полей"),  # no reason
        ("SUV-PD-001 example.ru 31.01.2027 ivanov причина", "ГГГГ-ММ-ДД"),
        ("SUV-PD-999 example.ru 2027-01-31 ivanov причина", "нет, см. suveren checks"),
        ("mail example.ru 2027-01-31 ivanov причина", "не похоже на ID"),
        ("SUV-PD-001 https://example.ru/ 2027-01-31 ivanov причина", "доменом"),
    ],
)
def test_a_broken_line_refuses_the_whole_file(line, said):
    with pytest.raises(IgnoreFileError, match=said) as exc:
        parse(f"# ok\n{line}\n")
    assert "строка 2" in str(exc.value)


def test_plugin_ids_are_allowed():
    assert parse("ACME-WEB-001 * 2027-01-31 ivanov наш плагин")[0].check_id == "ACME-WEB-001"


def test_an_accepted_problem_leaves_priorities_score_and_ci():
    check = policy()
    report = report_with(check)
    before = overall_score(report)
    notes = apply(report.checks, parse(FILE), "example.ru", TODAY)
    assert notes == []
    assert check.accepted == {
        "reason": "Политику публикуем вместе с новым сайтом",
        "author": "ivanov",
        "until": "2027-01-31",
    }
    # The problem stays in the report with its status...
    assert check.status is Status.FAIL
    # ...but costs nothing and fails no threshold.
    assert priorities(report) == [] and overall_score(report) > before
    from suveren.cli import FailOn

    assert failing_checks(report, FailOn.warn) == []
    data = report.to_dict()
    assert data["checks"][0]["accepted"]["author"] == "ivanov"
    assert audit(data) == []


def test_subdomains_match_and_other_sites_do_not():
    entries = parse(FILE)
    shop = policy()
    apply([shop], entries, "shop.example.ru", TODAY)
    assert shop.accepted is not None
    other = policy()
    apply([other], entries, "example.com", TODAY)
    assert other.accepted is None


def test_an_expired_exception_stops_working_and_says_so():
    csp = Check(
        GROUP_WEB, "Политика безопасности контента (CSP)", Status.WARN, "Нет CSP.", "Добавьте."
    )
    notes = apply([csp], parse(FILE), "example.ru", TODAY)
    assert csp.accepted is None
    assert notes == [
        "Исключение для SUV-WEB-004 (строка 4, petrova) истекло 01.10.2026: проверка снова "
        "учитывается."
    ]


def test_the_last_day_still_counts():
    check = policy()
    apply([check], parse(FILE), "example.ru", date(2027, 1, 31))
    assert check.accepted is not None


def test_an_exception_no_longer_needed_is_named():
    check = policy(Status.OK)
    notes = apply([check], parse(FILE), "example.ru", TODAY)
    assert check.accepted is None
    assert notes == [
        "Исключение для SUV-PD-001 (строка 3) больше не нужно: проверка в порядке. Его можно "
        "удалить."
    ]


def test_not_checked_is_never_accepted():
    check = policy(Status.UNKNOWN)
    apply([check], parse(FILE), "example.ru", TODAY)
    assert check.accepted is None


def test_sarif_marks_it_as_suppressed():
    check = policy()
    apply([check], parse(FILE), "example.ru", TODAY)
    [result] = [r for r in to_sarif(report_with(check))["runs"][0]["results"]]
    [suppression] = result["suppressions"]
    assert suppression["kind"] == "external" and suppression["status"] == "accepted"
    assert "ivanov" in suppression["justification"]


def test_scan_with_an_ignore_file_end_to_end(offline, tmp_path):  # noqa: F811
    case = offline("lab-tls-wrong-host")
    ignore = tmp_path / "accepted.txt"
    ignore.write_text(
        f"SUV-WEB-008 {case.host} 2099-12-31 ivanov сертификат меняем в декабре\n",
        encoding="utf-8",
    )
    out = tmp_path / "r.json"
    html = tmp_path / "r.html"
    args = [
        case.host,
        "--fail-on",
        "fail",
        "--allow-incomplete",
        "--json",
        str(out),
        "-o",
        str(html),
    ]
    # Without the file the TLS problem fails CI (exit 4); accepted, it does not.
    assert run_cli(tmp_path, *args).exit_code == 4
    result = run_cli(tmp_path, *args, "--ignore", str(ignore))
    assert result.exit_code == 0, result.output
    assert "Принято до 31.12.2099 (ivanov): сертификат меняем в декабре" in result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert errors(data, SCHEMA) == [] and audit(data) == []
    [tls] = [c for c in data["checks"] if c["id"] == "SUV-WEB-008"]
    assert tls["status"] == "fail" and tls["accepted"]["until"] == "2099-12-31"
    assert "Принято до 31.12.2099 (ivanov)" in html.read_text(encoding="utf-8")


def test_a_broken_ignore_file_stops_before_the_scan(offline, tmp_path):  # noqa: F811
    case = offline("lab-good")
    bad = tmp_path / "bad.txt"
    bad.write_text("SUV-WEB-008 * завтра ivanov потом\n", encoding="utf-8")
    result = run_cli(tmp_path, case.host, "--ignore", str(bad), "--no-report")
    assert result.exit_code == 2 and "ГГГГ-ММ-ДД" in result.output


def test_the_default_file_is_read_from_the_current_folder(tmp_path, monkeypatch):
    from suveren.ignore import load

    monkeypatch.chdir(tmp_path)
    assert load(None) == []
    (tmp_path / ".suveren-ignore").write_text(FILE, encoding="utf-8")
    assert len(load(None)) == 2
