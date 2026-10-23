import asyncio

import golden as corpus
import pytest

from suveren.audit import audit


def check(cid, status, details="Текст.", recommendation="Сделайте так."):
    return {
        "id": cid,
        "title": cid,
        "status": status,
        "details": details,
        "recommendation": recommendation,
    }


def rules(report):
    return {i.rule for i in audit(report)}


def test_each_contradiction_a_reader_once_caught_is_flagged():
    # SUV-WEB-001 filed under "в порядке" with alarming text.
    assert "ok-but-alarming" in rules(
        {"checks": [check("SUV-WEB-001", "ok", "Каждый может выполнить любой код. Уберите.")]}
    )
    # SUV-MAIL-005 warned with its advice inside the text.
    assert "problem-without-advice" in rules(
        {"checks": [check("SUV-MAIL-005", "warn", recommendation="")]}
    )
    # gosuslugi.ru: the security section vanished, no "не проверено" line.
    assert "section-vanished" in rules(
        {"checks": [check("SUV-PD-001", "ok"), check("SUV-MAIL-001", "ok")]}
    )
    # Cross-border transfer seen by one check and denied by another.
    assert "xborder-disagree" in rules(
        {"checks": [check("SUV-PD-006", "warn"), check("SUV-PD-010", "ok")]}
    )
    assert "flow-missing" in rules({"checks": [check("SUV-PD-010", "warn")], "facts": {}})
    assert "problem-but-calm" in rules(
        {"checks": [check("SUV-WEB-002", "warn", "Таких скриптов не найдено.")]}
    )
    assert "duplicate-id" in rules({"checks": [check("SUV-PD-001", "ok")] * 2})
    assert "grade-mismatch" in rules({"checks": [], "overall_score": 95, "overall_grade": "D"})
    # profi.ru: an HTTPS site whose TLS check left the report.
    web = [check("SUV-WEB-001", "ok"), check("SUV-WEB-005", "ok")]
    https = {"facts": {"final_url": "https://profi.ru/"}}
    assert "check-vanished" in rules({"checks": web, **https})
    assert "check-vanished" not in rules({"checks": [*web, check("SUV-WEB-008", "ok")], **https})


def test_a_consistent_report_passes():
    from test_view import sample_report

    report = sample_report()
    data = report.to_dict()
    assert audit(data) == []


@pytest.mark.skipif(not corpus.sites(), reason="no local corpus")
@pytest.mark.parametrize("host", corpus.sites())
def test_corpus_reports_do_not_contradict_themselves(host):
    checks = asyncio.run(corpus.replay_checks(host))
    report = {"checks": [c.to_dict() for c in checks]}
    assert audit(report) == [], host


def test_quoted_names_and_word_parts_are_not_alarms():
    # bi.zone: the operator's legal name holds "опасн" inside "БЕЗОПАСНАЯ".
    text = 'ООО "БЕЗОПАСНАЯ ИНФОРМАЦИОННАЯ ЗОНА" (ИНН 9701036178) в реестре.'
    assert "ok-but-alarming" not in rules({"checks": [check("SUV-PD-009", "ok", text)]})
    assert "ok-but-alarming" not in rules({"checks": [check("SUV-PD-009", "ok", "Безопасность.")]})
