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
    # sravni.ru: the site's DNS did not answer, and the grade was not "неполная".
    note = "Не удалось получить IP-адреса сайта: DNS не ответил вовремя на запрос A sravni.ru"
    assert "dns-gap-complete" in rules({"checks": [], "notes": [note], "overall_incomplete": []})
    gap = {"checks": [], "notes": [note], "overall_incomplete": ["не проверены: хостинг"]}
    assert "dns-gap-complete" not in rules(gap)
    whois = "Не удалось получить регистратора: WHOIS недоступен"
    assert "dns-gap-complete" not in rules(
        {"checks": [], "notes": [whois], "overall_incomplete": []}
    )


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


def _scored():
    from test_view import sample_report

    return sample_report().to_dict()


def test_scoring_rules_are_guarded():
    data = _scored()
    assert audit(data) == []
    # A failed check costs a high problem: the overall grade cannot stay at the top.
    top = {**data, "overall_score": 95, "overall_grade": "A"}
    assert {"fail-top", "score-mismatch"} <= rules(top)
    # An unseen page keeps both grades at B at most.
    unseen = {**data, "facts": {**data["facts"], "page_unseen": "стена от ботов"}}
    unseen |= {"score": 96, "grade": "A", "findings": []}
    assert "incomplete-top" in rules(unseen)
    # A quarter of the checks not run caps the overall grade too.
    gap = {**data, "overall_incomplete": ["не удалось проверить 9 из 20"], "overall_score": 92}
    gap["overall_grade"] = "A"
    assert "incomplete-top" in rules(gap)
    # The independence score is the sum of the findings' penalties.
    assert "score-mismatch" in rules({**data, "score": data["score"] + 4, "grade": "B"})
    assert "score-range" in rules({**data, "score": 120, "grade": "A"})
    assert "grade-mismatch" in rules({**data, "grade": "A"})


def test_old_reports_are_not_recounted_with_new_weights():
    data = _scored()
    old = {**data, "tool_version": "1.0.0", "overall_score": data["overall_score"] - 1}
    assert "score-mismatch" not in rules(old)
