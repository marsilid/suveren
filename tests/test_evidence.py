"""Every finding shows what it rests on: the DNS record, the header, the address, the
request, as they were seen."""

import json

import lab
import pytest
from test_view import sample_report

from suveren.checks import EVIDENCE_MAX, GROUP_152, Check, Evidence, Status
from suveren.report import render_html
from suveren.sarif import to_sarif

PAYLOAD = '<script>alert("x")</script>'


@pytest.fixture(scope="module")
def lab_checks():
    return {case.name: checks for case, checks in lab.run_all()}


def test_evidence_kinds_are_fixed_and_values_are_capped():
    with pytest.raises(ValueError):
        Evidence("guess", "что-то")
    long = Evidence("header", "Заголовок Content-Security-Policy", "x" * (EVIDENCE_MAX + 50))
    assert len(long.value) == EVIDENCE_MAX and long.value.endswith("…")


def test_every_problem_in_the_lab_shows_its_evidence(lab_checks):
    missing = sorted(
        f"{name}: {cid}"
        for name, checks in lab_checks.items()
        for cid, c in checks.items()
        if c.status in (Status.FAIL, Status.WARN) and not c.evidence
    )
    assert missing == []


def test_mail_and_header_evidence_is_the_record_as_seen(lab_checks):
    dmarc = lab_checks["lab-dmarc-none"]["SUV-MAIL-003"].evidence
    assert [(e.kind, e.what, e.value) for e in dmarc] == [
        ("dns", "TXT _dmarc.lab-dmarc-none.ru", "v=DMARC1; p=none")
    ]
    spf = lab_checks["lab-spf-plus-all"]["SUV-MAIL-002"].evidence
    assert spf[0].value.endswith("+all")
    # An absent header is evidence too: the value is empty.
    hsts = lab_checks["lab-no-hsts"]["SUV-WEB-005"].evidence
    assert [(e.what, e.value) for e in hsts] == [("Заголовок Strict-Transport-Security", "")]
    sts = [e.kind for e in lab_checks["lab-mta-sts-mx"]["SUV-MAIL-005"].evidence]
    assert sts == ["dns", "dns", "url", "dns"]


def test_a_secret_is_shown_masked_in_its_evidence(lab_checks):
    leak = lab_checks["lab-leak-aws"]["SUV-WEB-009"].evidence
    assert leak and all("…" in e.value and len(e.value) < 12 for e in leak)


def test_forms_show_their_fields_and_consent(lab_checks):
    form = lab_checks["lab-no-policy"]["SUV-PD-003"].evidence[0]
    assert form.kind == "html" and "phone (tel)" in form.value and "согласие рядом" in form.value


def test_evidence_reaches_json_sarif_and_html_as_text():
    report = sample_report()
    report.checks.append(
        Check(
            GROUP_152,
            "Политика обработки персональных данных",
            Status.FAIL,
            "Нет.",
            evidence=[Evidence("url", f"Ссылка {PAYLOAD}", f"https://x.ru/{PAYLOAD}")],
        )
    )
    data = report.to_dict()
    assert data["checks"][-1]["evidence"][0]["kind"] == "url"
    sarif = json.dumps(to_sarif(report), ensure_ascii=False)
    assert '"evidence": [{"kind": "url"' in sarif
    html = render_html(report)
    assert "Доказательство" in html
    assert "<script>alert" not in html and "&lt;script&gt;" in html
