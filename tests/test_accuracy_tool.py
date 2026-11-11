"""tools/accuracy.py: labels against reports, with Wilson intervals."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "accuracy", Path(__file__).parent.parent / "tools" / "accuracy.py"
)
acc = importlib.util.module_from_spec(_spec)
sys.modules["accuracy"] = acc  # dataclasses look their module up there
_spec.loader.exec_module(acc)


def test_wilson_interval():
    low, high = acc.wilson(10, 10)
    assert round(low, 3) == 0.722 and round(high, 6) == 1.0
    low, high = acc.wilson(5, 10)
    assert round(low, 3) == 0.237 and round(high, 3) == 0.763
    assert acc.wilson(0, 0) == (0.0, 1.0)


def test_compare_counts_and_names_misses(tmp_path):
    labels = tmp_path / "labels.csv"
    labels.write_text(
        "site,check,expected,labeller,date,note\n"
        "a.ru,SUV-WEB-005,warn,me,2026-11-01,\n"
        "b.ru,SUV-WEB-005,ok,me,2026-11-01,\n"
        "c.ru,SUV-WEB-005,fail,me,2026-11-01,\n"
        "d.ru,SUV-WEB-005,ok,me,2026-11-01,\n"
        "e.ru,SUV-WEB-005,warn,me,2026-11-01,нет отчёта\n",
        "utf-8",
    )
    reports = tmp_path / "reports"
    reports.mkdir()
    for site, status in (("a.ru", "warn"), ("b.ru", "ok"), ("c.ru", "ok"), ("d.ru", "fail")):
        data = {"target": site, "checks": [{"id": "SUV-WEB-005", "status": status}]}
        (reports / f"{site}.json").write_text(json.dumps(data), "utf-8")
    (reports / "junk.json").write_text("{not json", "utf-8")
    rows = acc.compare(acc.read_labels(labels), acc.read_reports(reports))
    row = rows["SUV-WEB-005"]
    assert (row.tp, row.fn, row.fp, row.tn, row.missing) == (1, 1, 1, 1, 1)
    assert row.misses == ["c.ru: ждали fail, получили ok", "d.ru: ждали ok, получили fail"]
    table = acc.markdown(rows)
    assert "| SUV-WEB-005 | 1 | 1 | 1 | 1 | 1 | 50% (9–91%) | 50% (9–91%) |" in table
    assert acc.main([str(labels), str(reports), "--markdown"]) == 0


def test_bad_labels_are_refused(tmp_path, capsys):
    labels = tmp_path / "labels.csv"
    labels.write_text("site,check,expected\na.ru,WEB-5,maybe\n", "utf-8")
    with pytest.raises(acc.LabelError):
        acc.read_labels(labels)
    assert acc.main([str(labels), str(tmp_path)]) == 2
    assert "нужны site" in capsys.readouterr().err


def test_template_is_blank_and_reads_back(tmp_path, capsys):
    sites = tmp_path / "sites.txt"
    sites.write_text("A.ru\n# comment\n\nb.ru\n", "utf-8")
    assert acc.main(["template", str(sites), "--checks", "SUV-WEB-005,SUV-PD-001"]) == 0
    text = capsys.readouterr().out
    assert text.splitlines() == [
        "site,check,expected,labeller,date,note",
        "a.ru,SUV-PD-001,,,,",
        "a.ru,SUV-WEB-005,,,,",
        "b.ru,SUV-PD-001,,,,",
        "b.ru,SUV-WEB-005,,,,",
    ]
    labels = tmp_path / "labels.csv"
    labels.write_text(text.replace("a.ru,SUV-PD-001,,", "a.ru,SUV-PD-001,ok,"), "utf-8")
    # Rows nobody judged are skipped, not an error.
    assert [(x.site, x.check) for x in acc.read_labels(labels)] == [("a.ru", "SUV-PD-001")]


def test_mismatches_quote_what_the_report_said(tmp_path):
    labels = tmp_path / "labels.csv"
    labels.write_text(
        "site,check,expected,labeller,date,note\n"
        "a.ru,SUV-WEB-005,ok,me,2026-11-01,\n"
        "b.ru,SUV-WEB-005,warn,me,2026-11-01,\n"
        "c.ru,SUV-WEB-005,warn,me,2026-11-01,\n",
        "utf-8",
    )
    reports = tmp_path / "reports"
    reports.mkdir()
    for site, status, said in (
        ("a.ru", "warn", "HSTS нет"),
        ("b.ru", "ok", "HSTS есть"),
        ("c.ru", "fail", "HSTS нет"),
    ):
        check = {"id": "SUV-WEB-005", "status": status, "title": "HSTS", "details": said}
        (reports / f"{site}.json").write_text(json.dumps({"target": site, "checks": [check]}))
    out = tmp_path / "diff.md"
    assert acc.main([str(labels), str(reports), "--mismatches", str(out)]) == 0
    text = out.read_text("utf-8")
    alarms, missed = text.split("## Пропущенные проблемы")
    assert "**a.ru**" in alarms and "разметка ok, Suveren warn" in alarms and "> HSTS нет" in alarms
    assert "**b.ru**" in missed and "> HSTS есть" in missed and "c.ru" not in text
