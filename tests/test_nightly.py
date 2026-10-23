import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "nightly", Path(__file__).parent.parent / "tools" / "nightly.py"
)
nightly = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nightly)


def report(grade, score, checks, deps=()):
    return {
        "target": "a.ru",
        "overall_grade": grade,
        "overall_score": score,
        "checks": [{"id": i, "status": s} for i, s in checks],
        "dependencies": [{"category": c, "service": s} for c, s in deps],
    }


def test_compare_lists_what_drifted():
    old = {"a.ru": report("B", 80, [("SUV-WEB-005", "ok")], [("dns", "Cloudflare")])}
    new = {
        "a.ru": report("C", 70, [("SUV-WEB-005", "warn")], [("dns", "Selectel")]),
        "b.ru": report("A", 95, []),
    }
    lines = nightly.compare(old, new)
    a = next(line for line in lines if "a.ru" in line)
    assert "B 80 → C 70" in a and "SUV-WEB-005 ok → warn" in a
    assert "+ сервис Selectel (dns)" in a and "− сервис Cloudflare (dns)" in a
    assert any("b.ru" in line and "новый" in line for line in lines)
    assert nightly.compare(old, old) == []


def test_a_grade_that_rose_because_a_section_did_not_run_is_not_an_improvement():
    # economy.gov.ru, 2026-10-23: the page timed out, its problems went with it.
    old = {"a.ru": report("B", 77, [("SUV-PD-000", "ok")])}
    new = {"a.ru": report("B", 89, [("SUV-PD-000", "unknown"), ("SUV-WEB-000", "unknown")])}
    line = nightly.compare(old, new)[0]
    assert "оценка неполная (сейчас не проверены: 152-ФЗ, безопасность сайта)" in line
    assert "сравнивать нельзя" in line and "B 77 → B 89" in line
    # A 1.3 report says it itself, and the gap of the previous run counts too.
    old["a.ru"]["overall_incomplete"] = ["не проверены: почта"]
    full = {"a.ru": report("C", 66, [("SUV-PD-000", "ok")])}
    full["a.ru"]["overall_incomplete"] = []
    assert "в прошлый раз не проверены: почта" in nightly.compare(old, full)[0]
