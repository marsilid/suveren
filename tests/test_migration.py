import json
from importlib.resources import files

from test_view import sample_report

from suveren.migration import DIFFICULTY, move_for, plan
from suveren.models import Category, Finding, Severity
from suveren.report import render_html


def finding(category, severity, services=("X",)):
    return Finding(category, f"{category.title}: X", severity, "", "", list(services))


def test_every_category_has_a_complete_move():
    data = json.loads(files("suveren").joinpath("data/migration.json").read_text("utf-8"))
    assert set(data["categories"]) == {c.value for c in Category}
    for key, entry in data["categories"].items():
        assert entry["difficulty"] in DIFFICULTY, key
        assert 2 <= len(entry["steps"]) <= 5, key
        assert entry["alternatives"] and entry["cost"], key
        # Costs are never prices: they go stale and would discredit the report.
        assert "₽" not in entry["cost"] and "руб" not in entry["cost"], key


def test_plan_puts_high_risk_and_easy_first():
    moves = plan(
        [
            finding(Category.BUILDER, Severity.HIGH),  # high, hard
            finding(Category.FONTS, Severity.LOW),  # low, easy
            finding(Category.DNS, Severity.HIGH),  # high, easy
            finding(Category.MAIL, Severity.HIGH),  # high, medium
        ]
    )
    assert [m.category for m in moves] == [
        Category.DNS,
        Category.MAIL,
        Category.BUILDER,
        Category.FONTS,
    ]
    assert move_for(finding(Category.DNS, Severity.HIGH)).difficulty_ru == "легко"


def test_report_shows_the_way_out():
    report = sample_report()  # foreign mail and Google Analytics
    html = render_html(report)
    assert "Как переехать" in html and "План переезда" in html
    assert "Яндекс 360" in html
    data = report.to_dict()
    assert data["migration"][0]["id"] == "SUV-DEP-MAIL"
    assert data["migration"][0]["steps"]
