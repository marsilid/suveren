"""Draft documents: filled from the report, marked as drafts, gaps left visible."""

import json
from datetime import date

import pytest
from typer.testing import CliRunner

from suveren.checks import Check, Status
from suveren.cli import app
from suveren.drafts import FILL, WARNING, consent, draft, policy
from suveren.models import Category, Dependency, Report


def report() -> dict:
    r = Report(
        "shop.ru", checks=[Check("Безопасность сайта", "Принудительный HTTPS (HSTS)", Status.OK)]
    )
    r.dependencies = [
        Dependency(Category.ANALYTICS, "Яндекс Метрика", "RU", "mc.yandex.ru"),
        Dependency(Category.ANALYTICS, "Google Analytics", "US", "gtag.js"),
        Dependency(Category.HOSTING, "Selectel", "RU", "IP"),
        Dependency(Category.FONTS, "Google Fonts", "US", "fonts.googleapis.com"),
    ]
    return r.to_dict()


def test_policy_lists_services_countries_and_server():
    text = policy(report(), date(2026, 11, 1))
    assert text.count(WARNING) == 2 and "Составлено: 01.11.2026" in text
    assert "- Google Analytics (США)" in text and "- Яндекс Метрика (Россия)" in text
    assert "передаются в: США." in text and "Сервер сайта: Selectel (Россия)" in text
    assert "аналитики: Яндекс Метрика, Google Analytics" in text
    assert FILL.format("полное наименование, ИНН, ОГРН, адрес") in text


def test_policy_without_services():
    empty = Report("a.ru").to_dict()
    text = policy(empty)
    assert "Сторонних сервисов, получающих данные посетителей, Suveren не увидел." in text
    assert FILL.format("где находится сервер с базой данных") in text


def test_consent_names_foreign_countries():
    text = consent(report())
    assert text.count(WARNING) == 2 and "ст. 9 ч. 1" in text
    assert "в странах: США." in text
    assert "в странах" not in consent(Report("a.ru").to_dict())
    with pytest.raises(ValueError):
        draft(report(), "contract")


def test_draft_command(tmp_path):
    path = tmp_path / "r.json"
    path.write_text(json.dumps(report(), ensure_ascii=False), "utf-8")
    result = CliRunner().invoke(app, ["draft", str(path), "-k", "consent"])
    assert result.exit_code == 0, result.output
    out = tmp_path / "shop.ru-consent-черновик.md"
    assert out.exists() and "юристом" in result.output
    assert CliRunner().invoke(app, ["draft", str(path), "-k", "x"]).exit_code == 2
