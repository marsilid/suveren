import json

from typer.testing import CliRunner

from suveren.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "Suveren" in result.output


def test_services_lists_database():
    result = runner.invoke(app, ["services"])
    assert result.exit_code == 0
    assert "Cloudflare" in result.output
    assert "Яндекс Метрика" in result.output


def test_scan_rejects_invalid_domain():
    result = runner.invoke(app, ["scan", "not a domain"])
    assert result.exit_code == 2


def test_scan_rejects_bad_grade():
    result = runner.invoke(app, ["scan", "example.ru", "--fail-under", "Z"])
    assert result.exit_code == 2


def _report(deps, grade, score):
    return {"target": "example.ru", "grade": grade, "score": score, "dependencies": deps}


def test_diff(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    cf = {"category_title": "DNS-серверы", "service": "Cloudflare", "foreign": True}
    sel = {"category_title": "DNS-серверы", "service": "Selectel", "foreign": False}
    old.write_text(json.dumps(_report([cf], "D", 50)), encoding="utf-8")
    new.write_text(json.dumps(_report([sel], "A", 100)), encoding="utf-8")
    result = runner.invoke(app, ["diff", str(old), str(new)])
    assert result.exit_code == 0
    assert "D → A" in result.output
    assert "убран" in result.output and "Cloudflare" in result.output
    assert "добавлен" in result.output and "Selectel" in result.output
