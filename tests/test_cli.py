import json

from typer.testing import CliRunner

from suveren.cli import app
from suveren.errors import SuverenError

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


def test_scan_runs_everything_by_default(monkeypatch):
    calls = {}

    async def fake_run_scan(host, **kwargs):
        calls.update(kwargs, host=host)
        raise SuverenError("stop")

    monkeypatch.setattr("suveren.cli.run_scan", fake_run_scan)
    runner.invoke(app, ["scan", "example.ru", "--no-open"])
    assert calls["compliance"] and calls["blocklist"]
    runner.invoke(app, ["scan", "example.ru", "--quick"])
    assert not calls["compliance"] and not calls["blocklist"]
    runner.invoke(app, ["scan", "example.ru", "--no-blocklist"])
    assert calls["compliance"] and not calls["blocklist"]


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


def test_fail_under_reads_the_overall_grade(monkeypatch, tmp_path):
    from suveren.catalog import BY_ID
    from suveren.checks import Check, Status
    from suveren.models import Report

    # Independence is perfect (no foreign services), but four separate problems
    # bring the overall grade down to C: --fail-under B must fail.
    report = Report(target="example.ru")
    ids = ("SUV-PD-001", "SUV-PD-002", "SUV-WEB-004", "SUV-WEB-006")
    report.checks = [
        Check(BY_ID[i].group, BY_ID[i].title, Status.FAIL, "", f"Исправьте {i}.") for i in ids
    ]

    async def fake_run_scan(host, **kwargs):
        return report

    monkeypatch.setattr("suveren.cli.run_scan", fake_run_scan)
    args = ["scan", "example.ru", "--no-open", "-o", str(tmp_path / "r.html")]
    assert report.grade == "A"
    result = runner.invoke(app, [*args, "--fail-under", "B"])
    assert result.exit_code == 3 and "Общая оценка C" in result.output
    assert runner.invoke(app, [*args, "--fail-under", "C"]).exit_code == 0
