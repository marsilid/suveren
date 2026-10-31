"""tools/update_vulns.py keeps the part of the retire.js database Suveren uses."""

import datetime as dt
import importlib.util
import json
from pathlib import Path

import pytest

from suveren.vulns import RETIRE_NAMES, parse_retire

_spec = importlib.util.spec_from_file_location(
    "update_vulns", Path(__file__).parent.parent / "tools" / "update_vulns.py"
)
uv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uv)


def repository(**extra):
    keys = {k for names in RETIRE_NAMES.values() for k in names}
    repo = {k: {"vulnerabilities": [], "extractors": {"uri": ["x"]}} for k in keys}
    repo["jquery"]["vulnerabilities"] = [
        {"below": "3.5.0", "severity": "medium", "identifiers": {"CVE": ["CVE-2020-11022"]}}
    ]
    repo["react"] = {"vulnerabilities": [{"below": "0.14.0"}]}
    repo.update(extra)
    return repo


def test_snapshot_keeps_our_libraries_and_their_vulnerabilities():
    snap = uv.snapshot(repository(), dt.date(2026, 10, 31))
    assert snap["_suveren"]["fetched"] == "2026-10-31"
    assert "react" not in snap and "extractors" not in snap["jquery"]
    assert parse_retire(snap)["jquery"][0].label == "CVE-2020-11022"


def test_snapshot_refuses_a_database_without_our_libraries():
    repo = repository()
    del repo["moment.js"]
    with pytest.raises(SystemExit, match=r"moment\.js"):
        uv.snapshot(repo, dt.date(2026, 10, 31))


def test_diff_names_added_and_removed_entries(tmp_path, monkeypatch, capsys):
    old = uv.snapshot(repository(), dt.date(2026, 10, 1))
    newer = repository()
    newer["lodash"]["vulnerabilities"] = [
        {"below": "4.17.23", "identifiers": {"githubID": "GHSA-xxxx"}}
    ]
    newer["jquery"]["vulnerabilities"] = []
    lines = uv.diff(old, uv.snapshot(newer, dt.date(2026, 10, 31)))
    assert lines == ["+ lodash GHSA-xxxx (ниже 4.17.23)", "- jquery CVE-2020-11022 (ниже 3.5.0)"]

    source = tmp_path / "jsrepository-v4.json"
    source.write_text(json.dumps(newer), "utf-8")
    data = tmp_path / "retire.json"
    data.write_text(json.dumps(old), "utf-8")
    monkeypatch.setattr(uv, "DATA", data)
    assert uv.main(["--file", str(source)]) == 0
    assert json.loads(data.read_text("utf-8")) == old  # without --write nothing changes
    assert uv.main(["--file", str(source), "--write"]) == 0
    assert json.loads(data.read_text("utf-8"))["lodash"]["vulnerabilities"]
    assert "записано" in capsys.readouterr().out
