"""tools/update_vulns.py reads NVD records offline the same way it does online."""

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "update_vulns", Path(__file__).parent.parent / "tools" / "update_vulns.py"
)
uv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uv)


def record(*matches, status="Analyzed"):
    return {"vulnStatus": status, "configurations": [{"nodes": [{"cpeMatch": list(matches)}]}]}


def match(product, **versions):
    return {"vulnerable": True, "criteria": f"cpe:2.3:a:{product}:*:*:*:*:*:*:*", **versions}


def test_ranges_are_read_deduplicated_and_compared():
    cve = record(
        match("momentjs:moment", versionStartIncluding="2.18.0", versionEndExcluding="2.29.4"),
        match("momentjs:moment", versionStartIncluding="2.18.0", versionEndExcluding="2.29.4"),
        match("f5:big-ip_analytics", versionStartIncluding="12.1.0", versionEndExcluding="13"),
    )
    assert uv.nvd_ranges(cve, "moment") == ([["2.18.0", "2.29.4"]], [])
    entry = {"library": "moment", "id": "CVE-2022-31129", "ranges": [["2.18.0", "2.29.4"]]}
    assert uv.compare(entry, cve) == ("moment CVE-2022-31129: совпадает", None)
    entry["ranges"] = [[None, "2.29.4"]]
    line, ranges = uv.compare(entry, cve)
    assert ranges == [["2.18.0", "2.29.4"]] and "было" in line


def test_rejected_cve_is_reported_not_rewritten():
    entry = {"library": "bootstrap", "id": "CVE-2024-6484", "ranges": [[None, "4.0.0"]]}
    line, ranges = uv.compare(entry, record(status="Rejected"))
    assert "ОТОЗВАНА" in line and ranges is None


def test_inclusive_bound_is_not_turned_into_a_wrong_range():
    cve = record(match("lodash:lodash", versionEndIncluding="4.17.20"))
    ranges, odd = uv.nvd_ranges(cve, "lodash")
    assert ranges == [] and "versionEndIncluding" in odd[0]


def test_write_changes_only_the_range_and_the_date(tmp_path, monkeypatch):
    import json

    data = tmp_path / "vulns.json"
    original = uv.DATA.read_text(encoding="utf-8")
    data.write_text(original.replace('[["2.18.0", "2.29.4"]]', '[[null, "2.29.4"]]'), "utf-8")
    entries = json.loads(original)["vulns"]

    def fake_fetch(client, cve_id):
        entry = next(e for e in entries if e["id"] == cve_id)
        product = uv.CPE[entry["library"]]
        return record(
            *(
                match(product, versionStartIncluding=a, versionEndExcluding=b)
                if a
                else match(product, versionEndExcluding=b)
                for a, b in entry["ranges"]
            )
        )

    monkeypatch.setattr(uv, "DATA", data)
    monkeypatch.setattr(uv, "fetch", fake_fetch)
    monkeypatch.setattr(uv, "DELAY", 0)
    assert uv.main(["--write"]) == 0
    written = data.read_text(encoding="utf-8")
    assert '[["2.18.0", "2.29.4"]]' in written
    # Everything else is as it was, apart from the date.
    old_date = json.loads(original)["checked"]
    new_date = json.loads(written)["checked"]
    assert written.replace(new_date, old_date) == original
