"""The JSON report matches data/report.schema.json (a small validator: no extra package)."""

import json
import re
from importlib.resources import files
from pathlib import Path

import lab
import pytest

SCHEMA = json.loads(files("suveren").joinpath("data/report.schema.json").read_text("utf-8"))
_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def _is(value, name: str) -> bool:
    if name in ("integer", "number") and isinstance(value, bool):
        return False
    return isinstance(value, _TYPES[name])


def errors(value, schema: dict, path: str = "$") -> list[str]:
    """The subset of JSON Schema 2020-12 that report.schema.json uses."""
    if "$ref" in schema:
        schema = SCHEMA["$defs"][schema["$ref"].rsplit("/", 1)[1]]
    if "oneOf" in schema:
        ok = [s for s in schema["oneOf"] if not errors(value, s, path)]
        return [] if len(ok) == 1 else [f"{path}: не подходит ровно под один вариант"]
    out = []
    kinds = schema.get("type")
    if kinds and not any(_is(value, k) for k in ([kinds] if isinstance(kinds, str) else kinds)):
        return [f"{path}: ожидался {kinds}, а не {type(value).__name__}"]
    if "const" in schema and value != schema["const"]:
        out.append(f"{path}: не {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        out.append(f"{path}: {value!r} не из {schema['enum']}")
    if isinstance(value, str) and "pattern" in schema and not re.search(schema["pattern"], value):
        out.append(f"{path}: {value!r} не по шаблону {schema['pattern']}")
    numeric = isinstance(value, int) and not isinstance(value, bool)
    if numeric and not schema.get("minimum", value) <= value <= schema.get("maximum", value):
        out.append(f"{path}: {value} вне диапазона")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        out += [f"{path}: нет поля {k}" for k in schema.get("required", []) if k not in value]
        for k, v in value.items():
            if k in props:
                out += errors(v, props[k], f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                out.append(f"{path}: лишнее поле {k}")
            elif isinstance(schema.get("additionalProperties"), dict):
                out += errors(v, schema["additionalProperties"], f"{path}.{k}")
    if isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
            out.append(f"{path}: {len(value)} элементов")
        for i, item in enumerate(value):
            out += errors(item, schema.get("items", {}), f"{path}[{i}]")
    return out


def test_a_full_report_matches_the_schema():
    from test_view import sample_report

    from suveren.checks import Evidence

    report = sample_report()
    report.checks[0].evidence = [
        Evidence("url", "Ссылка на политику на главной", ""),
        Evidence("header", "Заголовок Strict-Transport-Security", "max-age=0"),
    ]
    data = report.to_dict()
    assert data["schema_version"] == "1.4"
    assert errors(data, SCHEMA) == []
    data["checks"][0]["evidence"][0]["kind"] = "guess"
    assert errors(data, SCHEMA)


def test_every_lab_check_matches_the_schema():
    for case, checks in lab.run_all():
        for check in checks.values():
            assert errors(check.to_dict(), {"$ref": "#/$defs/check"}) == [], case.name


def test_the_validator_catches_a_broken_report():
    from test_view import sample_report

    data = sample_report().to_dict()
    data["checks"][0]["status"] = "maybe"
    del data["notes"]
    found = errors(data, SCHEMA)
    assert any("maybe" in e for e in found) and any("notes" in e for e in found)


SAVED = sorted((Path(__file__).parent.parent / "reports" / "1b" / "final").glob("*.json"))


@pytest.mark.skipif(not SAVED, reason="no saved reports")
@pytest.mark.parametrize("path", SAVED, ids=lambda p: p.stem)
def test_saved_reports_match_the_schema(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("schema_version", "1.0")  # written before the field existed
    data.setdefault("tool_version", "1.1.0")
    assert errors(data, SCHEMA) == []
