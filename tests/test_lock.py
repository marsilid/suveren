"""The release builds from packaging/*.txt: they must cover pyproject's dependencies."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _names(lock: str) -> set[str]:
    text = (ROOT / "packaging" / lock).read_text(encoding="utf-8")
    return {m.lower() for m in re.findall(r"^([A-Za-z0-9_.-]+)==", text, re.M)}


def _required(*extras: str) -> set[str]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    deps = project["dependencies"] + [
        d for e in extras for d in project["optional-dependencies"][e]
    ]
    return {re.split(r"[<>=!~;\[ ]", d, maxsplit=1)[0].lower() for d in deps}


def test_locks_cover_pyproject():
    # Out of date after a dependency change: see the commands in packaging/release.in.
    assert _required() <= _names("requirements.txt")
    assert _required("browser") | {"pyinstaller", "hatchling"} <= _names("requirements-release.txt")
