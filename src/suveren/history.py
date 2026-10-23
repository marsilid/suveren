"""What changed between two reports of the same site: services and verdicts.

Checks are matched by their stable ID (catalog.py), not by the Russian title, which
may be reworded between versions; reports from before IDs existed fall back to the
title.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from suveren.errors import SuverenError

_RANK = {"ok": 0, "unknown": 1, "warn": 2, "fail": 3}


class NotAReport(SuverenError):
    """The file is JSON, but not a report this version reads."""


def load_report(path: Path) -> dict[str, Any]:
    """A `scan --json` report, or a SuverenError saying why the file is not one. Any
    JSON used to pass: `audit` called {} "no contradictions", `diff` showed every service
    of a real report as removed against it."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SuverenError(f"{path}: не удалось прочитать ({exc})") from exc
    if not (
        isinstance(data, dict)
        and isinstance(data.get("target"), str)
        and isinstance(data.get("dependencies"), list)
    ):
        raise NotAReport(f"{path}: это не отчёт suveren scan --json")
    version = str(data.get("schema_version", "1.0"))
    if version.split(".")[0] != "1":
        raise NotAReport(f"{path}: отчёт в формате {version}, эта версия читает только 1.x")
    return data


def same_site(old: dict[str, Any], new: dict[str, Any]) -> None:
    """Two reports of different sites compare as one site's change: refuse instead."""
    if old["target"] != new["target"]:
        raise SuverenError(
            f"это отчёты разных сайтов: {old['target']} и {new['target']}; сравнивать "
            "можно только проверки одного сайта"
        )


@dataclass(slots=True)
class CheckChange:
    id: str
    title: str
    before: str
    after: str

    @property
    def better(self) -> bool:
        return _RANK.get(self.after, 1) < _RANK.get(self.before, 1)


@dataclass(slots=True)
class Changes:
    since: str  # when the earlier report was made, as it says
    grade: tuple[Any, Any]
    overall: tuple[Any, Any]
    removed: list[tuple[str, str, bool]] = field(default_factory=list)  # category, service, foreign
    added: list[tuple[str, str, bool]] = field(default_factory=list)
    checks: list[CheckChange] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.removed or self.added or self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "since": self.since,
            "grade": list(self.grade),
            "overall_grade": list(self.overall),
            "removed": [{"category": c, "service": s, "foreign": f} for c, s, f in self.removed],
            "added": [{"category": c, "service": s, "foreign": f} for c, s, f in self.added],
            "checks": [
                {"id": c.id, "title": c.title, "before": c.before, "after": c.after}
                for c in self.checks
            ],
        }


def _dep_key(dep: dict[str, Any]) -> tuple[str, str]:
    return dep.get("category_title", dep.get("category", "?")), dep.get("service", "?")


def _check_key(check: dict[str, Any]) -> str:
    return check.get("id") or check.get("title", "?")


def compare(old: dict[str, Any], new: dict[str, Any]) -> Changes:
    """Changes from ``old`` to ``new`` (both as Report.to_dict() gives them)."""
    a_deps = {_dep_key(d): d for d in old.get("dependencies", [])}
    b_deps = {_dep_key(d): d for d in new.get("dependencies", [])}
    changes = Changes(
        since=str(old.get("started_at", "?")),
        grade=(old.get("grade"), new.get("grade")),
        overall=(old.get("overall_grade"), new.get("overall_grade")),
        removed=[
            (k[0], k[1], bool(a_deps[k].get("foreign"))) for k in sorted(a_deps - b_deps.keys())
        ],
        added=[
            (k[0], k[1], bool(b_deps[k].get("foreign"))) for k in sorted(b_deps - a_deps.keys())
        ],
    )
    before = {_check_key(c): c for c in old.get("checks", [])}
    by_title = {c.get("title"): c for c in old.get("checks", [])}
    for c in new.get("checks", []):
        # An old report without IDs: find the check by its title instead.
        prev = before.get(_check_key(c)) or by_title.get(c.get("title"))
        if prev and prev.get("status") != c.get("status"):
            changes.checks.append(
                CheckChange(_check_key(c), c.get("title", ""), prev["status"], c["status"])
            )
    return changes
