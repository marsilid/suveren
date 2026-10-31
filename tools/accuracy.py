"""Honest accuracy: Suveren's answers against a hand-labelled sample of real sites.

The lab (tests/lab.py) guards against regressions; it can't say how often Suveren is
right on sites nobody wrote for it. This script compares saved reports with labels a
person made by looking at each site, and gives precision and recall with 95% Wilson
intervals, so that "100%" on twelve sites reads as what it is.

    python tools/accuracy.py labels.csv reports/            # table in the terminal
    python tools/accuracy.py labels.csv reports/ --markdown # for docs/accuracy.md

labels.csv (UTF-8, one row per site and check; see docs/accuracy-sample.md):

    site,check,expected,labeller,date,note
    example.ru,SUV-WEB-005,warn,ivanov,2026-11-02,нет HSTS

``expected`` is ok / warn / fail / unknown; a problem is warn or fail. Reports are the
JSON files of `suveren scan --json` (or a batch folder); the site is taken from
"target". Nothing is scanned here: the reports are made beforehand, by the owner.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

STATUSES = ("ok", "warn", "fail", "unknown")
PROBLEM = {"warn", "fail"}
Z95 = 1.959964


def wilson(hits: int, total: int, z: float = Z95) -> tuple[float, float]:
    """95% Wilson score interval of a proportion; (0, 1) when there is no data."""
    if total == 0:
        return 0.0, 1.0
    p = hits / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


@dataclass(slots=True)
class Label:
    site: str
    check: str
    expected: str


class LabelError(ValueError):
    pass


def read_labels(path: Path) -> list[Label]:
    labels = []
    with path.open(encoding="utf-8-sig", newline="") as fh:
        for n, row in enumerate(csv.DictReader(fh), start=2):
            site = (row.get("site") or "").strip().lower()
            check = (row.get("check") or "").strip().upper()
            expected = (row.get("expected") or "").strip().lower()
            if not site or not check.startswith("SUV-") or expected not in STATUSES:
                raise LabelError(f"{path}:{n}: нужны site, check (SUV-...) и expected ({STATUSES})")
            labels.append(Label(site, check, expected))
    return labels


def read_reports(folder: Path) -> dict[str, dict[str, str]]:
    """site -> check ID -> status, from every JSON report in the folder."""
    found: dict[str, dict[str, str]] = {}
    for path in sorted(folder.rglob("*.json")):
        try:
            data = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or "checks" not in data:
            continue
        site = str(data.get("target", "")).lower()
        found[site] = {c.get("id", ""): c.get("status", "") for c in data["checks"]}
    return found


@dataclass(slots=True)
class Row:
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0
    missing: int = 0  # labelled, but the report has no such check (or no report)
    misses: list[str] = field(default_factory=list)


def compare(labels: list[Label], reports: dict[str, dict[str, str]]) -> dict[str, Row]:
    rows: dict[str, Row] = defaultdict(Row)
    for label in labels:
        row = rows[label.check]
        got = reports.get(label.site, {}).get(label.check)
        if got is None:
            row.missing += 1
            continue
        want_problem, got_problem = label.expected in PROBLEM, got in PROBLEM
        if want_problem and got_problem:
            row.tp += 1
        elif want_problem:
            row.fn += 1
            row.misses.append(f"{label.site}: ждали {label.expected}, получили {got}")
        elif got_problem:
            row.fp += 1
            row.misses.append(f"{label.site}: ждали {label.expected}, получили {got}")
        else:
            row.tn += 1
    return dict(sorted(rows.items()))


def _pct(hits: int, total: int) -> str:
    if not total:
        return "—"
    low, high = wilson(hits, total)
    return f"{100 * hits / total:.0f}% ({100 * low:.0f}–{100 * high:.0f}%)"


def markdown(rows: dict[str, Row]) -> str:
    lines = [
        "| Проверка | Нашла | Пропустила | Ложных тревог | Верно «в порядке» | Нет в отчёте "
        "| Полнота (95% ДИ) | Точность (95% ДИ) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for cid, r in rows.items():
        lines.append(
            f"| {cid} | {r.tp} | {r.fn} | {r.fp} | {r.tn} | {r.missing} "
            f"| {_pct(r.tp, r.tp + r.fn)} | {_pct(r.tp, r.tp + r.fp)} |"
        )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Точность Suveren на размеченной выборке.")
    parser.add_argument("labels", type=Path)
    parser.add_argument("reports", type=Path)
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args(argv)
    try:
        labels = read_labels(args.labels)
    except LabelError as exc:
        print(exc, file=sys.stderr)
        return 2
    rows = compare(labels, read_reports(args.reports))
    if args.markdown:
        print(markdown(rows))
        return 0
    for cid, r in rows.items():
        recall, precision = _pct(r.tp, r.tp + r.fn), _pct(r.tp, r.tp + r.fp)
        print(f"{cid:13} полнота {recall:18} точность {precision:18} нет в отчёте {r.missing}")
        for miss in r.misses:
            print(f"    {miss}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
