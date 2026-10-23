"""Nightly run: scan a list of real sites, audit the reports, compare with the last run.

    python tools/nightly.py [sites.txt] [--jobs 4] [--profile standard]

Sites and services change while the code does not, so checks drift: a service moves to
another network, a site adds a bot wall, a register changes its format. This run makes
the drift visible: ``reports/nightly/<date>/changes.md`` lists the grades and statuses
that changed since the previous run, and the self-audit of every report. Exit code 1
when the audit finds contradictions, so a scheduler can flag the night.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "reports" / "nightly"


def load(folder: Path) -> dict[str, dict]:
    reports = {}
    for f in sorted(folder.glob("*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "checks" in data:
            reports[data["target"]] = data
    return reports


def incomplete(report: dict) -> str:
    """Why the report's overall grade is incomplete, "" when it is not. Reports before
    schema 1.3 have no "overall_incomplete": the sections that did not run say it."""
    from suveren.advice import MISSED_SECTION

    if "overall_incomplete" in report:
        return "; ".join(report["overall_incomplete"])
    missed = [
        MISSED_SECTION[c["id"]]
        for c in report.get("checks", [])
        if c.get("id") in MISSED_SECTION and c.get("status") == "unknown"
    ]
    return f"не проверены: {', '.join(missed)}" if missed else ""


def compare(old: dict[str, dict], new: dict[str, dict]) -> list[str]:
    """Markdown lines: what changed per site between two runs."""
    lines = []
    for site in sorted(new.keys() | old.keys()):
        a, b = old.get(site), new.get(site)
        if a is None:
            lines.append(f"- **{site}**: новый в списке")
            continue
        if b is None:
            lines.append(f"- **{site}**: не проверен в этот раз")
            continue
        changes = []
        if (a.get("overall_grade"), a.get("overall_score")) != (
            b.get("overall_grade"),
            b.get("overall_score"),
        ):
            grades = (
                f"общая оценка {a.get('overall_grade')} {a.get('overall_score')} → "
                f"{b.get('overall_grade')} {b.get('overall_score')}"
            )
            # A section that did not run takes its problems with it, so the grade goes
            # up (economy.gov.ru timed out: B 77 → B 89). That is not an improvement.
            if gap := incomplete(b) or incomplete(a):
                side = "сейчас" if incomplete(b) else "в прошлый раз"
                grades = f"оценка неполная ({side} {gap}), сравнивать нельзя: " + grades
            changes.append(grades)
        before = {c["id"]: c["status"] for c in a.get("checks", []) if c.get("id")}
        after = {c["id"]: c["status"] for c in b.get("checks", []) if c.get("id")}
        for cid in sorted(before.keys() | after.keys()):
            if before.get(cid) != after.get(cid):
                changes.append(f"{cid} {before.get(cid, '—')} → {after.get(cid, '—')}")
        deps_a = {(d.get("category"), d.get("service")) for d in a.get("dependencies", [])}
        deps_b = {(d.get("category"), d.get("service")) for d in b.get("dependencies", [])}
        changes += [f"+ сервис {s} ({c})" for c, s in sorted(deps_b - deps_a)]
        changes += [f"− сервис {s} ({c})" for c, s in sorted(deps_a - deps_b)]
        if changes:
            lines.append(f"- **{site}**: " + "; ".join(changes))
    return lines


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "sites", nargs="?", default=str(Path(__file__).with_name("nightly-sites.txt"))
    )
    parser.add_argument("--jobs", default="4")
    parser.add_argument("--profile", default="standard")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(ROOT / "src"))
    from suveren.audit import audit

    previous = sorted(p for p in OUT.glob("*") if p.is_dir()) if OUT.is_dir() else []
    folder = OUT / date.today().isoformat()
    subprocess.run(
        [
            sys.executable,
            "-m",
            "suveren",
            "batch",
            args.sites,
            "--no-open",
            "-j",
            args.jobs,
            "-P",
            args.profile,
            "--out",
            str(folder),
        ],
        cwd=ROOT,
        check=False,
    )
    new = load(folder)
    issues = [(site, i) for site, r in new.items() for i in audit(r)]
    last = next((p for p in reversed(previous) if p != folder), None)
    changed = compare(load(last), new) if last else []

    text = [f"# Ночной прогон {folder.name}", "", f"Сайтов проверено: {len(new)}.", ""]
    text += ["## Противоречия в отчётах", ""]
    text += [f"- {s} {i.check} `{i.rule}`: {i.text}" for s, i in issues] or ["Нет."]
    text += ["", f"## Изменения с прошлого прогона ({last.name if last else 'его нет'})", ""]
    text += changed or ["Ничего не изменилось."]
    (folder / "changes.md").write_text("\n".join(text) + "\n", encoding="utf-8")
    print(f"{folder / 'changes.md'}: противоречий {len(issues)}, изменений {len(changed)}")
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
