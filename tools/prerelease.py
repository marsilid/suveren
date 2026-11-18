"""Before a release: scan ~30 real sites with the code to be released and look for slips.

    python tools/prerelease.py [sites.txt] [--jobs 4] [--full 3]

The tests and the lab are offline; some mistakes show only on real sites and in the
finished files: "ailaba.ru и 1 поддоменов", "оценка не выше b" on the one-page summary
(2026-11-18), found by eye. This run:

1. scans the list with `suveren batch` (the working tree's code, DNS as users have it);
2. scans the first ``--full`` sites once more with every output: HTML, the summary, DOCX,
   SARIF, JSON and the terminal as text;
3. checks every report with `suveren audit` (logic) and tools/report_lint.py (wording);
4. compares grades and statuses with the previous pre-release run, like the nightly one.

Everything goes to ``reports/prerelease/<date-time>/``, the verdict to ``check.md`` there.
Exit code 1 when the audit or the lint found something: look before tagging. A changed
grade is not an error by itself (sites change); read the list and judge.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "reports" / "prerelease"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nightly import compare, load  # noqa: E402
from report_lint import lint  # noqa: E402

from suveren.audit import audit  # noqa: E402


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def read_sites(path: Path) -> list[str]:
    lines = (line.strip() for line in path.read_text(encoding="utf-8").splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def _suveren(args: list[str], *, log: Path | None = None) -> int:
    env = {**os.environ, "PYTHONUTF8": "1", "COLUMNS": "110", "PYTHONPATH": str(ROOT / "src")}
    with open(log, "w", encoding="utf-8") if log else open(os.devnull, "w") as out:
        done = subprocess.run(
            [sys.executable, "-m", "suveren", *args],
            cwd=ROOT, env=env, stdout=out, stderr=subprocess.STDOUT, check=False,
        )  # fmt: skip
    return done.returncode


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "sites", nargs="?", default=str(Path(__file__).with_name("prerelease-sites.txt"))
    )
    parser.add_argument("--jobs", default="4")
    parser.add_argument("--full", type=int, default=3, help="сколько сайтов во всех форматах")
    args = parser.parse_args(argv)

    sites = read_sites(Path(args.sites))
    previous = sorted(p for p in OUT.glob("[!.]*") if p.is_dir()) if OUT.is_dir() else []
    folder = OUT / datetime.now().strftime("%Y-%m-%d-%H%M")
    batch, full = folder / "batch", folder / "full"
    full.mkdir(parents=True, exist_ok=True)
    (folder / "sites.txt").write_text("\n".join(sites) + "\n", encoding="utf-8")

    print(f"batch: {len(sites)} сайтов → {batch}")
    _suveren(["batch", str(folder / "sites.txt"), "--no-open", "-j", args.jobs,
              "--out", str(batch)], log=folder / "batch.txt")  # fmt: skip
    failed = []
    for site in sites[: args.full]:
        print(f"полный скан: {site}")
        outputs = ["-o", f"{site}.html", "--json", f"{site}.json", "--sarif", f"{site}.sarif",
                   "--summary", f"{site}-summary.html", "--docx", f"{site}.docx"]  # fmt: skip
        code = _suveren(
            ["scan", site, "--no-open", *(o if o.startswith("-") else str(full / o)
                                          for o in outputs)],
            log=full / f"{site}-terminal.txt",
        )  # fmt: skip
        if code not in (0, 3, 4):  # 3 and 4 are thresholds, not failures; none are set
            failed.append(f"{site}: код выхода {code}")

    new = load(batch)
    missing = [s for s in sites if s not in new]
    issues = [(site, i) for site, r in sorted(new.items()) for i in audit(r)]
    issues += [(p.stem, i) for p in sorted(full.glob("*.json")) for i in audit(load_one(p))]
    slips = lint([batch, full])
    last = next(
        (p for p in reversed(previous) if p != folder and any((p / "batch").glob("*.json"))),
        None,
    )
    changed = compare(load(last / "batch"), new) if last else []

    head = _git("rev-parse", "--short", "HEAD")
    dirty = " + незакоммиченные правки" if _git("status", "--porcelain", "src") else ""
    text = [
        f"# Проверка перед релизом {folder.name}",
        "",
        f"Код: {head or 'не git'}{dirty}. Сайтов: {len(sites)}, отчётов: {len(new)}.",
        "",
        "## Ошибки в текстах отчётов (tools/report_lint.py)",
        "",
        *([f"- {s.where}: `{s.rule}`: {s.text}" for s in slips] or ["Нет."]),
        "",
        "## Противоречия в отчётах (suveren audit)",
        "",
        *([f"- {s} {i.check} `{i.rule}`: {i.text}" for s, i in issues] or ["Нет."]),
        "",
        "## Не проверились",
        "",
        *([f"- {s}" for s in missing + failed] or ["Все проверились."]),
        "",
        f"## Изменения с прошлой проверки ({last.name if last else 'её нет'})",
        "",
        *(changed or ["Ничего не изменилось." if last else "Сравнивать не с чем."]),
    ]
    (folder / "check.md").write_text("\n".join(text) + "\n", encoding="utf-8")
    verdict = "ЕСТЬ ЧТО ПОСМОТРЕТЬ" if slips or issues or failed else "чисто"
    print(
        f"{folder / 'check.md'}: {verdict} — ошибок в текстах {len(slips)}, противоречий "
        f"{len(issues)}, не проверились {len(missing) + len(failed)}, изменений {len(changed)}"
    )
    return 1 if slips or issues or failed else 0


def load_one(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
