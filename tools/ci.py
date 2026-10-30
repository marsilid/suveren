"""Local CI: the steps of .github/workflows/ci.yml, run here before a merge.

While nothing is pushed, GitHub Actions never runs, so this is the only gate. It runs
the same commands as the `test` job, in the same order, with the interpreter that runs
the script, and prints a table at the end. Exit code 1 when any step fails.

    .venv\\Scripts\\python tools/ci.py               # everything
    .venv\\Scripts\\python tools/ci.py --fast        # lint and types only, no tests
    .venv\\Scripts\\python tools/ci.py --no-audit    # skip pip-audit (it needs the network)

What CI does that this cannot: the Python 3.11-3.14 matrix (here only the local version
runs; mypy still checks against 3.11) and the Docker build.
"""

from __future__ import annotations

import argparse
import io
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def steps(fast: bool, audit: bool) -> list[tuple[str, list[list[str]]]]:
    py = [sys.executable, "-m"]
    plan = [
        ("ruff check", [[*py, "ruff", "check", "."]]),
        ("ruff format", [[*py, "ruff", "format", "--check", "."]]),
        ("mypy", [[*py, "mypy"]]),
    ]
    if audit:
        plan.append(("pip-audit", [[*py, "pip_audit", "--skip-editable"]]))
    if not fast:
        plan.append(
            (
                "pytest + coverage",
                [[*py, "coverage", "run", "-m", "pytest", "-q"], [*py, "coverage", "report"]],
            )
        )
        plan.append(("suveren services", [[*py, "suveren", "services"]]))
    return plan


# Steps whose output is only worth reading when they fail.
QUIET = {"suveren services"}


def run(cmd: list[str], env: dict[str, str], *, quiet: bool) -> bool:
    if not quiet:
        return subprocess.run(cmd, cwd=ROOT, env=env).returncode == 0
    done = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8")
    if done.returncode:
        print(done.stdout + done.stderr)
    return done.returncode == 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--fast", action="store_true", help="без тестов")
    parser.add_argument("--no-audit", action="store_true", help="без pip-audit")
    args = parser.parse_args(argv)

    # Piped output on Windows uses the ANSI code page; the summary is in Russian.
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")
    env = {**os.environ, "PYTHONUTF8": "1"}
    print(f"Python {sys.version.split()[0]} ({sys.executable})")
    results: list[tuple[str, bool, float]] = []
    for name, commands in steps(args.fast, not args.no_audit):
        print(f"\n=== {name}", flush=True)
        started = time.monotonic()
        ok = all(run(cmd, env, quiet=name in QUIET) for cmd in commands)
        results.append((name, ok, time.monotonic() - started))

    print("\n=== итог")
    for name, ok, seconds in results:
        print(f"  {'OK  ' if ok else 'FAIL'}  {name:<18} {seconds:6.1f} с")
    failed = [name for name, ok, _ in results if not ok]
    print("всё зелёное" if not failed else f"не прошло: {', '.join(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
