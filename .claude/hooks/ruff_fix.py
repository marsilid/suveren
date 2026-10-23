"""Claude Code PostToolUse hook: format and fix a Python file right after it is edited.

Reads the hook event from stdin, runs ``ruff check --fix`` and ``ruff format`` on the
edited file, and reports what ruff could not fix on stderr with exit code 2, so Claude
sees it at once instead of at the end of the task. Other files are left alone.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUFF = Path(sys.executable).with_name("ruff.exe" if sys.platform == "win32" else "ruff")


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    path = (event.get("tool_input") or {}).get("file_path") or ""
    file = Path(path)
    if file.suffix != ".py" or not file.is_file() or ROOT not in file.resolve().parents:
        return 0
    ruff = str(RUFF) if RUFF.is_file() else "ruff"
    left = subprocess.run(
        [ruff, "check", "--fix", "--quiet", str(file)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    # After the fixes: removing an import can leave blank lines only the formatter tidies.
    subprocess.run([ruff, "format", "--quiet", str(file)], cwd=ROOT, check=False)
    if left.returncode:
        sys.stderr.write(f"ruff: problems left in {file.name} after --fix:\n{left.stdout}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
