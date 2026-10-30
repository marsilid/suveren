import os

# Every check a module produces must be in catalog.py (see suveren.checks.STRICT_IDS).
os.environ["SUVEREN_STRICT_CHECK_IDS"] = "1"

# Tests read the CLI's words, so its output must not depend on the machine: on GitHub
# Actions typer forces colour codes into --help (it reads GITHUB_ACTIONS), and rich
# wraps lines at 80 columns, splitting a long temp path from the words after it.
# Set before suveren and typer are imported: both read this once, at import.
for name in ("GITHUB_ACTIONS", "FORCE_COLOR", "PY_COLORS"):
    os.environ.pop(name, None)
os.environ["COLUMNS"] = "200"
