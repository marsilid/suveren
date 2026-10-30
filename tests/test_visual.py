"""The HTML report looks as it did: light and dark, desktop and phone.

Screenshots differ between machines (fonts), so the baseline lives on this machine in
reports/shots-baseline and the test runs only with SUVEREN_VISUAL=1. To accept a change
on purpose: python tools/report_shots.py, then copy reports/shots to the baseline.
"""

import asyncio
import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "reports" / "shots-baseline"

pytestmark = pytest.mark.skipif(
    os.environ.get("SUVEREN_VISUAL") != "1" or not BASELINE.is_dir(),
    reason="visual test: set SUVEREN_VISUAL=1 and keep a baseline in reports/shots-baseline",
)


def test_report_screenshots_match_the_baseline(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "report_shots", ROOT / "tools" / "report_shots.py"
    )
    shots = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shots)
    asyncio.run(shots.shoot(shots.sample_html(), tmp_path))
    changed = {
        name: share
        for name, share in asyncio.run(shots.compare(tmp_path, BASELINE)).items()
        if share is None or share > shots.TOLERANCE
    }
    assert not changed, f"отчёт выглядит иначе: {changed}"
