"""Replays the local golden corpus (tests/golden.py); skipped when there is none."""

import asyncio
import difflib
import json

import golden as corpus
import pytest

SITES = corpus.sites()


@pytest.mark.skipif(not SITES, reason="no local corpus: python tests/golden.py record <site>")
@pytest.mark.parametrize("host", SITES)
def test_site_conclusions_did_not_change(host):
    want = corpus.expected(host)
    got = asyncio.run(corpus.replay(host))
    if got != want:
        diff = difflib.unified_diff(
            json.dumps(want, ensure_ascii=False, indent=1).splitlines(),
            json.dumps(got, ensure_ascii=False, indent=1).splitlines(),
            "было",
            "стало",
            lineterm="",
        )
        pytest.fail(
            f"{host}: выводы проверок изменились. Если так и надо: python tests/golden.py "
            "update\n" + "\n".join(diff)
        )
