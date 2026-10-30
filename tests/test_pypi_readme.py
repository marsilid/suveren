"""tools/pypi_readme.py: the README on PyPI links to the files of the released tag."""

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location("pypi_readme", ROOT / "tools" / "pypi_readme.py")
pr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pr)

RAW = "https://raw.githubusercontent.com/marsilid/suveren/v1.1.0/"
BLOB = "https://github.com/marsilid/suveren/blob/v1.1.0/"


def test_images_go_to_raw_files_and_documents_to_github():
    text = (
        "![demo](docs/demo.svg) see [guide](docs/guide.md#ci) and [license](./LICENSE)\n"
        '<source media="(prefers-color-scheme: dark)" srcset="docs/report-dark.png">\n'
        '<img alt="report" src="docs/report-light.png">\n'
    )
    out = pr.absolute(text, "v1.1.0")
    assert f"![demo]({RAW}docs/demo.svg)" in out
    assert f"[guide]({BLOB}docs/guide.md#ci)" in out
    assert f"[license]({BLOB}LICENSE)" in out
    assert f'srcset="{RAW}docs/report-dark.png"' in out
    assert f'src="{RAW}docs/report-light.png"' in out


def test_web_links_and_anchors_stay():
    text = (
        "[CI](https://github.com/marsilid/suveren/actions) [up](#install) "
        "[mail](mailto:a@example.com) ![badge](https://img.shields.io/badge/x-y-blue)"
    )
    assert pr.absolute(text, "v1.1.0") == text


def test_the_real_readmes_have_no_relative_link_left():
    for name in ("README.md", "README.en.md"):
        out = pr.absolute((ROOT / name).read_text(encoding="utf-8"), "v1.1.0")
        targets = re.findall(r'(?:\]\(|\b(?:src|srcset)=")([^)"\s]+)', out)
        assert targets
        relative = [t for t in targets if not re.match(r"https?:|#|mailto:", t)]
        assert relative == [], name
