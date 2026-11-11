"""A video library's YouTube template in a script is not a YouTube player (redfox0).

His site played RUTUBE, and the report said it embedded YouTube: most likely a player
library's code held "youtube.com/embed/" + id for whichever service a block uses."""

import pytest

from suveren import services as db
from suveren.page import page_code


def _services(html: str) -> set[str]:
    return {s.name for s, _ in db.scan_page(page_code(html, links=False))}


@pytest.mark.parametrize(
    "script",
    [
        'var u = "https://www.youtube.com/embed/" + id;',
        'tpl: "//www.youtube-nocookie.com/embed/{{videoId}}?autoplay=1"',
        "src = `https://youtube.com/embed/${id}`",
        'url: "youtube.com/embed"',
    ],
)
def test_a_template_in_a_script_is_not_a_player(script):
    html = f'<script>{script}</script><iframe src="https://rutube.ru/play/embed/abc"></iframe>'
    assert _services(html) == {"RUTUBE"}


@pytest.mark.parametrize(
    "html",
    [
        '<iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ"></iframe>',
        '<script>player.src = "https://www.youtube.com/embed/dQw4w9WgXcQ";</script>',
        '<script>t.src = "https://www.youtube.com/iframe_api";</script>',
    ],
)
def test_a_real_embed_is_still_found(html):
    assert "YouTube" in _services(html)
