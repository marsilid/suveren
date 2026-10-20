"""White-label reports: a studio's name, logo and link instead of Suveren's.

Set by ``--brand-name``, ``--brand-logo`` and ``--brand-url`` or by the environment
variables SUVEREN_BRAND_NAME, SUVEREN_BRAND_LOGO and SUVEREN_BRAND_URL (handy for a
studio that always uses its own). A small "сделано с помощью Suveren" line stays in
the footer: the licence is MIT, and saying so is honest.
"""

from __future__ import annotations

import base64
import mimetypes
import os
from dataclasses import dataclass
from pathlib import Path

from suveren.errors import SuverenError

MAX_LOGO = 512 * 1024
LOGO_TYPES = {"image/png", "image/jpeg", "image/svg+xml", "image/webp", "image/gif"}


@dataclass(frozen=True, slots=True)
class Brand:
    name: str
    logo: str | None = None  # data: URI, embedded so the report stays one file
    url: str | None = None


def _logo(path: Path) -> str:
    if not path.is_file():
        raise SuverenError(f"логотип не найден: {path}")
    kind = mimetypes.guess_type(path.name)[0] or ""
    if path.suffix.lower() == ".svg":
        kind = "image/svg+xml"
    if kind not in LOGO_TYPES:
        raise SuverenError("логотип должен быть PNG, JPEG, SVG, WebP или GIF")
    data = path.read_bytes()
    if len(data) > MAX_LOGO:
        raise SuverenError("логотип больше 512 КБ: уменьшите его, он встраивается в отчёт")
    return f"data:{kind};base64,{base64.b64encode(data).decode('ascii')}"


def brand_from(
    name: str | None = None, logo: Path | None = None, url: str | None = None
) -> Brand | None:
    """The brand from options, falling back to SUVEREN_BRAND_* variables; None if no
    name is given anywhere."""
    name = (name or os.environ.get("SUVEREN_BRAND_NAME") or "").strip()
    if not name:
        if logo or url:
            raise SuverenError("для --brand-logo и --brand-url нужно ещё --brand-name")
        return None
    env_logo = os.environ.get("SUVEREN_BRAND_LOGO")
    logo = logo or (Path(env_logo) if env_logo else None)
    url = url or os.environ.get("SUVEREN_BRAND_URL")
    if url and not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return Brand(name, _logo(logo) if logo else None, url)
