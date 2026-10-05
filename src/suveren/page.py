"""Minimal HTML structure extraction: links, forms and visible text."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

_SKIP_TEXT = frozenset({"script", "style", "noscript", "template", "svg"})


@dataclass(slots=True)
class Link:
    href: str
    text: str


@dataclass(slots=True)
class FormInput:
    type: str
    name: str
    hint: str  # id, placeholder and aria-label joined, for heuristics
    checked: bool = False


@dataclass(slots=True)
class Form:
    action: str
    inputs: list[FormInput] = field(default_factory=list)
    text: str = ""


@dataclass(slots=True)
class Page:
    links: list[Link] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    text: str = ""


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.page = Page()
        self._text: list[str] = []
        self._skip = 0
        self._link: Link | None = None
        self._form: Form | None = None
        self._form_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag in _SKIP_TEXT:
            self._skip += 1
        elif tag == "a":
            self._link = Link(a.get("href", ""), "")
        elif tag == "form":
            self._form = Form(a.get("action", ""))
            self._form_text = []
        elif tag in ("input", "textarea", "select") and self._form is not None:
            hint = " ".join(a.get(k, "") for k in ("id", "placeholder", "aria-label", "class"))
            self._form.inputs.append(
                FormInput(
                    type=(a.get("type") or ("text" if tag != "select" else "select")).lower(),
                    name=a.get("name", ""),
                    hint=hint,
                    checked="checked" in a,
                )
            )

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TEXT and self._skip:
            self._skip -= 1
        elif tag == "a" and self._link is not None:
            self._link.text = " ".join(self._link.text.split())
            self.page.links.append(self._link)
            self._link = None
        elif tag == "form" and self._form is not None:
            self._form.text = " ".join(" ".join(self._form_text).split())
            self.page.forms.append(self._form)
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self._text.append(data)
        if self._link is not None:
            self._link.text += " " + data
        if self._form is not None:
            self._form_text.append(data)

    def close(self) -> None:
        super().close()
        if self._form is not None:  # unclosed <form>
            self._form.text = " ".join(" ".join(self._form_text).split())
            self.page.forms.append(self._form)
        self.page.text = re.sub(r"\s+", " ", " ".join(self._text)).strip()


def parse_page(html: str) -> Page:
    parser = _Parser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # malformed markup: keep whatever was parsed
        pass
    return parser.page
