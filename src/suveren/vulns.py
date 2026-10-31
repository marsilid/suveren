"""Known-vulnerable versions of popular JavaScript libraries.

Conservative on purpose: a version counts only when it is written out — in the file
name or path (jquery-3.4.1.min.js, /jquery/3.4.1/, jquery@3.4.1) or in the library's
own banner comment at the top of the file (/*! jQuery v3.4.1). Nothing is guessed
from behaviour. A match is a warning, "possibly vulnerable": whether a flaw can be
used depends on how the site calls the library.

The vulnerability list lives in data/vulns.json with NVD ranges and the date checked.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from functools import cache
from importlib.resources import files
from typing import Any

from suveren.checks import Check, Evidence, Status, source

TITLE = "Уязвимые версии библиотек"
GROUP_WEB = "Безопасность сайта"
NVD = "https://nvd.nist.gov/vuln/detail/"

_V = r"(\d+\.\d+(?:\.\d+)?)"
# (library, pattern over a script URL); the version is group 1.
# The library name must not be glued to another word: "ui-bootstrap", "restangular"
# and "angular-moment" are other projects.
_B = r"(?<![\w-])"
_URL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (lib, re.compile(p, re.I))
    for lib, p in (
        ("jquery-ui", rf"{_B}jquery[-.]?ui[-./@]v?{_V}(?:[./-]|$)"),
        ("jquery-ui", rf"/jqueryui/{_V}/"),
        ("jquery", rf"{_B}jquery[-.@]v?{_V}(?:\.min|\.slim)*\.js"),
        ("jquery", rf"/jquery/{_V}/jquery"),
        ("jquery", rf"{_B}jquery@{_V}"),
        ("bootstrap", rf"/(?:twitter-)?bootstrap[/@]v?{_V}/"),
        ("bootstrap", rf"{_B}bootstrap[-.]v?{_V}(?:\.min)?\.js"),
        ("lodash", rf"/lodash(?:\.js)?[/@]{_V}/"),
        ("lodash", rf"{_B}lodash[-.@]{_V}(?:\.min)?\.js"),
        ("moment", rf"/moment(?:\.js)?[/@]{_V}/"),
        ("moment", rf"{_B}moment[-.@]{_V}(?:\.min)?\.js"),
        ("angularjs", rf"/angular(?:\.js|js)?[/@]{_V}/angular"),
        ("angularjs", rf"{_B}angular[-.]{_V}(?:\.min)?\.js"),
    )
)
# Banners the libraries put at the start of their files, right after the comment opener:
# "Requires jQuery v1.7.2" (a plugin) and "Datepicker for Bootstrap v1.9.0" are not them.
_HEAD = r"(?m)(?:/\*\*?!?|^[ \t]*\*)[ \t]*(?:@license[ \t]+)?"
_BANNERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jquery-ui", re.compile(rf"{_HEAD}jQuery UI\s*-\s*v{_V}")),
    ("jquery", re.compile(rf"{_HEAD}jQuery(?: JavaScript Library)? v{_V}")),
    ("bootstrap", re.compile(rf"{_HEAD}Bootstrap v{_V}")),
    # lodash writes its version as a variable; the file must also name lodash.
    ("lodash", re.compile(rf"(?s)lodash\.com.{{0,3000}}?\bVERSION\s*=\s*['\"]{_V}['\"]")),
    ("moment", re.compile(rf"//! moment\.js\s*\n//! version : {_V}")),
    ("angularjs", re.compile(rf"{_HEAD}AngularJS v{_V}")),
)  # fmt: skip
NAMES = {
    "jquery": "jQuery",
    "jquery-ui": "jQuery UI",
    "bootstrap": "Bootstrap",
    "lodash": "lodash",
    "moment": "Moment.js",
    "angularjs": "AngularJS",
}


@dataclass(frozen=True, slots=True)
class Library:
    name: str  # key in NAMES
    version: str
    where: str


def version_tuple(v: str) -> tuple[int, ...]:
    parts = [int(x) for x in v.split(".")]
    return tuple(parts + [0] * (3 - len(parts)))


def in_range(version: str, ranges: list[list[str | None]]) -> bool:
    v = version_tuple(version)
    for start, end in ranges:
        if (start is None or v >= version_tuple(start)) and (end is None or v < version_tuple(end)):
            return True
    return False


@cache
def _data() -> dict[str, Any]:
    return json.loads(files("suveren").joinpath("data/vulns.json").read_text("utf-8"))


def detect(urls: list[str], heads: dict[str, str]) -> list[Library]:
    """Libraries with an explicit version: from script URLs and from the first lines
    of script files (``heads``: URL -> beginning of the file)."""
    found: list[Library] = []
    for url in urls:
        short = re.sub(r"^https?://", "", url).split("?")[0][:90]
        libs: dict[str, str] = {}
        for lib, rx in _URL_PATTERNS:
            m = rx.search(url)
            # npm scope: "/@fullcalendar/moment@6.1.8/" is a plugin, not Moment.js.
            if m and not url[: m.start()].rsplit("/", 1)[-1].startswith("@"):
                libs.setdefault(lib, m.group(1))
        head = heads.get(url, "")
        for lib, rx in _BANNERS:
            m = rx.search(head)
            if m:
                libs.setdefault(lib, m.group(1))
        if "jquery-ui" in libs and libs.get("jquery") == libs["jquery-ui"]:
            del libs["jquery"]  # "jquery-ui-1.12.1.js" is jQuery UI, not jQuery 1.12.1
        found += [Library(lib, version, short) for lib, version in libs.items()]
    unique: dict[tuple[str, str], Library] = {}
    for item in found:
        unique.setdefault((item.name, item.version), item)
    return list(unique.values())


def known_issues(lib: Library) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    data = _data()
    vulns = [
        v for v in data["vulns"] if v["library"] == lib.name and in_range(lib.version, v["ranges"])
    ]
    eol = next(
        (
            e
            for e in data["end_of_life"]
            if e["library"] == lib.name and in_range(lib.version, e["ranges"])
        ),
        None,
    )
    return vulns, eol


def vuln_check(libs: list[Library]) -> Check:
    check = _verdict(libs)
    # Where each version was read: the script's address (or the page, for a comment).
    check.evidence = [
        Evidence("url", f"{NAMES[x.name]} {x.version}", x.where)
        for x in sorted(libs, key=lambda x: (x.name, version_tuple(x.version)))[:10]
    ]
    check.evidence.append(source(database_source()))
    return check


def database_source() -> str:
    """The built-in list is only as fresh as its last check against NVD."""
    day = date.fromisoformat(_data()["checked"])
    return f"встроенная база Suveren по NVD, сверена {day:%d.%m.%Y}"


def _verdict(libs: list[Library]) -> Check:
    if not libs:
        return Check(
            GROUP_WEB,
            TITLE,
            Status.OK,
            "Библиотек с явно указанной версией (jQuery, Bootstrap, lodash и др.) не найдено.",
        )
    bad: list[str] = []
    fine: list[str] = []
    for lib in sorted(libs, key=lambda x: (x.name, version_tuple(x.version))):
        label = f"{NAMES[lib.name]} {lib.version}"
        vulns, eol = known_issues(lib)
        if not vulns and not eol:
            fine.append(label)
            continue
        issues = [f"{v['id']} ({v['summary']})" for v in vulns]
        if eol:
            issues.append(eol["summary"])
        bad.append(f"{label} в {lib.where}: " + "; ".join(issues))
    if not bad:
        return Check(
            GROUP_WEB,
            TITLE,
            Status.OK,
            f"Известных уязвимостей нет: {', '.join(fine)}.",
        )
    text = "Возможно уязвимы: " + ". ".join(bad) + "."
    if fine:
        text += f" Без известных уязвимостей: {', '.join(fine)}."
    return Check(
        GROUP_WEB,
        TITLE,
        Status.WARN,
        text,
        "Обновите библиотеки до актуальных версий. Можно ли воспользоваться уязвимостью, "
        "зависит от того, как сайт вызывает библиотеку, но обновление снимает вопрос. "
        f"Подробности — по номеру CVE на {NVD}.",
    )
