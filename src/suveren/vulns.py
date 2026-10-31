"""Known-vulnerable versions of popular JavaScript libraries.

Conservative on purpose: a version counts only when it is written out — in the file
name or path (jquery-3.4.1.min.js, /jquery/3.4.1/, jquery@3.4.1) or in the library's
own banner comment at the top of the file (/*! jQuery v3.4.1). Nothing is guessed
from behaviour. A match is a warning, "possibly vulnerable": whether a flaw can be
used depends on how the site calls the library.

Which versions are vulnerable comes from the retire.js database
(https://github.com/RetireJS/retire.js, jsrepository-v4.json): downloaded once a day,
and without the network from the copy in data/retire.json (tools/update_vulns.py).
The evidence names the copy used and its date.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from functools import cache
from importlib.resources import files
from typing import Any

import httpx

from suveren.cache import fetch_cached
from suveren.checks import Check, Evidence, Status, copy_of, source
from suveren.errors import ModuleError
from suveren.utils import plural

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
    """The release numbers of a version; a pre-release suffix ("3.0.0-beta1", "1.9.0b1")
    is dropped. Detected versions are releases, and for a release X, X >= X-beta, so
    "below 3.0.0-beta1" means "below 3.0.0" for them, and so does "at or above"."""
    m = re.match(r"\d+(?:\.\d+)*", v.strip())
    parts = [int(x) for x in m.group(0).split(".")] if m else [0]
    return tuple(parts + [0] * (3 - len(parts)))


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


RETIRE_URL = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json"
)
RETIRE_SITE = "https://github.com/RetireJS/retire.js"
RETIRE_TTL = 24 * 3600
# Our library names -> entries of the retire.js database. A jQuery UI file usually holds
# every widget, so the widget entries (dialog, autocomplete, tooltip) count for it too.
RETIRE_NAMES = {
    "jquery": ("jquery",),
    "jquery-ui": ("jquery-ui", "jquery-ui-dialog", "jquery-ui-autocomplete", "jquery-ui-tooltip"),
    "bootstrap": ("bootstrap",),
    "lodash": ("lodash",),
    "moment": ("moment.js",),
    "angularjs": ("angularjs",),
}
# Flaws that exist only where the library runs on a server (Node.js), not in the copy a
# browser loads: moment loading a locale file from disk by a crafted name.
SERVER_ONLY = frozenset({"CVE-2022-24785", "CVE-2026-17495"})
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_RU = {"low": "низкая", "medium": "средняя", "high": "высокая", "critical": "критическая"}


@dataclass(frozen=True, slots=True)
class Vuln:
    library: str  # key in NAMES
    at_or_above: str | None
    below: str | None
    severity: str
    ids: tuple[str, ...]  # CVE first, then the GitHub advisory or the retire.js number
    summary: str  # in English, as in the database

    @property
    def eol(self) -> bool:
        """retire.js lists "End-of-Life" versions as an entry of their own."""
        return "end-of-life" in self.summary.lower()

    @property
    def label(self) -> str:
        return self.ids[0] if self.ids else "без номера"

    def affects(self, version: str) -> bool:
        v = version_tuple(version)
        if self.at_or_above is not None and v < version_tuple(self.at_or_above):
            return False
        return self.below is None or v < version_tuple(self.below)


@dataclass(slots=True)
class VulnDb:
    vulns: dict[str, list[Vuln]]
    source: str  # for the evidence: which copy and its date


def parse_retire(data: dict[str, Any]) -> dict[str, list[Vuln]]:
    """Entries for our libraries from a retire.js database (whole or the built-in copy).
    KeyError or ValueError when it is not one."""
    out: dict[str, list[Vuln]] = {}
    for lib, keys in RETIRE_NAMES.items():
        found = []
        for key in keys:
            for v in data[key].get("vulnerabilities", []):
                ident = v.get("identifiers", {})
                cves = [str(c) for c in ident.get("CVE", [])]
                if SERVER_ONLY & set(cves):
                    continue
                ghsa = [str(ident["githubID"])] if ident.get("githubID") else []
                if not cves and not ghsa and ident.get("retid"):
                    ghsa = [f"retire.js #{ident['retid']}"]
                at = v.get("atOrAbove")
                found.append(
                    Vuln(
                        lib,
                        str(at) if at is not None else None,
                        str(v["below"]) if v.get("below") is not None else None,
                        str(v.get("severity", "medium")).lower(),
                        tuple(cves + ghsa),
                        str(ident.get("summary", "")),
                    )
                )
        out[lib] = found
    if not any(out.values()):
        raise ValueError("в базе нет уязвимостей ни одной библиотеки")
    return out


def _bundled_raw() -> dict[str, Any]:
    return json.loads(files("suveren").joinpath("data/retire.json").read_text("utf-8"))


@cache
def bundled() -> VulnDb:
    """The copy in the package: what a scan uses when the database does not download."""
    raw = _bundled_raw()
    day = date.fromisoformat(raw["_suveren"]["fetched"])
    return VulnDb(parse_retire(raw), f"база retire.js, встроенная копия от {day:%d.%m.%Y}")


async def load_database(client: httpx.AsyncClient, *, refresh: bool = False) -> VulnDb:
    """Today's retire.js database, or the built-in copy when it does not download."""
    try:
        path, _ = await fetch_cached(
            client, RETIRE_URL, "retire/jsrepository-v4.json", ttl=RETIRE_TTL, refresh=refresh
        )
        vulns = parse_retire(json.loads(path.read_text("utf-8")))
    except (ModuleError, ValueError, KeyError, TypeError, AttributeError):
        db = bundled()
        return VulnDb(db.vulns, db.source + " (свежая база не скачалась)")
    return VulnDb(vulns, copy_of(f"база retire.js, {RETIRE_SITE}", path))


def known_issues(lib: Library, db: VulnDb | None = None) -> list[Vuln]:
    """Entries that cover the version, most severe first."""
    found = [v for v in (db or bundled()).vulns.get(lib.name, []) if v.affects(lib.version)]
    return sorted(found, key=lambda v: (-SEVERITY_RANK.get(v.severity, 2), v.label))


def vuln_check(libs: list[Library], db: VulnDb | None = None) -> Check:
    db = db or bundled()
    check = _verdict(libs, db)
    # Where each version was read: the script's address (or the page, for a comment).
    check.evidence = [
        Evidence("url", f"{NAMES[x.name]} {x.version}", x.where)
        for x in sorted(libs, key=lambda x: (x.name, version_tuple(x.version)))[:10]
    ]
    check.evidence.append(source(db.source))
    return check


def _issues_text(found: list[Vuln]) -> str:
    vulns = [v for v in found if not v.eol]
    parts = []
    if vulns:
        labels = list(dict.fromkeys(v.label for v in vulns))
        shown = ", ".join(labels[:4]) + (f" и ещё {len(labels) - 4}" if len(labels) > 4 else "")
        worst = SEVERITY_RU.get(vulns[0].severity, vulns[0].severity)
        n = len(labels)
        word = plural(n, "известная уязвимость", "известные уязвимости", "известных уязвимостей")
        parts.append(f"{n} {word}, самая опасная — {worst} ({shown})")
    if any(v.eol for v in found):
        parts.append("версия больше не поддерживается, новые уязвимости в ней не исправят")
    return "; ".join(parts)


def _verdict(libs: list[Library], db: VulnDb) -> Check:
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
        found = known_issues(lib, db)
        if not found:
            fine.append(label)
            continue
        bad.append(f"{label} в {lib.where}: {_issues_text(found)}")
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
        f"Подробности — по номеру CVE на {NVD} или в базе retire.js ({RETIRE_SITE}).",
    )
