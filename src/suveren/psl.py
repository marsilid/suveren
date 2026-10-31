"""Public Suffix List: where a registrable domain begins.

The list (https://publicsuffix.org, MPL-2.0) is kept in data/public_suffix_list.dat
with both sections. The private one matters for a site builder: mysite.github.io is
its owner's, not GitHub's, so the mail and the subdomains checked are those of
mysite.github.io, never of the platform. Russian site builders that are not in the
list yet are added below. Refresh the copy with ``python tools/update_psl.py``.
"""

from __future__ import annotations

from functools import cache
from importlib.resources import files

# Platforms where every customer gets a subdomain, missing from the list (checked
# 2026-10-31): Тильда, Nethouse, uKit, Taplink, Народ, uCoz, LPmotor, WordPress.com,
# LiveJournal.
SUVEREN_PRIVATE = frozenset(
    {
        "tilda.ws",
        "nethouse.ru",
        "ukit.me",
        "taplink.ws",
        "narod.ru",
        "ucoz.ru",
        "ucoz.net",
        "ucoz.com",
        "my1.ru",
        "at.ua",
        "do.am",
        "3dn.ru",
        "lpmotor.ru",
        "wordpress.com",
        "livejournal.com",
    }
)


def _ascii(name: str) -> str:
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


@cache
def rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """(plain rules, wildcard parents "*.ck" -> "ck", exceptions "!www.ck" -> "www.ck")."""
    text = files("suveren").joinpath("data/public_suffix_list.dat").read_text("utf-8")
    plain: set[str] = set(SUVEREN_PRIVATE)
    wild: set[str] = set()
    exceptions: set[str] = set()
    for line in text.splitlines():
        rule = line.strip().split(" ", 1)[0].lower()
        if not rule or rule.startswith("//"):
            continue
        for form in {rule, ".".join(_ascii(label) for label in rule.split("."))}:
            if form.startswith("!"):
                exceptions.add(form[1:])
            elif form.startswith("*."):
                wild.add(form[2:])
            else:
                plain.add(form)
    return frozenset(plain), frozenset(wild), frozenset(exceptions)


@cache
def public_suffix(domain: str) -> str:
    """The longest public suffix of ``domain`` by the list's algorithm; a name the list
    does not know has its last label as the suffix (the "*" rule)."""
    labels = domain.lower().rstrip(".").split(".")
    plain, wild, exceptions = rules()
    best = labels[-1:]
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exceptions:
            return ".".join(labels[i + 1 :])
        if candidate in plain and len(labels) - i > len(best):
            best = labels[i:]
        parent = ".".join(labels[i + 1 :])
        if i + 1 < len(labels) and parent in wild and len(labels) - i > len(best):
            best = labels[i:]
    return ".".join(best)


def registrable(domain: str) -> str:
    """The suffix plus one label: 'example.co.uk' from 'www.shop.example.co.uk'. A name
    that is itself a public suffix is returned as it is."""
    labels = domain.lower().rstrip(".").split(".")
    size = len(public_suffix(domain).split(".")) + 1
    return ".".join(labels[-size:]) if len(labels) >= size else ".".join(labels)
