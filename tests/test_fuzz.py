"""The parsers on garbage (roadmap 1.1.2, item 6): whatever a hostile or broken site
publishes in DNS, headers or its sitemap, the parser answers and does not crash.

Each strategy mixes real syntax (mechanisms, tags, directives, attributes) with random
text, so the examples reach deep into the parser instead of failing on the first byte.
CI runs a fixed, small set of examples (derandomized: the same every run); for a long
hunt set SUVEREN_FUZZ to the number of examples, e.g. ``SUVEREN_FUZZ=20000 pytest
tests/test_fuzz.py``.
"""

from __future__ import annotations

import asyncio
import os

import httpx
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from suveren import crawl, mailsec, websec
from suveren.checks import Check, Status

LONG = int(os.environ.get("SUVEREN_FUZZ", "0"))
settings.register_profile(
    "suveren",
    max_examples=LONG or 200,
    derandomize=not LONG,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("suveren")

# Characters that break parsers: separators, quotes, brackets, controls, non-ASCII.
NASTY = st.sampled_from(
    [*";:=,.-_/!*' \"\t\r\n\x00\\%[]{}()<>@#?&+~|^`$", "ё", "Ⅻ", "\u200b", "\ufeff", "𝕏"]
)
JUNK = st.text(alphabet=st.one_of(NASTY, st.characters()), max_size=40)
WORD = st.text(alphabet=st.characters(codec="ascii", categories=("L", "N")), max_size=12)
HOST = st.builds(".".join, st.lists(WORD, min_size=1, max_size=4))


def joined(tokens: st.SearchStrategy[str], sep: str = " ") -> st.SearchStrategy[str]:
    return st.lists(st.one_of(tokens, JUNK), max_size=12).map(sep.join)


# --- SPF ------------------------------------------------------------------------------

SPF_TOKEN = st.one_of(
    st.builds(
        lambda q, m, v: f"{q}{m}{v}",
        st.sampled_from(["", "+", "-", "~", "?", "!"]),
        st.sampled_from(["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists", "redirect"]),
        st.one_of(
            st.just(""), st.builds(lambda s, h: s + h, st.sampled_from([":", "=", "/"]), HOST)
        ),
    ),
    st.builds(lambda a, b: f"ip4:{a}/{b}", HOST, st.integers(-5, 300)),
)
SPF = st.builds(
    lambda v, rest: v + rest, st.sampled_from(["v=spf1 ", "V=SPF1 ", ""]), joined(SPF_TOKEN)
)


@given(SPF)
def test_parse_spf_never_crashes(record):
    spf = mailsec.parse_spf(record)
    assert spf.lookups >= 0
    assert spf.all in (None, "+", "-", "~", "?")


class GarbageResolver:
    """Answers every TXT query with garbage SPF, other queries with nothing."""

    kind = "fuzz"

    def __init__(self, data: st.DataObject) -> None:
        self.data = data

    async def resolve(self, name: str, rtype: str) -> list[str]:
        if rtype == "TXT":
            return self.data.draw(st.lists(SPF, max_size=3))
        return self.data.draw(st.lists(st.one_of(HOST, JUNK), max_size=2))


@given(st.data())
def test_spf_walk_and_check_never_crash(data):
    # The include/redirect walk over garbage records, then the verdict on what it found.
    result = asyncio.run(mailsec.check_spf(GarbageResolver(data), "example.ru"))
    facts = mailsec.MailFacts("example.ru", True, result, None, 0, [])
    assert isinstance(mailsec.spf_check(facts), Check)


# --- DMARC ----------------------------------------------------------------------------

DMARC_TAG = st.builds(
    lambda k, sep, v: f"{k}{sep}{v}",
    st.sampled_from(["v", "V", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "x"]),
    st.sampled_from(["=", " = ", "", "=="]),
    st.one_of(
        st.sampled_from(["DMARC1", "dmarc1", "none", "quarantine", "reject", "100", "-1", "1e9"]),
        st.builds(lambda u, h: f"mailto:{u}@{h}", WORD, HOST),
        st.builds(lambda h: f"https://{h}/r", HOST),
        JUNK,
    ),
)
DMARC = joined(DMARC_TAG, ";")


@given(DMARC, st.booleans())
def test_parse_dmarc_and_its_checks_never_crash(record, receives):
    d = mailsec.parse_dmarc(record)
    assert d.policy in (None, "none", "quarantine", "reject")
    assert 0 <= d.pct <= 100
    assert isinstance(d.report_domains(), list)
    spf = mailsec.SpfResult(None, 0)
    facts = mailsec.MailFacts("example.ru", receives, spf, d, 1, [])
    for check in (mailsec.dmarc_check(facts), mailsec.verdict(facts)):
        assert check.status in Status


@given(
    joined(
        st.sampled_from(
            [
                "version: STSv1",
                "mode: enforce",
                "mode: testing",
                "mx: *.a.ru",
                "max_age: 86400",
                "mx:",
                "mode:",
            ]
        ),
        "\n",
    )
)
def test_mta_sts_policy_never_crashes(policy):
    assert mailsec.parse_mta_sts_mode(policy) in (None, "enforce", "testing", "none")
    assert all(isinstance(m, str) for m in mailsec.parse_mta_sts_mx(policy))


# --- CSP ------------------------------------------------------------------------------

CSP_DIRECTIVE = st.builds(
    lambda d, vals: f"{d} {' '.join(vals)}",
    st.sampled_from(
        [
            "default-src",
            "script-src",
            "script-src-elem",
            "object-src",
            "base-uri",
            "frame-ancestors",
            "style-src",
            "upgrade-insecure-requests",
            "report-uri",
            "x",
        ]
    ),
    st.lists(
        st.one_of(
            st.sampled_from(
                [
                    "'self'",
                    "'none'",
                    "'unsafe-inline'",
                    "'unsafe-eval'",
                    "'strict-dynamic'",
                    "'nonce-abc'",
                    "'sha256-xyz'",
                    "*",
                    "https:",
                    "http:",
                    "data:",
                    "blob:",
                ]
            ),
            HOST,
            JUNK,
        ),
        max_size=5,
    ),
)
CSP = joined(CSP_DIRECTIVE, ";")


@given(st.lists(CSP, max_size=3).map(", ".join))
def test_csp_never_crashes(header):
    for policy in websec.csp_policies(header):
        parsed = websec.parse_csp(policy)
        assert all(k == k.lower() for k in parsed)
        assert all(isinstance(w, str) for w in websec.csp_weaknesses(policy))
    w = websec.WebFacts("example.ru", True, {"content-security-policy": header}, [], [], [], None)
    assert isinstance(websec.csp_check(w), Check)


# --- Set-Cookie -----------------------------------------------------------------------

COOKIE_ATTR = st.builds(
    lambda k, v: f"{k}={v}" if v is not None else k,
    st.sampled_from(
        [
            "Path",
            "Domain",
            "Secure",
            "HttpOnly",
            "SameSite",
            "Max-Age",
            "Expires",
            "Partitioned",
        ]
    ),
    st.one_of(
        st.none(),
        st.sampled_from(
            [
                "Lax",
                "Strict",
                "None",
                "0",
                "-1",
                "3600",
                "abc",
                "/",
                "Thu, 01-Jan-1970 00:00:01 GMT",
                "Fri, 31 Dec 9999 23:59:59 GMT",
                "Mon, 99 Foo 2026 25:61:61 GMT",
            ]
        ),
        JUNK,
    ),
)
SET_COOKIE = st.builds(
    lambda name, value, attrs: f"{name}={value}; " + "; ".join(attrs),
    st.one_of(st.sampled_from(["PHPSESSID", "sid", "sbjs_session", "csrftoken", ""]), JUNK),
    JUNK,
    st.lists(st.one_of(COOKIE_ATTR, JUNK), max_size=6),
)


@given(st.lists(st.one_of(SET_COOKIE, JUNK), max_size=5))
def test_set_cookie_never_crashes(lines):
    cookies = [c for c in (websec.parse_set_cookie(line) for line in lines) if c]
    for c in cookies:
        assert c.name and c.name == c.name.strip()
        assert c.same_site is None or c.same_site == c.same_site.lower()
    w = websec.WebFacts("example.ru", True, {}, [], [], cookies, None)
    check = websec.cookies_check(w)
    assert check is None or isinstance(check, Check)


# --- Sitemap --------------------------------------------------------------------------

URL = st.one_of(
    st.builds(
        lambda s, h, p: f"{s}{h}{p}",
        st.sampled_from(["https://", "http://", "ftp://", "//", "", "https://[", "http://[::1"]),
        st.one_of(st.just("example.ru"), st.just("www.example.ru"), HOST, JUNK),
        st.one_of(st.sampled_from(["/", "/contacts", "/order/", "/cart.php", "/a.pdf"]), JUNK),
    ),
    JUNK,
)
SITEMAP = st.builds(
    lambda index, locs: (
        f"<{'sitemapindex' if index else 'urlset'}>"
        + "".join(f"<loc>{u}</loc>" for u in locs)
        + f"</{'sitemapindex' if index else 'urlset'}>"
    ),
    st.booleans(),
    st.lists(URL, max_size=8),
)


@given(st.one_of(SITEMAP, JUNK), st.lists(URL, max_size=3))
def test_sitemap_never_crashes(sitemap, listed):
    robots = "\n".join(f"Sitemap: {u}" for u in listed)

    def handler(request: httpx.Request) -> httpx.Response:
        # A server sends bytes: lone surrogates arrive as invalid UTF-8.
        body = robots if request.url.path == "/robots.txt" else sitemap
        return httpx.Response(200, content=body.encode("utf-8", "surrogatepass"))

    async def go() -> list[str]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await crawl.sitemap_urls(client, "https://example.ru/")

    urls = asyncio.run(go())
    picked = crawl.pick_from_sitemap(urls, "https://example.ru/", set())
    assert all(isinstance(u, str) for u in picked)


@given(st.lists(URL, max_size=10))
def test_pick_from_sitemap_never_crashes(urls):
    assert all(
        isinstance(u, str) for u in crawl.pick_from_sitemap(urls, "https://example.ru/", set())
    )
