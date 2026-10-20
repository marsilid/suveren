"""Test keys are assembled at run time, so this file itself contains no string that
looks like a real secret (GitHub push protection and scanners would flag it)."""

import asyncio

import httpx

from suveren.checks import Status
from suveren.leaks import find_leaks, inline_scripts, leak_check, mask, scan_scripts


def k(*parts):
    return "".join(parts)


AWS = k("AK", "IA", "Q3EGRT7ZPNWM2K4D")
TELEGRAM = k("6123456789", ":", "AA", "Hq9vXr2Lm8Tz0Kd3Wn5Pb7Yc1Js4Fg6Ue")
GOOGLE = k("AI", "za", "SyB7dE3fG5hJ8kL1mN4pQ6rT9vW2xZ0aC3e")
STRIPE = k("sk", "_live_", "51Hq9vXr2Lm8Tz0Kd3Wn5Pb7")


def test_secrets_are_found_and_masked():
    js = f'const a="{AWS}";fetch("https://api.telegram.org/bot{TELEGRAM}/send");s="{STRIPE}"'
    leaks = find_leaks(js, "/app.js")
    kinds = {x.kind for x in leaks}
    assert kinds == {"ключ доступа AWS", "токен Telegram-бота", "секретный ключ Stripe"}
    assert all(x.secret for x in leaks)
    for x in leaks:
        assert x.masked.count("…") == 1 and len(x.masked) < 10
    assert mask(AWS) == "AKIA…4D"


def test_placeholders_and_lookalikes_are_ignored():
    text = k("AK", "IAXXXXXXXXXXXXXXXX ") + k("sk", "_live_your_key_here_please_1234 ")
    text += "function AIza(){} var token = '123:abc';"
    assert find_leaks(text, "/x.js") == []


def test_public_google_key_is_a_warning_and_a_secret_a_problem():
    public = find_leaks(f'key: "{GOOGLE}"', "/maps.js")
    check = leak_check(public, 3)
    assert check.status is Status.WARN and check.id == "SUV-WEB-009"
    assert GOOGLE not in check.details and "AIza…" in check.details
    secret = find_leaks(AWS, "код страницы главная")
    check = leak_check(secret + public, 3)
    assert check.status is Status.FAIL
    assert "отзовите" in check.recommendation
    assert leak_check([], 7).status is Status.OK


def test_inline_scripts_only_without_src():
    html = f'<script src="/a.js">{AWS}</script><script>var t="{TELEGRAM}"</script>'
    assert TELEGRAM in inline_scripts(html) and AWS not in inline_scripts(html)


def test_scan_reads_own_scripts_and_pages():
    def handler(request):
        if request.url.path == "/static/app.js":
            return httpx.Response(200, text=f'var k="{AWS}"')
        return httpx.Response(404)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await scan_scripts(
                client,
                ["https://site.ru/static/app.js", "https://site.ru/missing.js"],
                [("главная", f"<script>x='{TELEGRAM}'</script>")],
            )

    leaks, sources = asyncio.run(go())
    assert sources == 3
    assert {(x.kind, x.where) for x in leaks} == {
        ("ключ доступа AWS", "site.ru/static/app.js"),
        ("токен Telegram-бота", "код страницы главная"),
    }


def test_region_names_and_trailing_dash():
    assert find_leaks(k("ASIA", "PACIFICSOUTHEAST"), "/x.js") == []
    dashed = k("AI", "za", "SyB7dE3fG5hJ8kL1mN4pQ6rT9vW2xZ0aC3-")
    assert [x.kind for x in find_leaks(f'k="{dashed}"', "/x.js")] == ["ключ Google API"]
