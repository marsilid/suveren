"""Ground-truth lab: synthetic sites with known problems, run through the real checks.

Every case is a small site written for the lab: a home page, headers, cookies, files,
DNS records and a TLS result. Its ``expect`` says what a careful auditor would conclude
from the standard or the law (RFC, OWASP, 152-ФЗ), written before looking at Suveren's
answer. The runner feeds the case to the same code `suveren scan` uses, offline: pages
come from an httpx MockTransport, DNS from a fake resolver, TLS from the case.

    python tests/lab.py              # accuracy table per check
    python tests/lab.py --markdown   # the same, for docs/accuracy.md

``test_lab.py`` fails when a result differs from the expectation, except the known
misses in KNOWN, each with the reason; so the table in docs stays honest.
"""

from __future__ import annotations

import asyncio
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from suveren import websec
from suveren.analyze import analyze
from suveren.checks import Check, Status
from suveren.collect import Collector, Facts, NetInfo
from suveren.compliance import run_compliance
from suveren.crawl import DEFAULT_PAGES, fetch_pages, pick_from_sitemap, pick_links, sitemap_urls
from suveren.dnsutil import DnsLookupError
from suveren.mailsec import collect_mail
from suveren.mailsec import evaluate as mail_checks
from suveren.page import parse_page
from suveren.websec import TlsInfo, run_web_checks

NOW = datetime.now(UTC)
POSITIVE = {Status.WARN.value, Status.FAIL.value}

# Keys are put together at run time, so that no scanner takes this file for a leak.
AWS_KEY = "AKIA" + "Z7QX4M2KD9WPL3T8"
AWS_SECRET = "wJalr" + "XUtnFEMI/K7MDENG/bPxRfiCY" + "Zq3x8LmN9p"
GOOGLE_KEY = "AIza" + "SyD3x9Kq7Lm2Pn8Rt4Vw6Yz1Ab5Cd0Ef7Gh"

# --- Building blocks ------------------------------------------------------------------

GOOD_HEADERS = {
    "content-type": "text/html; charset=utf-8",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; "
    "frame-ancestors 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "SAMEORIGIN",
}
SESSION_OK = "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"

FOOTER = (
    '<footer><a href="/privacy">Политика обработки персональных данных</a> '
    '<a href="/consent">Согласие на обработку персональных данных</a></footer>'
)
FORM_OK = """<form action="/lead" method="post">
<input name="name" placeholder="Ваше имя"><input type="tel" name="phone" placeholder="Телефон">
<label><input type="checkbox" name="agree" required> Я даю согласие на обработку
персональных данных в соответствии с <a href="/privacy">политикой</a></label>
<button>Отправить</button></form>"""
FORM_NO_CONSENT = """<form action="/lead" method="post">
<input name="name" placeholder="Ваше имя"><input type="tel" name="phone" placeholder="Телефон">
<button>Перезвоните мне</button></form>"""
FORM_PRECHECKED = """<form action="/lead" method="post">
<input name="name" placeholder="Ваше имя"><input type="tel" name="phone" placeholder="Телефон">
<label><input type="checkbox" name="agree" checked> Я даю согласие на обработку
персональных данных</label><button>Отправить</button></form>"""
# Consent folded into the acceptance of another document: ст. 9 ч. 1 since 01.09.2025.
FORM_BUNDLED = """<form action="/signup" method="post">
<input type="email" name="email" placeholder="E-mail"><input type="tel" name="phone">
<label><input type="checkbox" name="agree" required> Я принимаю условия пользовательского
соглашения и даю согласие на обработку персональных данных</label>
<button>Зарегистрироваться</button></form>"""

POLICY_FULL = (
    """<h1>Политика в отношении обработки персональных данных</h1>
<p>1. Общие положения. Оператор — ООО «Лаборатория», ИНН 7700000000, адрес: 101000, г. Москва,
ул. Тестовая, д. 1. Политика разработана в соответствии с Федеральным законом от 27.07.2006
№ 152-ФЗ «О персональных данных».</p>
<p>2. Цели обработки персональных данных: обработка заявок посетителей сайта, обратная связь,
заключение и исполнение договоров.</p>
<p>3. Правовые основания обработки: согласие субъекта персональных данных, договор, стороной
которого является субъект, статья 6 Федерального закона № 152-ФЗ.</p>
<p>4. Категории субъектов и перечень обрабатываемых персональных данных: посетители сайта и
клиенты; фамилия, имя, номер телефона, адрес электронной почты.</p>
<p>5. Порядок и условия обработки: сбор, запись, систематизация, накопление, хранение,
уточнение, извлечение, использование, удаление, уничтожение персональных данных
с использованием средств автоматизации и без них.</p>
<p>6. Сроки обработки и хранения: персональные данные хранятся не дольше, чем этого требуют
цели обработки, и не более 3 лет с момента последнего обращения. Порядок уничтожения:
по достижении целей обработки или при отзыве согласия данные уничтожаются в течение 30 дней.</p>
<p>7. Права субъекта персональных данных: получать сведения об обработке, требовать уточнения,
блокирования или уничтожения данных, отозвать согласие на обработку.</p>
<p>8. Порядок направления запросов: запрос или отзыв согласия направляется оператору на адрес
privacy@lab.example или по почте по адресу оператора.</p>
<p>9. Меры по обеспечению безопасности персональных данных: оператор принимает правовые,
организационные и технические меры защиты в соответствии со статьей 19 Закона: назначен
ответственный за организацию обработки, применяются средства защиты информации, ведется
учет машинных носителей, проводится внутренний контроль.</p>
<p>10. Сведения о реализуемых требованиях к защите персональных данных опубликованы в этом
документе. Оператор не осуществляет трансграничную передачу персональных данных.</p>
<p>11. Файлы cookie: сайт использует файлы cookie и сервисы веб-аналитики, чтобы считать
посещения; посетитель может отключить cookie в настройках браузера.</p>
"""
    + "<p>Дополнительные положения. "
    + "Текст раздела. " * 120
    + "</p>"
)
POLICY_STUB = """<h1>Политика конфиденциальности</h1>
<p>Мы уважаем вашу конфиденциальность и бережно относимся к вашим данным. Мы используем
данные только для улучшения сервиса. По вопросам пишите на info@lab.example.</p>"""
CONSENT_DOC = """<h1>Согласие на обработку персональных данных</h1>
<p>Я, субъект персональных данных, даю согласие ООО «Лаборатория» на обработку моих
персональных данных: имени и номера телефона, в целях обработки заявки.</p>"""

GA = (
    '<script async src="https://www.googletagmanager.com/gtag/js?id=G-LAB1234"></script>'
    "<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}"
    "gtag('js',new Date());gtag('config','G-LAB1234');</script>"
)
COOKIE_BANNER = (
    '<div class="cookie-banner">Мы используем файлы cookie. Продолжая пользоваться сайтом, '
    "вы соглашаетесь с их использованием. <button>Принять</button></div>"
)


# A real site has a menu and some text: a near-empty page with scripts is taken for a
# shell built by JavaScript and not judged (collect.page_problem).
NAV = "<nav>" + "".join(
    f'<a href="/{p}">{t}</a> '
    for p, t in [
        ("about", "О компании"), ("services", "Услуги"), ("prices", "Цены"),
        ("projects", "Проекты"), ("team", "Команда"), ("news", "Новости"),
        ("blog", "Блог"), ("jobs", "Вакансии"), ("faq", "Вопросы"), ("contacts", "Контакты"),
    ]
) + "</nav>"  # fmt: skip
ABOUT = (
    "<p>Лаборатория делает сайты и мобильные приложения для малого бизнеса с 2015 года. "
    "Мы проектируем интерфейсы, пишем код, настраиваем хостинг и сопровождаем проекты после "
    "запуска. Среди клиентов — магазины, клиники, школы и службы доставки в разных городах. "
    "Оставьте заявку, и менеджер перезвонит в течение рабочего дня, чтобы обсудить задачу, "
    "сроки и бюджет. Первая консультация бесплатна. Работаем по договору, с актами и "
    "гарантией на результат. Офис находится в Москве, но мы работаем со всей страной.</p>"
)


def page(body: str, *, footer: bool = True) -> str:
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Лаборатория</title>'
        f"</head><body>{NAV}<main><h1>Лаборатория</h1>{ABOUT}{body}</main>"
        f"{FOOTER if footer else ''}</body></html>"
    )


def good_tls(host: str) -> TlsInfo:
    return TlsInfo(host, "TLSv1.3", NOW + timedelta(days=200), {"TLS 1.0": False, "TLS 1.1": False})


def good_dns(host: str) -> dict[tuple[str, str], list[str]]:
    return {
        (host, "MX"): ["10 mx.yandex.net."],
        (host, "TXT"): ["v=spf1 include:_spf.yandex.net -all"],
        ("_spf.yandex.net", "TXT"): ["v=spf1 ip4:77.88.0.0/18 ip4:5.45.198.0/23 ~all"],
        (f"_dmarc.{host}", "TXT"): [f"v=DMARC1; p=reject; rua=mailto:dmarc@{host}"],
        (f"mail._domainkey.{host}", "TXT"): ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN"],
        (f"_mta-sts.{host}", "TXT"): ["v=STSv1; id=20261022"],
        (f"_smtp._tls.{host}", "TXT"): [f"v=TLSRPTv1; rua=mailto:tls@{host}"],
    }


MTA_STS_OK = "version: STSv1\nmode: enforce\nmx: mx.yandex.net\nmax_age: 604800\n"


# A DNS record whose lookup times out (put as the value in Case.dns).
NO_ANSWER: list[str] = ["<нет ответа>"]


@dataclass
class Case:
    name: str  # also the host: <name>.lab-suveren.ru
    about: str  # what is broken, in one line
    expect: dict[str, str]  # check ID -> ok / warn / fail / unknown
    html: str = ""
    headers: dict[str, str] = field(default_factory=lambda: dict(GOOD_HEADERS))
    cookies: list[str] = field(default_factory=lambda: [SESSION_OK])
    files: dict[str, str] = field(default_factory=dict)  # path or URL -> body
    hosting: tuple[str, str] = ("Selectel", "RU")
    tls: TlsInfo | None = None  # None: a good certificate
    dns: dict[tuple[str, str], list[str]] | None = None  # changes over good_dns
    mta_sts: str | None = MTA_STS_OK
    http: bool = False  # the site answers over plain HTTP
    # With ``http``: how its HTTPS fails instead of a 404 (httpx.ConnectTimeout, ...).
    https_error: type[httpx.HTTPError] | None = None

    @property
    def host(self) -> str:
        return f"{self.name}.ru"


def site_files(extra: dict[str, str] | None = None) -> dict[str, str]:
    return {"/privacy": page(POLICY_FULL), "/consent": page(CONSENT_DOC), **(extra or {})}


CASES: list[Case] = [
    # --- the reference: everything right --------------------------------------------
    Case(
        "lab-good",
        "всё сделано правильно",
        {
            "SUV-WEB-004": "ok",
            "SUV-WEB-005": "ok",
            "SUV-WEB-006": "ok",
            "SUV-WEB-007": "ok",
            "SUV-WEB-008": "ok",
            "SUV-WEB-009": "ok",
            "SUV-WEB-010": "ok",
            "SUV-PD-001": "ok",
            "SUV-PD-002": "ok",
            "SUV-PD-003": "ok",
            "SUV-PD-006": "ok",
            "SUV-PD-007": "ok",
            "SUV-PD-008": "ok",
            "SUV-PD-011": "ok",
            "SUV-MAIL-001": "ok",
            "SUV-MAIL-002": "ok",
            "SUV-MAIL-003": "ok",
            "SUV-MAIL-004": "ok",
            "SUV-MAIL-005": "ok",
        },
        html=page(FORM_OK + '<script src="/app.js"></script>'),
        files=site_files({"/app.js": "console.log('ok');"}),
    ),
    # --- headers (OWASP Secure Headers, RFC 6797) ------------------------------------
    Case(
        "lab-no-hsts",
        "нет Strict-Transport-Security",
        {"SUV-WEB-005": "warn"},
        html=page(FORM_OK),
        headers={k: v for k, v in GOOD_HEADERS.items() if k != "strict-transport-security"},
        files=site_files(),
    ),
    Case(
        "lab-hsts-day",
        "HSTS на сутки (меньше 180 дней)",
        {"SUV-WEB-005": "warn"},
        html=page(FORM_OK),
        headers={**GOOD_HEADERS, "strict-transport-security": "max-age=86400"},
        files=site_files(),
    ),
    Case(
        "lab-hsts-off",
        "HSTS выключен (max-age=0)",
        {"SUV-WEB-005": "warn"},
        html=page(FORM_OK),
        headers={**GOOD_HEADERS, "strict-transport-security": "max-age=0"},
        files=site_files(),
    ),
    Case(
        "lab-hsts-repeated",
        "HSTS отдаётся несколько раз (после сверки с Mozilla Observatory на bi.zone)",
        {"SUV-WEB-005": "warn"},
        html=page(FORM_OK),
        headers={
            **GOOD_HEADERS,
            # httpx joins repeated headers with ", ", as the browser's network stack does.
            "strict-transport-security": "max-age=15552000;, max-age=31536000, max-age=7200",
        },
        files=site_files(),
    ),
    Case(
        "lab-no-csp",
        "нет Content-Security-Policy, защита от фреймов через X-Frame-Options",
        {"SUV-WEB-004": "warn", "SUV-WEB-006": "ok"},
        html=page(FORM_OK),
        headers={k: v for k, v in GOOD_HEADERS.items() if k != "content-security-policy"},
        files=site_files(),
    ),
    Case(
        "lab-csp-inline",
        "CSP с 'unsafe-inline' в script-src",
        {"SUV-WEB-004": "warn"},
        html=page(FORM_OK),
        headers={
            **GOOD_HEADERS,
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "object-src 'none'",
        },
        files=site_files(),
    ),
    Case(
        "lab-csp-nonce",
        "CSP с nonce и 'unsafe-inline' для старых браузеров: 'unsafe-inline' игнорируется",
        {"SUV-WEB-004": "ok"},
        html=page(FORM_OK),
        headers={
            **GOOD_HEADERS,
            "content-security-policy": "script-src 'nonce-r4nd0m' 'strict-dynamic' "
            "'unsafe-inline' https:; object-src 'none'; base-uri 'none'",
        },
        files=site_files(),
    ),
    Case(
        "lab-csp-wildcard",
        "CSP с script-src * — скрипты откуда угодно",
        {"SUV-WEB-004": "warn"},
        html=page(FORM_OK),
        headers={**GOOD_HEADERS, "content-security-policy": "script-src *; object-src 'none'"},
        files=site_files(),
    ),
    Case(
        "lab-csp-report-only",
        "CSP только в режиме Report-Only: ничего не блокирует",
        {"SUV-WEB-004": "warn"},
        html=page(FORM_OK),
        headers={
            **{k: v for k, v in GOOD_HEADERS.items() if k != "content-security-policy"},
            "content-security-policy-report-only": "script-src 'self'; object-src 'none'",
        },
        files=site_files(),
    ),
    Case(
        "lab-xfo-allow-from",
        "X-Frame-Options: ALLOW-FROM (браузеры его игнорируют), CSP без frame-ancestors",
        {"SUV-WEB-006": "warn"},
        html=page(FORM_OK),
        headers={
            **GOOD_HEADERS,
            "x-frame-options": "ALLOW-FROM https://partner.example",
            "content-security-policy": "default-src 'self'; object-src 'none'",
        },
        files=site_files(),
    ),
    Case(
        "lab-frame-ancestors",
        "нет X-Frame-Options, но есть CSP frame-ancestors: защита есть",
        {"SUV-WEB-006": "ok"},
        html=page(FORM_OK),
        headers={k: v for k, v in GOOD_HEADERS.items() if k != "x-frame-options"},
        files=site_files(),
    ),
    Case(
        "lab-headers-twice",
        "X-Frame-Options и X-Content-Type-Options отдаются дважды (склеиваются через запятую)",
        {"SUV-WEB-006": "ok"},
        html=page(FORM_OK),
        headers={
            **GOOD_HEADERS,
            "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'",
            "x-frame-options": "SAMEORIGIN, SAMEORIGIN",
            "x-content-type-options": "nosniff, nosniff",
        },
        files=site_files(),
    ),
    Case(
        "lab-csp-default-self",
        "CSP default-src 'self' без object-src: object-src берётся из default-src, плагины "
        "только со своего сайта",
        {"SUV-WEB-004": "ok"},
        html=page(FORM_OK),
        headers={**GOOD_HEADERS, "content-security-policy": "default-src 'self'"},
        files=site_files(),
    ),
    Case(
        "lab-frame-ancestors-any",
        "CSP frame-ancestors * без X-Frame-Options: встроить сайт может кто угодно",
        {"SUV-WEB-006": "warn"},
        html=page(FORM_OK),
        headers={
            **{k: v for k, v in GOOD_HEADERS.items() if k != "x-frame-options"},
            "content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors *",
        },
        files=site_files(),
    ),
    Case(
        "lab-csp-two-policies",
        "две CSP: строгая script-src и отдельная frame-ancestors (браузер применяет обе)",
        {"SUV-WEB-004": "ok", "SUV-WEB-006": "ok"},
        html=page(FORM_OK),
        headers={
            **{k: v for k, v in GOOD_HEADERS.items() if k != "x-frame-options"},
            "content-security-policy": "script-src 'self'; object-src 'none', "
            "frame-ancestors 'self'",
        },
        files=site_files(),
    ),
    Case(
        "lab-no-nosniff",
        "нет X-Content-Type-Options",
        {"SUV-WEB-006": "warn"},
        html=page(FORM_OK),
        headers={k: v for k, v in GOOD_HEADERS.items() if k != "x-content-type-options"},
        files=site_files(),
    ),
    Case(
        "lab-cookie-flags",
        "сессионная cookie без Secure и HttpOnly",
        {"SUV-WEB-007": "warn"},
        html=page(FORM_OK),
        cookies=["PHPSESSID=9f8e7d6c5b4a; path=/"],
        files=site_files(),
    ),
    Case(
        "lab-cookie-analytics",
        "только cookie аналитики без HttpOnly: так и задумано, скрипт её читает",
        {"SUV-WEB-007": "ok"},
        html=page(FORM_OK),
        cookies=["_ym_uid=1729600000123456789; Path=/; Secure; Max-Age=31536000"],
        files=site_files(),
    ),
    # --- TLS (RFC 8996, browser validation) ------------------------------------------
    Case(
        "lab-tls-legacy",
        "сервер принимает TLS 1.0 и 1.1",
        {"SUV-WEB-008": "warn"},
        html=page(FORM_OK),
        tls=TlsInfo("x", "TLSv1.3", NOW + timedelta(days=200), {"TLS 1.0": True, "TLS 1.1": True}),
        files=site_files(),
    ),
    Case(
        "lab-tls-expiring",
        "сертификат истекает через 5 дней",
        {"SUV-WEB-008": "fail"},
        html=page(FORM_OK),
        tls=TlsInfo("x", "TLSv1.3", NOW + timedelta(days=5), {"TLS 1.0": False, "TLS 1.1": False}),
        files=site_files(),
    ),
    Case(
        "lab-tls-revoked",
        "OCSP-сервер удостоверяющего центра отвечает, что сертификат отозван (RFC 6960)",
        {"SUV-WEB-008": "fail"},
        html=page(FORM_OK),
        tls=TlsInfo(
            "x",
            "TLSv1.3",
            NOW + timedelta(days=200),
            {"TLS 1.0": False, "TLS 1.1": False},
            revoked=NOW - timedelta(days=3),
        ),
        files=site_files(),
    ),
    Case(
        "lab-tls-wrong-host",
        "сертификат выписан на другое имя",
        {"SUV-WEB-008": "fail"},
        html=page(FORM_OK),
        tls=TlsInfo(
            "x",
            "TLSv1.3",
            NOW + timedelta(days=200),
            {"TLS 1.0": False, "TLS 1.1": False},
            "Hostname mismatch, certificate is not valid for 'lab-tls-wrong-host.ru'.",
        ),
        files=site_files(),
    ),
    # --- code: secrets and libraries --------------------------------------------------
    Case(
        "lab-leak-aws",
        "ключ AWS с секретной частью в собственном скрипте сайта",
        {"SUV-WEB-009": "fail"},
        html=page(FORM_OK + '<script src="/static/app.js"></script>'),
        files=site_files(
            {
                "/static/app.js": f"const s3 = new S3({{accessKeyId: '{AWS_KEY}', "
                f"secretAccessKey: '{AWS_SECRET}', region: 'eu'}});"
            }
        ),
    ),
    Case(
        "lab-leak-aws-id",
        "только идентификатор ключа AWS, без секретной части: сам по себе ничего не открывает",
        {"SUV-WEB-009": "warn"},
        html=page(FORM_OK + '<script src="/static/app.js"></script>'),
        files=site_files({"/static/app.js": f"const bucketOwner = '{AWS_KEY}';"}),
    ),
    Case(
        "lab-pem-header",
        "библиотека шифрования (как JSEncrypt) со строкой заголовка PEM, но без ключа",
        {"SUV-WEB-009": "ok"},
        html=page(FORM_OK + '<script src="/static/jsencrypt.js"></script>'),
        files=site_files(
            {
                "/static/jsencrypt.js": 'var h="-----BEGIN RSA PRIVATE KEY-----\n";'
                'function pem(b){return h+b+"\n-----END RSA PRIVATE KEY-----";}'
            }
        ),
    ),
    Case(
        "lab-leak-google",
        "ключ Google Maps в коде страницы: публичный по задумке, но должен быть ограничен",
        {"SUV-WEB-009": "warn"},
        html=page(
            FORM_OK + f'<script>window.mapsKey = "{GOOGLE_KEY}"; initMap(window.mapsKey);</script>'
        ),
        files=site_files(),
    ),
    Case(
        "lab-leak-placeholder",
        "в коде пример ключа из документации, не настоящий",
        {"SUV-WEB-009": "ok"},
        html=page(FORM_OK + '<script>const key = "AKIAIOSFODNN7EXAMPLE";</script>'),
        files=site_files(),
    ),
    Case(
        "lab-jquery-old",
        "jQuery 1.12.4 с CDN (CVE-2015-9251, CVE-2019-11358, CVE-2020-11022/11023)",
        {"SUV-WEB-010": "warn", "SUV-WEB-003": "warn"},
        html=page(
            FORM_OK
            + '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js">'
            "</script>"
        ),
        files=site_files(),
    ),
    Case(
        "lab-jquery-new",
        "jQuery 3.7.1 с CDN и integrity",
        {"SUV-WEB-010": "ok", "SUV-WEB-003": "ok"},
        html=page(
            FORM_OK + '<script src="https://code.jquery.com/jquery-3.7.1.min.js" '
            'integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=" '
            'crossorigin="anonymous"></script>'
        ),
        files=site_files(),
    ),
    Case(
        "lab-moment-old",
        "moment.js 2.15.1 на своём сервере (CVE-2017-18214)",
        {"SUV-WEB-010": "warn"},
        html=page(FORM_OK + '<script src="/js/moment-2.15.1.min.js"></script>'),
        files=site_files({"/js/moment-2.15.1.min.js": "//! moment.js\n//! version : 2.15.1\n"}),
    ),
    # --- 152-ФЗ ----------------------------------------------------------------------
    Case(
        "lab-no-policy",
        "нет политики обработки персональных данных и ссылок на неё",
        {"SUV-PD-001": "warn"},  # FAIL only in --browser mode: the footer may be scripted
        html=page(FORM_PRECHECKED, footer=False),
        files={},
    ),
    Case(
        "lab-policy-404",
        "ссылка на политику ведёт на несуществующую страницу (404)",
        {"SUV-PD-001": "warn"},
        html=page(FORM_OK),
        files={"/consent": page(CONSENT_DOC)},
    ),
    Case(
        "lab-policy-stub",
        "«политика» из трёх предложений без обязательных разделов",
        {"SUV-PD-001": "ok", "SUV-PD-002": "warn"},
        html=page(FORM_OK),
        files=site_files({"/privacy": page(POLICY_STUB)}),
    ),
    Case(
        "lab-form-no-consent",
        "форма заявки (имя, телефон) без согласия",
        {"SUV-PD-003": "warn"},
        html=page(FORM_NO_CONSENT),
        files=site_files(),
    ),
    Case(
        "lab-form-in-sitemap",
        "форма без согласия только на странице «Контакты», на которую главная не ссылается",
        {"SUV-PD-003": "warn"},
        html=page("<p>Звоните нам.</p>"),
        files=site_files(
            {
                "/robots.txt": "User-agent: *\nSitemap: https://lab-form-in-sitemap.ru/sitemap.xml\n",
                "/sitemap.xml": '<?xml version="1.0"?><urlset>'
                "<url><loc>https://lab-form-in-sitemap.ru/blog/news-1</loc></url>"
                "<url><loc>https://lab-form-in-sitemap.ru/kontakty</loc></url></urlset>",
                "/kontakty": page(FORM_NO_CONSENT),
            }
        ),
    ),
    Case(
        "lab-form-prechecked",
        "галочка согласия стоит заранее",
        {"SUV-PD-003": "warn"},
        html=page(FORM_PRECHECKED),
        files=site_files(),
    ),
    Case(
        "lab-consent-bundled",
        "согласие спрятано в принятии пользовательского соглашения (ст. 9 ч. 1)",
        {"SUV-PD-004": "warn"},
        html=page(FORM_BUNDLED),
        files=site_files(),
    ),
    Case(
        "lab-ga-no-banner",
        "Google Analytics без уведомления о cookies и без уведомления о трансграничной передаче",
        {"SUV-PD-005": "warn", "SUV-PD-006": "warn"},
        html=page(FORM_OK + GA),
        files=site_files(),
    ),
    Case(
        "lab-ga-banner",
        "Google Analytics с баннером cookies: баннер есть, передача за рубеж остаётся",
        {"SUV-PD-005": "ok", "SUV-PD-006": "warn"},
        html=page(FORM_OK + GA + COOKIE_BANNER),
        files=site_files(),
    ),
    # --- the policy against the site (152-ФЗ, ст. 18.1 ч. 1 п. 2) ---------------------
    Case(
        "lab-policy-copied",
        "политика скопирована с другого сайта: говорит о other-shop.ru, этот сайт не называет",
        {"SUV-PD-002": "ok", "SUV-PD-011": "warn"},
        html=page(FORM_OK),
        files=site_files(
            {
                "/privacy": page(
                    "<p>Настоящая Политика применяется ко всей информации, которую сайт "
                    "www.other-shop.ru может получить о посетителе.</p>" + POLICY_FULL
                )
            }
        ),
    ),
    Case(
        "lab-policy-two-sites",
        "одна политика на два сайта компании, этот среди них: не копия",
        {"SUV-PD-011": "ok"},
        html=page(FORM_OK),
        files=site_files(
            {
                "/privacy": page(
                    "<p>Политика действует на сайтах lab-policy-two-sites.ru и "
                    "www.brand-shop.ru.</p>" + POLICY_FULL
                )
            }
        ),
    ),
    Case(
        "lab-policy-other-inn",
        "в реквизитах сайта ИНН 7700000016, в политике оператор с ИНН 7700000023",
        {"SUV-PD-011": "warn"},
        html=page(FORM_OK + "<p>ООО «Лаборатория», ИНН 7700000016</p>"),
        files=site_files(
            {"/privacy": page(POLICY_FULL.replace("ИНН 7700000000", "ИНН 7700000023"))}
        ),
    ),
    Case(
        "lab-requisites-inn-kpp",
        "реквизиты «ИНН/КПП: 7700000016/770001001», в политике оператор с другим ИНН",
        {"SUV-PD-011": "warn"},
        html=page(FORM_OK + "<p>ООО «Лаборатория», ИНН/КПП: 7700000016/770001001</p>"),
        files=site_files(
            {"/privacy": page(POLICY_FULL.replace("ИНН 7700000000", "ИНН 7700000023"))}
        ),
    ),
    Case(
        "lab-policy-no-email",
        "форма просит e-mail, а в перечне данных политики его нет",
        {"SUV-PD-011": "warn"},
        html=page(
            FORM_OK.replace(
                'placeholder="Телефон">', 'placeholder="Телефон"><input type="email" name="email">'
            )
        ),
        files=site_files(
            {
                "/privacy": page(
                    POLICY_FULL.replace("номер телефона, адрес электронной почты", "номер телефона")
                )
            }
        ),
    ),
    Case(
        "lab-policy-no-cookies",
        "на сайте Google Analytics, а политика о cookies молчит",
        {"SUV-PD-011": "warn"},
        html=page(FORM_OK + GA + COOKIE_BANNER),
        files=site_files({"/privacy": page(POLICY_FULL.split("<p>11. Файлы cookie")[0])}),
    ),
    Case(
        "lab-policy-lies",
        "политика: «не передаём третьим лицам», а на сайте Google Analytics",
        {"SUV-PD-011": "warn"},
        html=page(FORM_OK + GA + COOKIE_BANNER),
        files=site_files(
            {
                "/privacy": page(
                    POLICY_FULL + "<p>Оператор не передает персональные данные третьим лицам.</p>"
                )
            }
        ),
    ),
    Case(
        "lab-hosting-abroad",
        "сайт с формой заявки на сервере в Германии (Hetzner)",
        {"SUV-PD-007": "fail"},
        html=page(FORM_OK),
        hosting=("Hetzner Online GmbH", "DE"),
        files=site_files(),
    ),
    Case(
        "lab-hosting-abroad-crm-form",
        "сайт в Германии, но заявки уходят в российскую CRM: база, вероятно, там",
        {"SUV-PD-007": "warn"},
        html=page(FORM_OK.replace('action="/lead"', 'action="https://crm.bitrix24.ru/lead"')),
        hosting=("Hetzner Online GmbH", "DE"),
        files=site_files(),
    ),
    # --- mail (RFC 7208, 7489, 8461) -------------------------------------------------
    Case(
        "lab-spf-plus-all",
        "SPF +all: отправлять от имени домена может кто угодно",
        {"SUV-MAIL-002": "fail"},
        html=page(FORM_OK),
        files=site_files(),
        dns={("lab-spf-plus-all.ru", "TXT"): ["v=spf1 include:_spf.yandex.net +all"]},
    ),
    Case(
        "lab-spf-broken-include",
        "SPF include на домен без SPF-записи: permerror (RFC 7208, 5.2)",
        {"SUV-MAIL-002": "fail"},
        html=page(FORM_OK),
        files=site_files(),
        dns={
            ("lab-spf-broken-include.ru", "TXT"): [
                "v=spf1 include:_spf.yandex.net include:spf.gone.example -all"
            ]
        },
    ),
    Case(
        "lab-dmarc-none",
        "DMARC p=none: поддельные письма доходят, на вопрос «можно ли подделать» ответ «да»",
        {"SUV-MAIL-001": "fail", "SUV-MAIL-003": "warn"},
        html=page(FORM_OK),
        files=site_files(),
        dns={("_dmarc.lab-dmarc-none.ru", "TXT"): ["v=DMARC1; p=none"]},
    ),
    Case(
        "lab-dmarc-lowercase",
        "v=dmarc1 строчными: по RFC 7489 (6.3) значение должно точно совпадать с DMARC1",
        {"SUV-MAIL-003": "warn"},
        html=page(FORM_OK),
        files=site_files(),
        dns={
            ("_dmarc.lab-dmarc-lowercase.ru", "TXT"): [
                "v=dmarc1; p=reject; rua=mailto:dmarc@lab-dmarc-lowercase.ru"
            ]
        },
    ),
    Case(
        "lab-no-dmarc",
        "нет DMARC: письмо от имени домена может прийти от кого угодно",
        {"SUV-MAIL-001": "fail", "SUV-MAIL-003": "fail"},
        html=page(FORM_OK),
        files=site_files(),
        dns={("_dmarc.lab-no-dmarc.ru", "TXT"): []},
    ),
    Case(
        "lab-mta-sts-mx",
        "MTA-STS enforce, но MX нет в политике: Gmail не доставит письма",
        {"SUV-MAIL-005": "fail"},
        html=page(FORM_OK),
        files=site_files(),
        mta_sts="version: STSv1\nmode: enforce\nmx: mx.old-provider.example\nmax_age: 604800\n",
    ),
    # --- harder cases, added after the first round ------------------------------------
    Case(
        "lab-csp-meta",
        "строгая CSP только в <meta>; frame-ancestors в <meta> не действует, X-Frame-Options нет",
        {"SUV-WEB-004": "ok", "SUV-WEB-006": "warn"},
        html=page(FORM_OK).replace(
            "<head>",
            '<head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; '
            "script-src 'self'; object-src 'none'; frame-ancestors 'self'\">",
        ),
        headers={
            k: v
            for k, v in GOOD_HEADERS.items()
            if k not in ("content-security-policy", "x-frame-options")
        },
        files=site_files(),
    ),
    Case(
        "lab-cookie-samesite-none",
        "сессионная cookie с SameSite=None без Secure: браузер её отвергнет",
        {"SUV-WEB-007": "warn"},
        html=page(FORM_OK),
        cookies=["session=8c1f2e; Path=/; HttpOnly; SameSite=None"],
        files=site_files(),
    ),
    Case(
        "lab-jquery-banner",
        "старый jQuery без версии в адресе: версия только в заголовке файла",
        {"SUV-WEB-010": "warn"},
        html=page(FORM_OK + '<script src="/js/vendor/jquery.min.js"></script>'),
        files=site_files(
            {
                "/js/vendor/jquery.min.js": "/*! jQuery v1.11.0 | (c) 2005, 2014 jQuery "
                "Foundation, Inc. | jquery.org/license */\n!function(a,b){}(window);"
            }
        ),
    ),
    Case(
        "lab-leak-telegram",
        "токен Telegram-бота во встроенном скрипте (уведомления о заявках)",
        {"SUV-WEB-009": "fail"},
        html=page(
            FORM_OK
            + "<script>fetch('https://api.telegram.org/bot"
            + "7012345678:AA"
            + "Fq9xV2mL7kP3sT8wY1zB4cD6eG0hJ5nR9"
            + "/sendMessage', {method: 'POST'});</script>"
        ),
        files=site_files(),
    ),
    Case(
        "lab-tls-mintsifry",
        "сертификат НУЦ Минцифры: браузеры без российского корня покажут ошибку",
        {"SUV-WEB-008": "warn"},
        html=page(FORM_OK),
        tls=TlsInfo(
            "x",
            "TLSv1.3",
            NOW + timedelta(days=200),
            {"TLS 1.0": False, "TLS 1.1": False},
            "self-signed certificate in certificate chain",
            "CN=Russian Trusted Sub CA,O=The Ministry of Digital Development,C=RU",
        ),
        files=site_files(),
    ),
    Case(
        "lab-metrika-no-banner",
        "Яндекс Метрика без уведомления о cookies; передачи за рубеж нет",
        {"SUV-PD-005": "warn", "SUV-PD-006": "ok"},
        html=page(
            FORM_OK + '<script src="https://mc.yandex.ru/metrika/tag.js"></script>'
            "<script>ym(98765432, 'init', {clickmap: true});</script>"
        ),
        files=site_files(),
    ),
    Case(
        "lab-consent-below-form",
        "согласие фразой «нажимая кнопку, вы соглашаетесь» под формой, без галочки",
        {"SUV-PD-003": "warn"},
        html=page(
            FORM_NO_CONSENT + "<p>Нажимая кнопку «Перезвоните мне», вы соглашаетесь "
            'с <a href="/privacy">политикой обработки персональных данных</a>.</p>'
        ),
        files=site_files(),
    ),
    Case(
        "lab-consent-provided",
        "в форме фраза «вы предоставляете согласие на обработку» (cloudpayments.ru), без галочки",
        {"SUV-PD-003": "ok"},
        html=page(
            '<form action="/lead"><input type="tel" name="phone" placeholder="Телефон">'
            "<button>Отправить</button><p>Нажимая «Отправить», вы предоставляете Согласие "
            "на обработку персональных данных в соответствии с Политикой</p></form>"
        ),
        files=site_files(),
    ),
    Case(
        "lab-search-only",
        "на сайте только поиск по городам и билетам: персональные данные не собираются",
        {"SUV-PD-003": "unknown"},
        html=page(
            '<form action="/search"><input name="city_name_from" placeholder="Откуда">'
            '<input name="city_name_to" placeholder="Куда"><input name="date" type="date">'
            "<button>Найти</button></form>"
        ),
        files=site_files(),
    ),
    Case(
        "lab-newsletter-box",
        "в форме только галочка «согласен получать рассылку»: это не согласие на обработку",
        {"SUV-PD-003": "warn"},
        html=page(
            '<form action="/lead"><input name="name" placeholder="Ваше имя">'
            '<input type="tel" name="phone"><label><input type="checkbox" name="news"> '
            "Согласен получать рассылку</label><button>Отправить</button></form>"
        ),
        files=site_files(),
    ),
    Case(
        "lab-marketing-prechecked",
        "согласие на обработку без галочки, а заранее отмечена подписка на новости",
        {"SUV-PD-003": "ok"},
        html=page(
            '<form action="/lead"><input name="name" placeholder="Ваше имя">'
            '<input type="tel" name="phone"><label><input type="checkbox" name="agree" '
            "required> Я даю согласие на обработку персональных данных</label>"
            '<label><input type="checkbox" name="newsletter" checked> Хочу получать новости'
            "</label><button>Отправить</button></form>"
        ),
        files=site_files(),
    ),
    Case(
        "lab-consent-with-ads",
        "согласие на обработку одной фразой с согласием на рекламную рассылку",
        {"SUV-PD-004": "warn"},
        html=page(
            '<form action="/lead"><input name="name" placeholder="Ваше имя">'
            '<input type="tel" name="phone"><label><input type="checkbox" name="agree" '
            "required> Даю согласие на обработку персональных данных и на получение "
            "рекламной рассылки</label><button>Отправить</button></form>"
        ),
        files=site_files(),
    ),
    Case(
        "lab-cookie-footer-link",
        "Google Analytics, а про cookies только ссылка в подвале на документ",
        {"SUV-PD-005": "warn"},
        html=page(
            FORM_OK + GA + '<p><a href="/cookies">Политика использования файлов cookie</a> '
            '<a href="/terms">Пользовательское соглашение</a></p>'
        ),
        files=site_files(),
    ),
    Case(
        "lab-http-no-forms",
        "сайт-визитка без HTTPS и без форм: данных из форм нет, но соединение открытое",
        {"SUV-PD-008": "warn"},
        html=page("<p>Звоните: +7 495 000-00-00</p>"),
        files=site_files(),
        http=True,
    ),
    Case(
        "lab-https-timeout",
        "по HTTPS сайт не отвечает (блокировка по стране), по HTTP открывается",
        {"SUV-PD-008": "unknown"},
        html=page("<p>Звоните: +7 495 000-00-00</p>"),
        files=site_files(),
        http=True,
        https_error=httpx.ConnectTimeout,
    ),
    Case(
        "lab-https-refused",
        "порт HTTPS закрыт, сайт работает только по HTTP",
        {"SUV-PD-008": "warn"},
        html=page("<p>Звоните: +7 495 000-00-00</p>"),
        files=site_files(),
        http=True,
        https_error=httpx.ConnectError,
    ),
    Case(
        "lab-spf-too-many",
        "SPF требует 11 DNS-запросов при лимите 10 (RFC 7208, 4.6.4)",
        {"SUV-MAIL-002": "fail"},
        html=page(FORM_OK),
        files=site_files(),
        dns={
            ("lab-spf-too-many.ru", "TXT"): [
                "v=spf1 " + " ".join(f"include:s{i}.lab.example" for i in range(11)) + " -all"
            ],
            **{(f"s{i}.lab.example", "TXT"): ["v=spf1 ip4:192.0.2.1 -all"] for i in range(11)},
        },
    ),
    Case(
        "lab-dmarc-sp-none",
        "DMARC p=reject, но sp=none: письма от поддоменов подделать можно",
        {"SUV-MAIL-001": "warn", "SUV-MAIL-003": "ok"},
        html=page(FORM_OK),
        files=site_files(),
        dns={("_dmarc.lab-dmarc-sp-none.ru", "TXT"): ["v=DMARC1; p=reject; sp=none"]},
    ),
    Case(
        "lab-no-mail",
        "домен без почты (null MX) и без SPF: письма от его имени не запрещены",
        {"SUV-MAIL-002": "fail"},
        html=page(FORM_OK),
        files=site_files(),
        dns={("lab-no-mail.ru", "MX"): ["0 ."], ("lab-no-mail.ru", "TXT"): []},
        mta_sts=None,
    ),
    Case(
        "lab-mta-sts-testing",
        "MTA-STS в режиме testing: шифрование не обязательно",
        {"SUV-MAIL-005": "warn"},
        html=page(FORM_OK),
        files=site_files(),
        mta_sts="version: STSv1\nmode: testing\nmx: mx.yandex.net\nmax_age: 86400\n",
    ),
    # --- found by the fresh-eyes review --------------------------------------------
    Case(
        "lab-spf-shared-include",
        "два include ведут к одной большой записи: она вычисляется дважды, 14 запросов",
        {"SUV-MAIL-002": "fail"},
        html=page(FORM_OK),
        files=site_files(),
        dns={
            ("lab-spf-shared-include.ru", "TXT"): [
                "v=spf1 include:a.lab.example include:b.lab.example -all"
            ],
            ("a.lab.example", "TXT"): ["v=spf1 include:big.lab.example -all"],
            ("b.lab.example", "TXT"): ["v=spf1 include:big.lab.example -all"],
            ("big.lab.example", "TXT"): [
                "v=spf1 " + " ".join(f"a:m{i}.lab.example" for i in range(5)) + " -all"
            ],
        },
    ),
    Case(
        "lab-spf-void",
        "в SPF три имени a: без адресов: больше двух пустых ответов — permerror (4.6.4)",
        {"SUV-MAIL-002": "fail"},
        html=page(FORM_OK),
        files=site_files(),
        dns={
            ("lab-spf-void.ru", "TXT"): [
                "v=spf1 a:old1.lab.example a:old2.lab.example a:old3.lab.example "
                "include:_spf.yandex.net -all"
            ]
        },
    ),
    Case(
        "lab-spf-redirect-chain",
        "redirect ведёт на redirect, в конце -all: запись в порядке",
        {"SUV-MAIL-002": "ok"},
        html=page(FORM_OK),
        files=site_files(),
        dns={
            ("lab-spf-redirect-chain.ru", "TXT"): ["v=spf1 redirect=_spf.lab.example"],
            ("_spf.lab.example", "TXT"): ["v=spf1 redirect=_spf2.lab.example"],
            ("_spf2.lab.example", "TXT"): ["v=spf1 include:_spf.yandex.net -all"],
        },
    ),
    Case(
        "lab-dmarc-pct-zero",
        "DMARC p=quarantine; pct=0: политика не применяется ни к одному письму",
        {"SUV-MAIL-001": "fail"},
        html=page(FORM_OK),
        files=site_files(),
        dns={("_dmarc.lab-dmarc-pct-zero.ru", "TXT"): ["v=DMARC1; p=quarantine; pct=0"]},
    ),
    Case(
        "lab-mta-sts-incomplete",
        "файл MTA-STS без version и max_age: отправители его игнорируют",
        {"SUV-MAIL-005": "warn"},
        html=page(FORM_OK),
        files=site_files(),
        mta_sts="mode: enforce\nmx: mx.yandex.net\n",
    ),
    Case(
        "lab-dmarc-rua-outside",
        "отчёты DMARC на чужой домен без его TXT-записи _report._dmarc (RFC 7489, 7.1)",
        {"SUV-MAIL-001": "ok", "SUV-MAIL-003": "warn"},
        html=page(FORM_OK),
        files=site_files(),
        dns={
            ("_dmarc.lab-dmarc-rua-outside.ru", "TXT"): [
                "v=DMARC1; p=reject; rua=mailto:dmarc@reports.example"
            ]
        },
    ),
    Case(
        "lab-dmarc-rua-outside-ok",
        "отчёты DMARC на чужой домен, который их принимает: запись в порядке",
        {"SUV-MAIL-003": "ok"},
        html=page(FORM_OK),
        files=site_files(),
        dns={
            ("_dmarc.lab-dmarc-rua-outside-ok.ru", "TXT"): [
                "v=DMARC1; p=reject; rua=mailto:dmarc@reports.example"
            ],
            ("lab-dmarc-rua-outside-ok.ru._report._dmarc.reports.example", "TXT"): ["v=DMARC1"],
        },
    ),
    # --- DKIM without a known selector (RFC 2308: an empty non-terminal is NOERROR) ---
    Case(
        "lab-dkim-odd-selector",
        "ключ DKIM под редким селектором: узел _domainkey есть, DKIM, вероятно, настроен",
        {"SUV-MAIL-004": "ok"},
        html=page(FORM_OK),
        files=site_files(),
        dns={
            ("mail._domainkey.lab-dkim-odd-selector.ru", "TXT"): [],
            ("k2026q4._domainkey.lab-dkim-odd-selector.ru", "TXT"): [
                "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN"
            ],
        },
    ),
    Case(
        "lab-dkim-none",
        "под _domainkey ничего нет: про DKIM ничего сказать нельзя",
        {"SUV-MAIL-004": "unknown"},
        html=page(FORM_OK),
        files=site_files(),
        dns={("mail._domainkey.lab-dkim-none.ru", "TXT"): []},
    ),
    Case(
        "lab-dkim-wildcard",
        "в зоне *-запись: на любое имя NOERROR, узел _domainkey ничего не доказывает",
        {"SUV-MAIL-004": "unknown"},
        html=page(FORM_OK),
        files=site_files(),
        dns={
            ("mail._domainkey.lab-dkim-wildcard.ru", "TXT"): [],
            ("*.lab-dkim-wildcard.ru", "TXT"): ["v=spf1 -all"],
        },
    ),
    # --- a record that times out: only the checks resting on it are unknown -----------
    Case(
        "lab-mta-sts-silent",
        "DNS не ответил на _mta-sts: MTA-STS не проверить, SPF, DMARC и DKIM — можно",
        {
            "SUV-MAIL-001": "ok",
            "SUV-MAIL-002": "ok",
            "SUV-MAIL-003": "ok",
            "SUV-MAIL-004": "ok",
            "SUV-MAIL-005": "unknown",
        },
        html=page(FORM_OK),
        files=site_files(),
        dns={("_mta-sts.lab-mta-sts-silent.ru", "TXT"): NO_ANSWER},
    ),
    # --- recommendation technologies (149-ФЗ, ст. 10.2-2) -----------------------------
    Case(
        "lab-recs-no-rules",
        "блок «Рекомендуем для вас», правил рекомендательных технологий нет",
        {"SUV-LAW-002": "warn"},
        html=page(FORM_OK + "<section><h2>Рекомендуем для вас</h2><p>Товар 1</p></section>"),
        files=site_files(),
    ),
    Case(
        "lab-recs-rules",
        "персональные рекомендации и ссылка на правила их применения в подвале",
        {"SUV-LAW-002": "ok"},
        html=page(
            FORM_OK
            + "<section><h2>Вам может понравиться</h2></section>"
            + '<a href="/recommendations">Правила применения рекомендательных технологий</a>'
        ),
        files=site_files({"/recommendations": page("<p>Правила применения…</p>")}),
    ),
    Case(
        "lab-recs-popular",
        "«Популярные товары» одинаковы для всех: это не рекомендательная технология",
        {"SUV-LAW-002": "нет проверки"},
        html=page(FORM_OK + "<section><h2>Популярные товары</h2></section>"),
        files=site_files(),
    ),
]

# Expected and actual differ here for a stated reason; the table counts them as misses.
KNOWN: dict[tuple[str, str], str] = {}


# --- Runner ---------------------------------------------------------------------------


class FakeResolver:
    kind = "lab"

    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self.records = records

    async def resolve(self, name: str, rtype: str) -> list[str]:
        records = self.records.get((name, rtype), [])
        if records is NO_ANSWER:
            raise DnsLookupError(f"DNS не ответил вовремя на запрос {rtype} {name}")
        return records

    async def exists(self, domain: str) -> bool:
        return True

    async def node_exists(self, name: str) -> bool | None:
        # A name exists when it, or a name under it, holds records (RFC 2308), or a
        # wildcard covers it.
        names = {n for (n, _), v in self.records.items() if v}
        if "*." + name.partition(".")[2] in names:
            return True
        return any(n == name or n.endswith("." + name) for n in names)


def _transport(case: Case) -> httpx.MockTransport:
    base = f"{'http' if case.http else 'https'}://{case.host}"
    bodies = {(k if "://" in k else base + k): v for k, v in case.files.items()}
    if case.mta_sts is not None:
        bodies[f"https://mta-sts.{case.host}/.well-known/mta-sts.txt"] = case.mta_sts

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url).split("#")[0]
        if case.https_error and url == f"https://{case.host}/":
            raise case.https_error("lab", request=request)
        if url in (base, base + "/"):
            return httpx.Response(200, headers=case.headers, text=case.html)
        body = bodies.get(url)
        if body is None:
            return httpx.Response(404, text="нет такой страницы")
        kind = "text/plain" if url.endswith(".txt") else "text/html; charset=utf-8"
        return httpx.Response(200, headers={"content-type": kind}, text=body)

    return httpx.MockTransport(handler)


async def run_case(case: Case) -> dict[str, Check]:
    host = case.host
    final_url = f"{'http' if case.http else 'https'}://{host}/"
    facts = Facts(
        host,
        host,
        web=[NetInfo("192.0.2.10", 64500, case.hosting[0], case.hosting[1])],
        final_url=final_url,
        page_status=200,
        html=case.html,
        headers={k.lower(): v for k, v in case.headers.items()},
        set_cookies=list(case.cookies),
    )
    records = {**good_dns(host), **(case.dns or {})}
    tls = case.tls or good_tls(host)

    async def probe(_host: str, _timeout: float) -> TlsInfo:
        return tls

    saved = websec.probe_tls
    websec.probe_tls = probe
    try:
        async with httpx.AsyncClient(transport=_transport(case), follow_redirects=True) as client:
            links = pick_links(parse_page(case.html), final_url, DEFAULT_PAGES)
            links += pick_from_sitemap(await sitemap_urls(client, final_url), final_url, set(links))
            facts.extra_pages = await fetch_pages(client, links)
            if case.https_error:
                # The real fallback from HTTPS to HTTP, to see why HTTPS failed.
                collector = Collector(FakeResolver(records), client, 5)
                await collector.homepage(host)
                facts.https_unanswered = collector.https_unanswered
            report = analyze(facts)
            checks = await run_compliance(
                client,
                final_url,
                case.html,
                report.dependencies,
                extra_pages=facts.extra_pages,
                https_unanswered=facts.https_unanswered,
            )
            web, _ = await run_web_checks(facts, FakeResolver(records), client, 5)
            checks += web
            checks += mail_checks(await collect_mail(FakeResolver(records), client, host))
    finally:
        websec.probe_tls = saved
    return {c.id: c for c in checks if c.id}


def run_all() -> list[tuple[Case, dict[str, Check]]]:
    async def go() -> list[tuple[Case, dict[str, Check]]]:
        return [(case, await run_case(case)) for case in CASES]

    return asyncio.run(go())


def mismatches(results: list[tuple[Case, dict[str, Check]]]) -> list[str]:
    out = []
    for case, got in results:
        for cid, want in case.expect.items():
            check = got.get(cid)
            have = check.status.value if check else "нет проверки"
            if have != want:
                out.append(f"{case.name} {cid}: ждали {want}, получили {have}")
    return out


def table(results: list[tuple[Case, dict[str, Check]]]) -> list[tuple[str, int, int, int, int]]:
    """Per check ID: true positives, false negatives, false positives, true negatives.
    A problem is "warn" or "fail"; a check that did not run counts as a miss."""
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    for case, got in results:
        for cid, want in case.expect.items():
            check = got.get(cid)
            have = check.status.value if check else "unknown"
            row = counts[cid]
            if want in POSITIVE:
                row[0 if have in POSITIVE else 1] += 1
            else:
                row[2 if have in POSITIVE else 3] += 1
    return [(cid, *row) for cid, row in sorted(counts.items())]


def _pct(a: int, b: int) -> str:
    return f"{100 * a // b}%" if b else "—"


def markdown(results: list[tuple[Case, dict[str, Check]]]) -> str:
    lines = [
        "| Проверка | Нашла проблем | Пропустила | Ложных тревог | Верно «в порядке» "
        "| Полнота | Точность |",
        "|---|---|---|---|---|---|---|",
    ]
    for cid, tp, fn, fp, tn in table(results):
        lines.append(
            f"| {cid} | {tp} | {fn} | {fp} | {tn} | {_pct(tp, tp + fn)} | {_pct(tp, tp + fp)} |"
        )
    return "\n".join(lines)


def main(argv: list[str]) -> None:
    results = run_all()
    if "--markdown" in argv:
        print(markdown(results))
        return
    for cid, tp, fn, fp, tn in table(results):
        print(f"{cid:13} TP {tp:2}  FN {fn:2}  FP {fp:2}  TN {tn:2}")
    bad = mismatches(results)
    print(f"\nСлучаев: {len(CASES)}, расхождений: {len(bad)}")
    for line in bad:
        print(" ", line)


if __name__ == "__main__":
    main(sys.argv[1:])
