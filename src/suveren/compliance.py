"""152-ФЗ checklist: what a visitor-facing website must have to collect personal data.

The checks are heuristics over the home page and the privacy policy it links to.
They point at likely problems; they are not a legal opinion.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import unquote, urldefrag, urljoin, urlsplit

import httpx

from suveren.checks import GROUP_152, Check, Evidence, Status
from suveren.collect import bot_wall
from suveren.collect import page_problem as detect_page_problem
from suveren.crawl import MAX_HTML_CHARS, FetchedPage, get_once_more
from suveren.discover import discover_inns, is_requisites_path
from suveren.errors import ModuleError
from suveren.inn import find_inns, own_ad_inns
from suveren.logins import (
    LoginEvidence,
    find_evidence,
    find_login_page,
    login_check,
    short_path,
)
from suveren.models import Category, Dependency
from suveren.page import Form, Link, Page, parse_page
from suveren.pdpolicy import (
    ConsentFinding,
    bundled_in_form,
    bundled_in_text,
    consent_check,
    consent_doc_link,
    cookie_doc_link,
    implied_in_document,
    policy_content,
    policy_reality,
)
from suveren.registries import RknOperator, rkn_operator
from suveren.utils import registrable_domain

_PLATFORM_DOMAINS = frozenset(
    {
        "yandex.ru", "yandex.com", "ya.ru", "google.com", "google.ru", "vk.com", "vk.ru",
        "mail.ru", "ok.ru", "apple.com", "microsoft.com", "facebook.com", "2gis.ru",
        "jivo.ru", "jivosite.com", "cloudflare.com", "tilda.cc", "youtube.com",
    }
)  # fmt: skip
_PD_PHRASE = re.compile(r"персональн\w* данн|обработк\w* (?:персональн|данн)", re.I)
_POLICY_HREF = re.compile(r"privacy|polit|policy|konfiden|confiden|personal|pdn|152", re.I)
# Fallback documents that often contain the personal-data section on big sites.
_LEGAL_TEXT = re.compile(r"соглашени|правов|юридическ|оферт|условия использования|terms", re.I)
_LEGAL_HREF = re.compile(r"legal|terms|agreement|usage|oferta|soglash|rules", re.I)
_PD_FIELD = re.compile(
    r"phone|tel|e-?mail|mail|name|fio|фио|имя|телефон|почт|фамили|contact|whatsapp|telegram",
    re.I,
)
# What a consent checkbox is about: processing, the policy. "Согласен получать рассылку"
# is a newsletter opt-in, not consent to processing.
_CONSENT_TEXT = re.compile(
    r"обработк|персональн|политик\w* конфиденциальн|политик\w* обработк|privacy|consent", re.I
)
# A checkbox for news or ads: ticked in advance, it is not the consent to processing.
_MARKETING_BOX = re.compile(r"news|subscri|mailing|promo|advert|реклам|рассыл|новост", re.I)
# A statement the visitor makes ("нажимая кнопку, вы соглашаетесь с политикой", "даю
# согласие на обработку"), not the title of a document linked in the footer. The verb
# varies: cloudpayments.ru has "вы предоставляете Согласие на обработку".
_CONSENT_NEARBY = re.compile(
    r"(?:соглаша\w*|согласен|согласна|согласны|(?:даю|да[её]те|да[её]м|предоставля\w*|"
    r"предоставить|выража\w*|подтвержда\w*)\s+(?:сво[её]\s+)?"
    r"согласие)(?:\s+[\w-]+){0,3}?\s+(?:на|с|со)\s+(?:обработк|политик|услови|правил)|"
    r"обработк\w* моих персональных",
    re.I,
)
_COOKIE_WIDGETS = re.compile(
    r"cookiebot|onetrust|cookieyes|cookie-?notice|cookie-?consent|cookieconsent|cookie-?banner|"
    r"cookies?-?(?:popup|alert|bar|warning|policy|accept)|t-cookies|klaro|ccm19|cookie_agree",
    re.I,
)
_COOKIE_TEXT = re.compile(r"cookie|куки", re.I)
# Verbs of a notice ("мы используем cookie", "вы соглашаетесь", "принять"), not the nouns
# of a document title: a footer link "Политика использования файлов cookie" next to
# "Пользовательское соглашение" is no notice.
_COOKIE_CONTEXT = re.compile(r"соглаша|согласн|использу|принять|принимаю|accept|продолжая", re.I)
# Visitor-tracking categories: they set cookies whatever the provider's country.
_TRACKING = frozenset({Category.ANALYTICS, Category.ADS, Category.CHAT})
# Who receives visitor data as a third party, and who sets cookies, for policy claims.
_THIRD_PARTIES = frozenset({Category.ANALYTICS, Category.ADS, Category.CHAT, Category.SOCIAL})
_COOKIE_SETTERS = frozenset({Category.ANALYTICS, Category.ADS})


def _names(deps: Iterable[Dependency]) -> list[str]:
    return list(dict.fromkeys(d.service for d in deps))


@dataclass(slots=True)
class PolicyInfo:
    url: str | None = None
    text: str = ""
    fetched: bool = False
    is_pdf: bool = False
    error: str | None = None
    # Found inside a general legal document (user agreement) rather than a policy link.
    indirect_label: str | None = None
    # The link works but the text could not be read (bot wall, JS shell).
    unreadable: str | None = None
    scripted: bool = True  # the page has scripts that may draw the text


@dataclass(slots=True)
class ComplianceInput:
    final_url: str | None
    page: Page
    deps: list[Dependency]
    policy: PolicyInfo = field(default_factory=PolicyInfo)
    inns: list[str] = field(default_factory=list)
    # The ИНН came from the site's own ad label: the advertiser's name, as quoted.
    inn_from_ad: str | None = None
    operator: RknOperator | None = None
    operator_error: str | None = None
    page_problem: str | None = None
    # Inner pages: (path, raw HTML, parsed page).
    extra: list[tuple[str, str, Page]] = field(default_factory=list)
    # The sign-in page, if found: (where, parsed page).
    login: tuple[str, Page] | None = None
    # The sign-in page answered with a bot wall: (where, why).
    login_blocked: tuple[str, str] | None = None
    login_external: str | None = None  # the sign-in page redirected to this host
    # The pages were opened in a browser: a footer added by scripts was seen too.
    rendered: bool = False


# Checks that are concluded from the page markup; meaningless if the page is an
# anti-bot stub or an empty JavaScript shell.
# Checks that read the page's HTML (catalog.py IDs): unproven when the page is a shell.
_HTML_CHECKS = frozenset({"SUV-PD-001", "SUV-PD-003", "SUV-PD-005", "SUV-PD-006", "SUV-PD-004"})


def _mark_unverifiable(checks: list[Check], problem: str) -> None:
    for c in checks:
        if c.id not in _HTML_CHECKS:
            continue
        found_something = c.status is Status.OK and c.link  # e.g. a policy link was found
        if c.id == "SUV-PD-001":
            if c.link:  # a policy, maybe inside another document, was found after all
                continue
        elif found_something or (c.status is Status.WARN and c.id != "SUV-PD-005"):
            continue
        c.status = Status.UNKNOWN
        c.details = f"Не проверено: {problem}."
        c.recommendation = "Проверьте вручную или запустите проверку с параметром --browser."


def find_policy_link(links: list[Link], base: str) -> str | None:
    """Best candidate for the privacy-policy link on the page.

    The link text must be about personal data or privacy ("персональный ассистент"
    is not), and the site's own policy beats a third party's (a map widget often
    links to Yandex's policy).
    """
    site = registrable_domain(urlsplit(base).hostname or "")
    scored: list[tuple[bool, int, str]] = []
    for link in links:
        href = link.href.strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        text = link.text.lower()
        score = 0
        if _PD_PHRASE.search(text):
            score += 3
        if "конфиденциальн" in text or "privacy" in text:
            score += 2
        if "политик" in text or "policy" in text:
            score += 1
        if score == 0:
            continue  # the URL alone (/personal/, /premium/) is not evidence
        if _POLICY_HREF.search(href):
            score += 1
        url = urljoin(base, href)
        domain = registrable_domain(urlsplit(url).hostname or "")
        own = domain == site
        if not own and domain in _PLATFORM_DOMAINS:
            continue  # a widget's own policy (Yandex Maps, Google) is not the site's
        if score >= 2:
            scored.append((own, score, url))
    if not scored:
        return None
    scored.sort(key=lambda item: (not item[0], -item[1]))
    return scored[0][2]


def find_legal_link(links: list[Link], base: str) -> tuple[str, str] | None:
    """(URL, link text) of a user agreement / legal page, used when no policy link exists."""
    for link in links:
        href = link.href.strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        if _LEGAL_TEXT.search(link.text) or (_LEGAL_HREF.search(href) and link.text.strip()):
            return urljoin(base, href), link.text.strip() or href
    return None


def pd_forms(page: Page) -> list[Form]:
    """Forms that collect personal data (not search boxes or newsletters with no fields)."""
    result = []
    for form in page.forms:
        fields = [i for i in form.inputs if i.type not in ("hidden", "submit", "button", "image")]
        if not fields:
            continue
        if any(i.type == "password" for i in fields):
            continue  # sign-in form: the account already exists
        if all(i.type == "search" or i.name in ("q", "s", "search", "query") for i in fields):
            continue
        if any(
            (i.type in ("email", "tel") or _PD_FIELD.search(f"{i.name} {i.hint}"))
            and not _NOT_PD_FIELD.search(i.name)
            for i in fields
        ):
            result.append(form)
    return result


# A gift card, promo code or SMS code typed into a "tel" field is not personal data
# (vkusvill.ru's cart: <input type="tel" name="GIFT_CARD">). Only the field's name is
# read: CSS classes say "card" for an e-mail field in a card layout (banki.ru) and
# "SignInBySms" for a phone (citilink.ru).
# "name" and "tel" also sit in the names of things: tutu.ru's ticket search has
# city_name_from, a hotel search has hotel_name.
_NOT_PD_FIELD = re.compile(
    r"card|gift|promo|coupon|otp|sms|cvv|cvc|captcha|amount|qty|quantity|"
    r"city|town|station|airport|country|region|hotel|product|goods|item|file",
    re.I,
)
_FIRST_STEP = re.compile(
    r"(?<!\w)(?:продолжить|далее|получить код|отправить код|выбрать станцию|next|continue)(?!\w)",
    re.I,
)


def _unique_forms(located: list[tuple[str, Form]]) -> list[tuple[str, Form]]:
    """A header or footer form repeats on every page; count it once (first page wins)."""
    seen: set[tuple[str, tuple[str, ...]]] = set()
    unique = []
    for path, form in located:
        signature = (
            form.action.split("?", 1)[0].rstrip("/"),
            tuple(sorted(f"{i.type}:{i.name}" for i in form.inputs if i.type != "hidden")),
        )
        if signature not in seen:
            seen.add(signature)
            unique.append((path, form))
    return unique


def has_cookie_notice(html: str) -> bool:
    if _COOKIE_WIDGETS.search(html):
        return True
    for match in _COOKIE_TEXT.finditer(html):
        window = html[max(0, match.start() - 300) : match.end() + 300]
        if _COOKIE_CONTEXT.search(window):
            return True
    return False


def evaluate(data: ComplianceInput, html: str) -> list[Check]:
    checks: list[Check] = []
    page = data.page
    located = _unique_forms(
        [("главная", f) for f in pd_forms(page)]
        + [(path, f) for path, _, extra in data.extra for f in pd_forms(extra)]
    )
    forms = [f for _, f in located]
    pages_checked = 1 + len(data.extra)
    foreign_visitor = [d for d in data.deps if d.foreign and d.category.info.visitor_data]
    tracking = [d for d in data.deps if d.category in _TRACKING]

    # 1. Policy published.
    policy = data.policy
    if policy.url is None:
        checks.append(
            Check(
                GROUP_152,
                "Политика обработки персональных данных",
                # Unproven if the sign-in page, where the link sometimes is, was a bot wall,
                # or without a browser: footers added by scripts (mos.ru) are not in the HTML.
                # The duty to publish it on the site is for an operator collecting data
                # through the site (152-ФЗ, ст. 18.1 ч. 2): with no form or counter seen,
                # that is not proven either.
                Status.FAIL
                if data.rendered and not data.login_blocked and (forms or tracking)
                else Status.WARN,
                "На проверенных страницах нет ссылки на политику обработки персональных данных."
                + (
                    ""
                    if forms or tracking
                    else " Форм и счётчиков, собирающих данные, на них тоже нет: если сайт "
                    "совсем не собирает данные посетителей, публиковать политику на нём не "
                    "обязательно."
                )
                + (
                    ""
                    if data.rendered
                    else " Без браузера не виден подвал, который подгружается скриптами: "
                    "перепроверьте в режиме --browser."
                )
                + (
                    f" Страница входа ({data.login_blocked[0]}) не открылась: "
                    f"{data.login_blocked[1]}, а ссылка бывает только там."
                    if data.login_blocked
                    else ""
                ),
                "Опубликуйте политику и поставьте ссылку на неё в подвале сайта и рядом с каждой "
                "формой (152-ФЗ, ст. 18.1 ч. 2).",
            )
        )
    elif policy.indirect_label:
        checks.append(
            Check(
                GROUP_152,
                "Политика обработки персональных данных",
                Status.WARN,
                "Отдельной ссылки на политику на главной нет, о персональных данных говорится "
                f"в документе «{policy.indirect_label}».",
                "Поставьте отдельную ссылку на политику обработки персональных данных в подвале "
                "сайта и рядом с формами (152-ФЗ, ст. 18.1 ч. 2).",
                link=policy.url,
            )
        )
    elif policy.error:
        gone = policy.error.startswith("такой страницы нет")
        checks.append(
            Check(
                GROUP_152,
                "Политика обработки персональных данных",
                # A 404 is the site's fault; a timeout is the network's, not a finding
                # (kp.ru's policy timed out in one of two runs on 2026-10-23).
                Status.WARN if gone else Status.UNKNOWN,
                f"Ссылка на политику есть, но страница не открылась: {policy.error}."
                + ("" if gone else " Содержание политики не проверено."),
                "Опубликуйте политику по этому адресу или исправьте ссылку (152-ФЗ, ст. 18.1 ч. 2)."
                if gone
                else "Проверьте, что ссылка открывается, и повторите проверку.",
                link=policy.url,
            )
        )
    else:
        checks.append(
            Check(
                GROUP_152,
                "Политика обработки персональных данных",
                Status.OK,
                "Политика опубликована"
                + (
                    " (PDF)."
                    if policy.is_pdf
                    else f", но прочитать текст не удалось: {policy.unreadable}."
                    if policy.unreadable
                    else "."
                ),
                link=policy.url,
            )
        )
        if policy.fetched and not policy.is_pdf and not policy.unreadable:
            checks.append(policy_content(policy.text, bool(foreign_visitor), policy.scripted))
            site = " ".join([html, *(h for _, h, _ in data.extra)])
            site_inns = [] if data.inn_from_ad else find_inns(site)
            hosts = {urlsplit(u).hostname or "" for u in (data.final_url, policy.url) if u}
            checks.append(
                policy_reality(
                    policy.text,
                    _names(d for d in data.deps if d.category in _THIRD_PARTIES),
                    _names(foreign_visitor),
                    _names(d for d in data.deps if d.category in _COOKIE_SETTERS),
                    collected=collected(forms),
                    site_inn=site_inns[0] if site_inns else None,
                    own={registrable_domain(h) for h in hosts if h},
                    cookie_doc=any(
                        cookie_doc_link(pg.links, data.final_url or "", policy.url)
                        for pg in [page, *(p for _, _, p in data.extra)]
                    ),
                )
            )

    # 2. Consent in forms.
    if not forms:
        checks.append(
            Check(
                GROUP_152,
                "Согласие на обработку в формах",
                Status.UNKNOWN,
                (
                    "На главной странице нет форм с персональными данными."
                    if pages_checked == 1
                    else f"На проверенных страницах ({pages_checked}) нет форм с "
                    "персональными данными."
                )
                + " Проверьте формы на остальных страницах вручную.",
            )
        )
    else:
        # Consent text often sits right under the form rather than inside <form>; when the
        # page mentions it, the form is "probably fine" rather than a clear failure.
        page_texts = {"главная": page.text, **{p: pg.text for p, _, pg in data.extra}}
        missing = [(p, f) for p, f in located if not _form_has_consent(f)]
        unseen = [(p, f) for p, f in missing if not _CONSENT_NEARBY.search(page_texts.get(p, ""))]
        # The first step of a multi-step form ("Отправим СМС… Продолжить") often shows the
        # consent on a later step that plain HTML does not have: not a proven failure.
        steps = [(p, f) for p, f in unseen if _FIRST_STEP.search(f.text)]
        hard = [x for x in unseen if x not in steps]
        soft = [(p, f) for p, f in missing if (p, f) not in unseen]
        prechecked = [
            f
            for f in forms
            if any(
                i.type == "checkbox"
                and i.checked
                and not _MARKETING_BOX.search(f"{i.name} {i.hint}")
                for i in f.inputs
            )
        ]
        if steps and not hard:
            where = ", ".join(dict.fromkeys(p for p, _ in steps))
            checks.append(
                Check(
                    GROUP_152,
                    "Согласие на обработку в формах",
                    Status.WARN,
                    f"Форм с персональными данными: {len(forms)}. Согласия не видно в "
                    f"первом шаге формы ({where}). Если оно появляется на следующем шаге, "
                    "всё в порядке: проверьте, пройдя форму до конца.",
                    "Согласие должно быть дано до того, как данные отправлены. Если на "
                    "первом шаге уже собирается телефон или имя, покажите согласие там же.",
                )
            )
        elif hard:
            where = ", ".join(dict.fromkeys(p for p, _ in hard))
            # Not FAIL: whether consent is needed depends on what the form is for, which
            # can't be seen from outside. A request to sign a contract (ст. 6 ч. 1 п. 5)
            # or an appeal to a state body (59-ФЗ, п. 2) needs none: kremlin.ru, pochta.ru.
            checks.append(
                Check(
                    GROUP_152,
                    "Согласие на обработку в формах",
                    Status.WARN,
                    f"Форм с персональными данными: {len(forms)}. Рядом с {len(hard)} из них "
                    f"не найдено согласия на обработку данных ({where}). Нужно ли оно, "
                    "зависит от цели формы: снаружи её не видно.",
                    "Согласие не нужно, если данные нужны только для заключения или "
                    "исполнения договора по просьбе посетителя (152-ФЗ, ст. 6 ч. 1 п. 5); в "
                    "остальных случаях получите его до отправки формы, например отдельным "
                    "чекбоксом со ссылкой на текст согласия. С 1 сентября 2025 года согласие "
                    "оформляется отдельно от других документов (ст. 9 ч. 1).",
                )
            )
        elif soft:
            where = ", ".join(dict.fromkeys(p for p, _ in soft))
            checks.append(
                Check(
                    GROUP_152,
                    "Согласие на обработку в формах",
                    Status.WARN,
                    f"Форм с персональными данными: {len(forms)}. Согласие упоминается на "
                    f"странице, но не внутри формы ({where}): проверьте, что посетитель "
                    "подтверждает его сам.",
                    "Сделайте согласие отдельным чекбоксом внутри формы, без заранее "
                    "поставленной галочки (152-ФЗ, ст. 9).",
                )
            )
        elif prechecked:
            checks.append(
                Check(
                    GROUP_152,
                    "Согласие на обработку в формах",
                    Status.WARN,
                    "Чекбокс согласия отмечен заранее. Такое согласие трудно считать "
                    "конкретным и сознательным.",
                    "Уберите предустановленную галочку: посетитель должен поставить её сам.",
                )
            )
        else:
            checks.append(
                Check(
                    GROUP_152,
                    "Согласие на обработку в формах",
                    Status.OK,
                    f"Форм с персональными данными: {len(forms)}, во всех есть согласие.",
                )
            )

    # 2a. Consent drawn up separately from other documents.
    separate = _consent_check(data, located)
    if separate:
        checks.append(separate)

    # 3. Cookie notice.
    if tracking:
        names = ", ".join(dict.fromkeys(d.service for d in tracking))
        if has_cookie_notice(html) or any(has_cookie_notice(h) for _, h, _ in data.extra):
            checks.append(
                Check(
                    GROUP_152,
                    "Уведомление о cookies",
                    Status.OK,
                    f"Сайт использует {names} и показывает уведомление о cookies.",
                )
            )
        else:
            checks.append(
                Check(
                    GROUP_152,
                    "Уведомление о cookies",
                    Status.WARN,
                    f"Сайт использует {names}, но уведомление о cookies не найдено. По позиции "
                    "Роскомнадзора данные метрических сервисов могут быть персональными данными.",
                    "Добавьте баннер с уведомлением о cookies и ссылкой на политику.",
                )
            )

    # 4. Cross-border transfer.
    if foreign_visitor:
        names = ", ".join(f"{d.service} ({d.country_ru})" for d in foreign_visitor)
        checks.append(
            Check(
                GROUP_152,
                "Трансграничная передача данных",
                Status.WARN,
                f"Данные посетителей уходят иностранным сервисам: {names}.",
                "Уведомите Роскомнадзор о трансграничной передаче до её начала, отдельно от "
                "уведомления об обработке (152-ФЗ, ст. 12 ч. 3, с 1 марта 2023 года), или "
                "замените сервисы на российские.",
            )
        )
    else:
        checks.append(
            Check(
                GROUP_152,
                "Трансграничная передача данных",
                Status.OK,
                "Скрипты иностранных сервисов, получающие данные посетителей, не найдены.",
            )
        )

    # 5. Localisation of databases.
    hosting = [d for d in data.deps if d.category is Category.HOSTING]
    if any(d.foreign for d in hosting):
        where = ", ".join(f"{d.service} ({d.country_ru})" for d in hosting if d.foreign)
        checks.append(
            Check(
                GROUP_152,
                "Хранение данных в России",
                Status.FAIL if forms else Status.WARN,
                f"Сайт размещён за рубежом: {where}."
                + (
                    " На нём есть формы сбора данных: если заявки сохраняются на этом "
                    "сервере, база с персональными данными находится за рубежом."
                    if forms
                    else ""
                ),
                "Перенесите сайт и базу данных к российскому провайдеру: при сборе данных "
                "граждан РФ записывать и хранить их в базах за рубежом нельзя (152-ФЗ, ст. 18 "
                "ч. 5 в ред. от 01.07.2025).",
            )
        )
    elif hosting and all(d.foreign is False for d in hosting):
        checks.append(
            Check(GROUP_152, "Хранение данных в России", Status.OK, "Сервер сайта в России.")
        )
    else:
        checks.append(
            Check(
                GROUP_152,
                "Хранение данных в России",
                Status.UNKNOWN,
                "Не удалось определить, где находится сервер (например, сайт за CDN).",
                "Убедитесь, что база с персональными данными хранится в России.",
            )
        )

    # 6. Encryption.
    insecure_forms = [f for f in forms if f.action.lower().startswith("http://")]
    if data.final_url and not data.final_url.startswith("https://"):
        checks.append(
            Check(
                GROUP_152,
                "Защищённое соединение",
                Status.FAIL if forms else Status.WARN,
                "Сайт открывается без HTTPS: данные из форм передаются в открытом виде."
                if forms
                else "Сайт открывается без HTTPS: форм на проверенных страницах нет, но адрес "
                "посетителя, cookies и всё, что он введёт на других страницах, передаются в "
                "открытом виде.",
                "Включите HTTPS и перенаправление с HTTP.",
            )
        )
    elif insecure_forms:
        checks.append(
            Check(
                GROUP_152,
                "Защищённое соединение",
                Status.FAIL,
                "Форма отправляет данные по незащищённому адресу http://.",
                "Отправляйте формы только по HTTPS.",
            )
        )
    elif data.final_url:
        checks.append(
            Check(GROUP_152, "Защищённое соединение", Status.OK, "Сайт работает по HTTPS.")
        )

    # 7. Register of personal-data operators.
    checks.append(_operator_check(data))
    if data.page_problem:
        _mark_unverifiable(checks, data.page_problem)
    for check in checks:
        check.law = check.law or LAW_BY_ID.get(check.id)
        if check.status is not Status.UNKNOWN and not check.evidence:
            check.evidence = evidence(data, located, check.id)
    return checks


_SHOWN_EVIDENCE = 10
_PAGE_CATEGORIES = frozenset(c for c in Category if c.info.visitor_data)


def _dep_evidence(deps: list[Dependency]) -> list[Evidence]:
    """Where each service was seen: a script or request address on the page, or a DNS
    answer for infrastructure (hosting, CDN)."""
    return [
        Evidence("url" if d.category in _PAGE_CATEGORIES else "dns", d.service, d.evidence)
        for d in deps[:_SHOWN_EVIDENCE]
    ]


def evidence(
    data: ComplianceInput, located: list[tuple[str, Form]], check_id: str
) -> list[Evidence]:
    """What a 152-ФЗ check rests on: the policy address, the forms as found (their fields
    and whether a consent statement is next to them), the services and their addresses."""
    policy = data.policy
    if check_id in ("SUV-PD-001", "SUV-PD-002", "SUV-PD-011"):
        pages = ["главная", *(path for path, _, _ in data.extra)]
        found = [Evidence("url", "Ссылка на политику", policy.url or "")]
        if check_id == "SUV-PD-001":
            found.append(Evidence("url", "Проверенные страницы", ", ".join(pages)))
        return found
    if check_id == "SUV-PD-003":
        return [
            Evidence(
                "html",
                f"Форма на странице {where}",
                f"поля: {_fields(form)}; согласие рядом: "
                + ("есть" if _form_has_consent(form) else "нет")
                + (
                    "; галочка уже стоит"
                    if any(i.checked for i in form.inputs if i.type == "checkbox")
                    else ""
                ),
            )
            for where, form in located[:_SHOWN_EVIDENCE]
        ]
    if check_id == "SUV-PD-005":
        return _dep_evidence([d for d in data.deps if d.category in _TRACKING])
    if check_id == "SUV-PD-006":
        return _dep_evidence([d for d in data.deps if d.foreign and d.category.info.visitor_data])
    if check_id == "SUV-PD-007":
        return _dep_evidence([d for d in data.deps if d.category is Category.HOSTING])
    if check_id == "SUV-PD-008":
        insecure = [f.action for _, f in located if f.action.lower().startswith("http://")]
        return [Evidence("url", "Адрес сайта", data.final_url or "")] + [
            Evidence("html", "Форма отправляется на", a) for a in insecure[:_SHOWN_EVIDENCE]
        ]
    return []


def _fields(form: Form) -> str:
    shown = [i for i in form.inputs if i.type not in ("hidden", "submit", "button", "image")]
    return ", ".join(f"{i.name or i.hint or '?'} ({i.type})" for i in shown[:8]) or "нет"


# Where each conclusion comes from in the law, shown next to it in the report.
LAW_BY_ID = {
    "SUV-PD-001": "152-ФЗ, ст. 18.1",
    "SUV-PD-002": "152-ФЗ, ст. 18.1",
    "SUV-PD-011": "152-ФЗ, ст. 18.1",
    "SUV-PD-003": "152-ФЗ, ст. 9",
    "SUV-PD-004": "152-ФЗ, ст. 9 ч. 1",
    "SUV-PD-005": "152-ФЗ, ст. 9",
    "SUV-PD-006": "152-ФЗ, ст. 12",
    "SUV-PD-007": "152-ФЗ, ст. 18 ч. 5",
    "SUV-PD-008": "152-ФЗ, ст. 19",
    "SUV-PD-009": "152-ФЗ, ст. 22",
}


# What a form field asks for, by its type and name: the words of pdpolicy.DATA_WORDS.
_ASKS = (
    ("phone", re.compile(r"phone|tel|телефон|mobile", re.I)),
    ("email", re.compile(r"e-?mail|почт", re.I)),
    (
        "name",
        re.compile(r"(?<![a-z])(?:name|fio|first_?name|last_?name)(?![a-z])|фио|имя|фамили", re.I),
    ),
)


def collected(forms: list[Form]) -> list[str]:
    """What the forms ask a visitor for: phone, email, name."""
    found = set()
    for form in forms:
        for i in form.inputs:
            if i.type in ("tel", "email"):
                found.add("phone" if i.type == "tel" else "email")
                continue
            if i.type not in ("text", ""):
                continue
            hint = f"{i.name} {i.hint}"
            if _NOT_PD_FIELD.search(i.name):
                continue
            found |= {kind for kind, rx in _ASKS if rx.search(hint)}
    return [k for k in ("phone", "email", "name") if k in found]


def _form_has_consent(form: Form) -> bool:
    if any(i.type == "checkbox" for i in form.inputs) and _CONSENT_TEXT.search(form.text):
        return True
    # A statement ("нажимая кнопку, вы соглашаетесь с политикой"), not any mention of
    # personal data: "мы не храним ваши персональные данные" is no consent.
    return bool(_CONSENT_NEARBY.search(form.text))


def _consent_check(data: ComplianceInput, located: list[tuple[str, Form]]) -> Check | None:
    findings = []
    for where, form in located:
        quote = bundled_in_form(form)
        if quote:
            findings.append(ConsentFinding(where, quote, "form"))
    if data.login:
        quote = bundled_in_text(data.login[1].text)
        if quote:
            findings.append(ConsentFinding(data.login[0], quote, "page"))
    policy = data.policy
    if policy.text:
        quote = implied_in_document(policy.text)
        if quote:
            label = f"«{policy.indirect_label}»" if policy.indirect_label else "политика"
            findings.append(ConsentFinding(label, quote, "doc"))
    base = data.final_url or ""
    separate = None
    for url, page in [(base, data.page), *((urljoin(base, p), pg) for p, _, pg in data.extra)]:
        link = consent_doc_link(page.links)
        if link:
            separate = urljoin(url, link.href.strip())
            break
    check = consent_check(findings, separate, len(located))
    if check is not None:
        # The statements as quoted, and the separate consent document if there is one.
        check.evidence = [
            Evidence("html", f"Текст ({f.where})", f.quote) for f in findings[:_SHOWN_EVIDENCE]
        ]
        if separate:
            check.evidence.append(Evidence("url", "Отдельный документ согласия", separate))
    return check


def _operator_check(data: ComplianceInput) -> Check:
    title = "Реестр операторов персональных данных"
    if not data.inns:
        return Check(
            GROUP_152,
            title,
            Status.UNKNOWN,
            "ИНН компании на сайте не найден, поэтому реестр не проверялся.",
            "Укажите реквизиты компании на сайте. Проверить реестр можно командой "
            "suveren company <ИНН>.",
        )
    inn = data.inns[0]
    source = (
        f" ИНН взят из маркировки рекламы на сайте: рекламодатель «{data.inn_from_ad}» носит "
        "имя сайта, других реквизитов на проверенных страницах нет."
        if data.inn_from_ad
        else ""
    )
    if data.operator_error:
        return Check(GROUP_152, title, Status.UNKNOWN, f"ИНН {inn}: {data.operator_error}.{source}")
    if data.operator is None:
        return Check(
            GROUP_152,
            title,
            Status.WARN,
            f"Организация с ИНН {inn} не найдена в реестре операторов персональных данных."
            + source,
            "Подайте уведомление в Роскомнадзор: это обязательно почти для всех операторов "
            "до начала обработки данных (152-ФЗ, ст. 22).",
            evidence=[
                Evidence("html", "ИНН на сайте", inn),
                Evidence("registry", "Реестр операторов Роскомнадзора, поиск по ИНН", ""),
            ],
        )
    op = data.operator
    since = op.registered.strftime("%d.%m.%Y") if op.registered else "?"
    return Check(
        GROUP_152,
        title,
        Status.OK,
        f"{op.name} (ИНН {inn}) в реестре: № {op.reg_number} от {since}.{source}",
        link=op.url,
    )


def policy_target(
    page: Page, extras: list[tuple[str, Page]], base: str
) -> tuple[str, str | None] | None:
    """(URL, None) for a policy link, or (URL, link text) for a user agreement to fall
    back on. The link may only be in an inner page's footer, so those are searched too."""
    if not base:
        return None
    for url, candidate in [(base, page), *extras]:
        found = find_policy_link(candidate.links, url)
        if found:
            return found, None
    legal = find_legal_link(page.links, base)
    return (legal[0], legal[1]) if legal else None


async def fetch_policy(
    client: httpx.AsyncClient, url: str, prefetched: FetchedPage | None = None
) -> PolicyInfo:
    info = PolicyInfo(url=url)
    if urlsplit(url).path.lower().endswith(".pdf"):
        info.fetched = info.is_pdf = True
        return info
    if prefetched is not None:
        status, html, content_type = prefetched.status, prefetched.html, "text/html"
    else:
        try:
            resp = await get_once_more(client, url)
        except httpx.TimeoutException as exc:
            info.error = f"сайт не ответил вовремя ({type(exc).__name__})"
            return info
        except httpx.HTTPError as exc:
            info.error = type(exc).__name__
            return info
        if resp.status_code in (404, 410):
            # sravni.ru's policy answered 404 in one of two runs and 200 in the other: a
            # 404 is a finding, so it is asked twice before it counts.
            with contextlib.suppress(httpx.HTTPError):
                resp = await client.get(url)
        status, html = resp.status_code, resp.text[:3_000_000]
        content_type = resp.headers.get("content-type", "")
        if status in (404, 410):
            # The link leads nowhere: no policy is published, whatever the link says.
            info.error = f"такой страницы нет (код {status})"
            return info
    info.fetched = True
    if "pdf" in content_type:
        info.is_pdf = True
        return info
    # A bot wall or an empty shell is not the policy: don't judge its "content".
    problem = detect_page_problem(status, html, rendered=prefetched is not None)
    if problem:
        info.unreadable = problem
    else:
        info.text = parse_page(html).text
        info.scripted = "<script" in html.lower()
    return info


async def run_compliance(
    client: httpx.AsyncClient,
    final_url: str | None,
    html: str,
    deps: list[Dependency],
    page_problem: str | None = None,
    extra_pages: list[FetchedPage] | None = None,
    prefetched: dict[str, FetchedPage] | None = None,
    loaded_urls: list[str] | None = None,
    rendered: bool = False,
) -> list[Check]:
    """``prefetched`` holds pages already opened in the browser (the policy, the sign-in
    page), keyed by URL; ``loaded_urls`` are the home page's requests in the browser."""
    page = parse_page(html)
    data = ComplianceInput(
        final_url=final_url, page=page, deps=deps, page_problem=page_problem, rendered=rendered
    )
    data.extra = [(p.path, p.html, parse_page(p.html)) for p in extra_pages or []]
    base = final_url or ""
    prefetched = prefetched or {}
    # The sign-in page: foreign sign-in buttons, and sometimes the only policy link
    # (drom.ru links its policy from "При входе вы принимаете...").
    login = await _login_page(client, data, prefetched)
    extras = [(urljoin(base, p), pg) for p, _, pg in data.extra]
    if login:
        login_page = parse_page(login.html)
        extras.append((login.url, login_page))
        data.login = (_where(login.url, base), login_page)
    target = policy_target(page, extras, base)
    if target is None or target[1] is not None:
        # No direct link: the policy is often one page away, in a list of documents
        # (beget.com: "Правила и лицензии"). Check that before falling back on an offer.
        via_hub = await _policy_via_hub(client, [(base, page), *extras], base)
        if via_hub:
            target = (via_hub, None)
    if target and target[1] is None:
        data.policy = await fetch_policy(client, target[0], prefetched.get(target[0]))
    elif target and target[1] is not None:
        doc = await fetch_policy(client, target[0], prefetched.get(target[0]))
        if doc.fetched and "персональн" in doc.text.lower():
            doc.indirect_label = target[1][:60]
            data.policy = doc
    if base:
        own = [h for path, h, _ in data.extra if is_requisites_path(path)]
        extra_text = " ".join([data.policy.text, *own])
        data.inns, _ = await discover_inns(client, base, html, extra_text)
        if not data.inns:
            pages = " ".join([html, *(h for _, h, _ in data.extra)])
            own_ads = own_ad_inns(pages, urlsplit(base).hostname or "")
            if own_ads:
                data.inns, data.inn_from_ad = [own_ads[0][0]], own_ads[0][1]
    if data.inns:
        try:
            data.operator = await rkn_operator(client, data.inns[0])
        except ModuleError as exc:
            data.operator_error = str(exc)
    checks = evaluate(data, html)
    loaded = {p.path: p.loaded_urls for p in extra_pages or []}
    checks.append(_foreign_login(data, html, loaded_urls or [], loaded, login))
    return checks


_HUB_TEXT = re.compile(
    r"^(?:документ\w*|правовая информация|правовые документы|юридическая информация|"
    r"правила(?: и лицензии| и документы| сервиса| сайта)?|договор\w*|"
    r"документы и (?:правила|лицензии)|legal|documents)$",
    re.I,
)
MAX_HUBS = 3


def hub_links(pages: list[tuple[str, Page]], base: str) -> list[str]:
    """The site's own pages that list its legal documents, from link text alone."""
    site = registrable_domain(urlsplit(base).hostname or "")
    found: list[str] = []
    for url, page in pages:
        for link in page.links:
            href = link.href.strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            if not _HUB_TEXT.match(" ".join(link.text.split())):
                continue
            absolute = urljoin(url, href)
            if registrable_domain(urlsplit(absolute).hostname or "") != site:
                continue
            if absolute not in found:
                found.append(absolute)
    return found[:MAX_HUBS]


async def _policy_via_hub(
    client: httpx.AsyncClient, pages: list[tuple[str, Page]], base: str
) -> str | None:
    for url in hub_links(pages, base):
        doc = await _fetch_html(client, url)
        if doc is None or detect_page_problem(doc.status, doc.html, rendered=False):
            continue
        # The hub's table of contents links to its own sections (#politika...); the
        # document itself is the link inside that section (beget.com: a PDF).
        here = urldefrag(doc.url)[0]
        links = [
            link
            for link in parse_page(doc.html).links
            if urldefrag(urljoin(doc.url, link.href.strip()))[0] != here
        ]
        found = find_policy_link(links, doc.url)
        if found:
            return found
    return None


async def _login_page(
    client: httpx.AsyncClient, data: ComplianceInput, prefetched: dict[str, FetchedPage]
) -> FetchedPage | None:
    base = data.final_url or ""
    if not base or data.page_problem:
        return None
    url = find_login_page(data.page, base)
    if not url or urlsplit(url).path in {p for p, _, _ in data.extra}:
        return None
    doc = prefetched.get(url) or await _fetch_html(client, url)
    if doc is None:
        return None
    # A redirect to another company's sign-in (Yandex ID, a corporate SSO): its buttons
    # and its policy link are not this site's.
    host = (urlsplit(doc.url).hostname or "").lower()
    if host and registrable_domain(host) != registrable_domain(urlsplit(base).hostname or ""):
        data.login_external = host
        return None
    # A sign-in page is short by nature and often has a captcha, so a bot wall is
    # told apart by having no field to type a login into (drom.ru redirects to /verify).
    wall = bot_wall(doc.status, doc.html)
    fields = {i.type for f in parse_page(doc.html).forms for i in f.inputs}
    if (doc.status or 200) >= 400 or (wall and not fields & _LOGIN_FIELDS):
        data.login_blocked = (_where(url, base), wall or f"ответ {doc.status}")
        return None
    return doc


_LOGIN_FIELDS = frozenset({"text", "email", "tel", "password"})


def _foreign_login(
    data: ComplianceInput,
    html: str,
    loaded_urls: list[str],
    extra_loaded: dict[str, list[str]],
    doc: FetchedPage | None,
) -> Check:
    """Look for foreign sign-in on the pages already fetched and on the sign-in page."""
    base = data.final_url or ""
    evidence: list[LoginEvidence] = []
    pages: list[str] = []
    if not data.page_problem:
        evidence += find_evidence(html, data.page, base, "главная", loaded_urls)
        pages.append("главная")
    for path, extra_html, extra in data.extra:
        where = short_path(unquote(path))
        evidence += find_evidence(
            extra_html, extra, urljoin(base, path), where, extra_loaded.get(path, [])
        )
        if where not in pages:
            pages.append(where)
    shell: str | None = None
    if doc and data.login:
        where, login_page = data.login
        evidence += find_evidence(doc.html, login_page, doc.url, where, doc.loaded_urls)
        pages.insert(1 if pages[:1] == ["главная"] else 0, where)  # shown first
        if not doc.loaded_urls and len(login_page.text) < 300:
            shell = where
    return login_check(
        evidence, pages, data.page_problem, shell, data.login_blocked, data.login_external
    )


def _where(url: str, base: str) -> str:
    """Path for people; the host too if it is another subdomain (my.drom.ru/sign)."""
    parts = urlsplit(url)
    path = parts.path or "/"
    same = parts.hostname == urlsplit(base).hostname
    return short_path(path if same else f"{parts.hostname}{path}")


async def _fetch_html(client: httpx.AsyncClient, url: str) -> FetchedPage | None:
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return None
    if "html" not in resp.headers.get("content-type", "html"):
        return None
    return FetchedPage(str(resp.url), resp.status_code, resp.text[:MAX_HTML_CHARS])
