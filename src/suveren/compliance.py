"""152-ФЗ checklist: what a visitor-facing website must have to collect personal data.

The checks are heuristics over the home page and the privacy policy it links to.
They point at likely problems; they are not a legal opinion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from suveren.checks import GROUP_152, Check, Status
from suveren.discover import discover_inns
from suveren.errors import ModuleError
from suveren.models import Category, Dependency
from suveren.page import Form, Link, Page, parse_page
from suveren.registries import RknOperator, rkn_operator

_POLICY_TEXT = re.compile(r"персональн|конфиденциальн|privacy|политик[аи] обработки", re.I)
_POLICY_HREF = re.compile(r"privacy|polit|policy|konfiden|confiden|personal|pdn|152", re.I)
# Fallback documents that often contain the personal-data section on big sites.
_LEGAL_TEXT = re.compile(r"соглашени|правов|юридическ|оферт|условия использования|terms", re.I)
_LEGAL_HREF = re.compile(r"legal|terms|agreement|usage|oferta|soglash|rules", re.I)
_PD_FIELD = re.compile(
    r"phone|tel|e-?mail|mail|name|fio|фио|имя|телефон|почт|фамили|contact|whatsapp|telegram",
    re.I,
)
_CONSENT_TEXT = re.compile(r"соглас|персональн|политик|privacy|consent", re.I)
_COOKIE_WIDGETS = re.compile(
    r"cookiebot|onetrust|cookieyes|cookie-?notice|cookie-?consent|cookieconsent|cookie-?banner|"
    r"cookies?-?(?:popup|alert|bar|warning|policy|accept)|t-cookies|klaro|ccm19|cookie_agree",
    re.I,
)
_COOKIE_TEXT = re.compile(r"cookie|куки", re.I)
_COOKIE_CONTEXT = re.compile(r"соглас|использ|принять|принимаю|accept|продолжая", re.I)
# Visitor-tracking categories: they set cookies whatever the provider's country.
_TRACKING = frozenset({Category.ANALYTICS, Category.ADS, Category.CHAT})


@dataclass(slots=True)
class PolicyInfo:
    url: str | None = None
    text: str = ""
    fetched: bool = False
    is_pdf: bool = False
    error: str | None = None
    # Found inside a general legal document (user agreement) rather than a policy link.
    indirect_label: str | None = None


@dataclass(slots=True)
class ComplianceInput:
    final_url: str | None
    page: Page
    deps: list[Dependency]
    policy: PolicyInfo = field(default_factory=PolicyInfo)
    inns: list[str] = field(default_factory=list)
    operator: RknOperator | None = None
    operator_error: str | None = None
    page_problem: str | None = None


# Checks that are concluded from the page markup; meaningless if the page is an
# anti-bot stub or an empty JavaScript shell.
_HTML_CHECKS = frozenset(
    {
        "Политика обработки персональных данных",
        "Согласие на обработку в формах",
        "Уведомление о cookies",
        "Трансграничная передача данных",
    }
)


def _mark_unverifiable(checks: list[Check], problem: str) -> None:
    for c in checks:
        if c.title not in _HTML_CHECKS:
            continue
        found_something = c.status is Status.OK and c.link  # e.g. a policy link was found
        if found_something or (c.status is Status.WARN and c.title != "Уведомление о cookies"):
            continue
        c.status = Status.UNKNOWN
        c.details = f"Не проверено: {problem}."
        c.recommendation = "Проверьте вручную или запустите проверку с параметром --browser."


def find_policy_link(links: list[Link], base: str) -> str | None:
    """Best candidate for the privacy-policy link on the page."""
    scored: list[tuple[int, str]] = []
    for link in links:
        href = link.href.strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        score = 0
        text = link.text.lower()
        if "персональн" in text:
            score += 3
        if "конфиденциальн" in text or "privacy" in text:
            score += 2
        if _POLICY_TEXT.search(text):
            score += 1
        if _POLICY_HREF.search(href):
            score += 1
        if score >= 2:
            scored.append((score, urljoin(base, href)))
    if not scored:
        return None
    scored.sort(key=lambda item: -item[0])
    return scored[0][1]


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
            i.type in ("email", "tel") or _PD_FIELD.search(f"{i.name} {i.hint}") for i in fields
        ):
            result.append(form)
    return result


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
    forms = pd_forms(page)
    foreign_visitor = [d for d in data.deps if d.foreign and d.category.info.visitor_data]
    tracking = [d for d in data.deps if d.category in _TRACKING]

    # 1. Policy published.
    policy = data.policy
    if policy.url is None:
        checks.append(
            Check(
                GROUP_152,
                "Политика обработки персональных данных",
                Status.FAIL,
                "В коде главной страницы нет ссылки на политику обработки персональных данных. "
                "Если подвал сайта подгружается скриптом, проверьте вручную.",
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
        checks.append(
            Check(
                GROUP_152,
                "Политика обработки персональных данных",
                Status.WARN,
                f"Ссылка на политику есть, но страница не открылась: {policy.error}.",
                "Проверьте, что ссылка рабочая.",
                link=policy.url,
            )
        )
    else:
        checks.append(
            Check(
                GROUP_152,
                "Политика обработки персональных данных",
                Status.OK,
                "Политика опубликована" + (" (PDF)." if policy.is_pdf else "."),
                link=policy.url,
            )
        )
        if policy.fetched and not policy.is_pdf:
            checks.append(_policy_content(policy.text, bool(foreign_visitor)))

    # 2. Consent in forms.
    if not forms:
        checks.append(
            Check(
                GROUP_152,
                "Согласие на обработку в формах",
                Status.UNKNOWN,
                "На главной странице нет форм с персональными данными. Проверьте формы на "
                "других страницах вручную.",
            )
        )
    else:
        no_consent = [f for f in forms if not _form_has_consent(f)]
        prechecked = [f for f in forms if any(i.type == "checkbox" and i.checked for i in f.inputs)]
        if no_consent:
            checks.append(
                Check(
                    GROUP_152,
                    "Согласие на обработку в формах",
                    Status.FAIL,
                    f"Форм с персональными данными: {len(forms)}, без согласия на обработку: "
                    f"{len(no_consent)}.",
                    "Добавьте в каждую форму отдельный чекбокс согласия со ссылкой на текст "
                    "согласия. С 1 сентября 2025 года согласие должно оформляться отдельно от "
                    "других документов (152-ФЗ, ст. 9).",
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

    # 3. Cookie notice.
    if tracking:
        names = ", ".join(dict.fromkeys(d.service for d in tracking))
        if has_cookie_notice(html):
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
                    f"Сайт использует {names}, но уведомление о cookies не найдено. "
                    "Роскомнадзор относит данные метрических сервисов к персональным.",
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
                "Перед трансграничной передачей нужно уведомить Роскомнадзор (152-ФЗ, ст. 12, "
                "действует с 1 марта 2023 года) или заменить сервисы на российские.",
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
                + (" При этом на нём есть формы сбора данных." if forms else ""),
                "Базы с персональными данными граждан РФ должны находиться в России "
                "(152-ФЗ, ст. 18 ч. 5). Перенесите сайт и базу к российскому провайдеру.",
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
                Status.FAIL,
                "Сайт открывается без HTTPS: данные из форм передаются в открытом виде.",
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
    return checks


def _form_has_consent(form: Form) -> bool:
    if any(i.type == "checkbox" for i in form.inputs) and _CONSENT_TEXT.search(form.text):
        return True
    return bool(re.search(r"персональн\w* данн|соглас\w* на обработк", form.text, re.I))


def _policy_content(text: str, foreign: bool) -> Check:
    low = text.lower()
    required = {
        "ссылка на 152-ФЗ": "152-фз" in low or "о персональных данных" in low,
        "кто оператор": "оператор" in low,
        "цели обработки": bool(re.search(r"цел[ьи]\w*", low)),
        "права субъекта и отзыв согласия": "отзыв" in low or "права субъект" in low,
    }
    if foreign:
        required["трансграничная передача"] = "трансграничн" in low
    missing = [name for name, ok in required.items() if not ok]
    if not missing:
        return Check(
            GROUP_152,
            "Содержание политики",
            Status.OK,
            "В политике есть основные обязательные разделы.",
        )
    return Check(
        GROUP_152,
        "Содержание политики",
        Status.WARN,
        "В тексте политики не найдено: " + ", ".join(missing) + ".",
        "Дополните политику недостающими разделами.",
    )


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
    if data.operator_error:
        return Check(GROUP_152, title, Status.UNKNOWN, f"ИНН {inn}: {data.operator_error}.")
    if data.operator is None:
        return Check(
            GROUP_152,
            title,
            Status.WARN,
            f"Организация с ИНН {inn} не найдена в реестре операторов персональных данных.",
            "Почти все операторы обязаны подать уведомление в Роскомнадзор до начала "
            "обработки данных (152-ФЗ, ст. 22).",
        )
    op = data.operator
    since = op.registered.strftime("%d.%m.%Y") if op.registered else "?"
    return Check(
        GROUP_152,
        title,
        Status.OK,
        f"{op.name} (ИНН {inn}) в реестре: № {op.reg_number} от {since}.",
        link=op.url,
    )


async def fetch_policy(client: httpx.AsyncClient, url: str) -> PolicyInfo:
    info = PolicyInfo(url=url)
    try:
        resp = await client.get(url)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        info.error = type(exc).__name__
        return info
    info.fetched = True
    content_type = resp.headers.get("content-type", "")
    if "pdf" in content_type or urlsplit(url).path.lower().endswith(".pdf"):
        info.is_pdf = True
    else:
        info.text = parse_page(resp.text[:3_000_000]).text
    return info


async def run_compliance(
    client: httpx.AsyncClient,
    final_url: str | None,
    html: str,
    deps: list[Dependency],
    page_problem: str | None = None,
) -> list[Check]:
    page = parse_page(html)
    data = ComplianceInput(final_url=final_url, page=page, deps=deps, page_problem=page_problem)
    base = final_url or ""
    policy_url = find_policy_link(page.links, base) if base else None
    if policy_url:
        data.policy = await fetch_policy(client, policy_url)
    elif base and (legal := find_legal_link(page.links, base)):
        doc = await fetch_policy(client, legal[0])
        if doc.fetched and "персональн" in doc.text.lower():
            doc.indirect_label = legal[1][:60]
            data.policy = doc
    if base:
        data.inns, _ = await discover_inns(client, base, html, data.policy.text)
    if data.inns:
        try:
            data.operator = await rkn_operator(client, data.inns[0])
        except ModuleError as exc:
            data.operator_error = str(exc)
    return evaluate(data, html)
