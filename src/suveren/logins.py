"""Sign-in through foreign services (Google, Apple, Facebook...) on a Russian site.

Since 1 December 2023 a Russian site owner who lets users in only after sign-in must
authorise users located in Russia by a Russian phone number, Gosuslugi (ЕСИА), the
Unified Biometric System or another system owned by Russians (VK ID, Yandex ID,
Sber ID, T-ID...). Checked 2026-10-17:
- 149-ФЗ, ст. 8 ч. 10 (added by 406-ФЗ of 31.07.2023, in force since 01.12.2023):
  https://www.consultant.ru/document/cons_doc_LAW_61798/78b773a28f3ad19eb234697b20ab1d48c09f748a/
- КоАП, ст. 13.55 (added by 199-ФЗ of 26.06.2026, in force since 07.07.2026), fines of
  10–20 thousand ₽ for citizens, 30–50 for officials, 500–700 for legal entities:
  https://www.consultant.ru/document/cons_doc_LAW_34661/eecaf3bcdcd8f21011f025127298179a3bfd8877/
  https://www.garant.ru/article/2136195/
A foreign e-mail used as a login is not a sign-in *system* and is not flagged.

Only page code counts (links, form targets, script tags, element attributes) and
the visible text of buttons, not the words of an article: "how to sign in with
Google" on a blog alone is at most a warning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urljoin, urlsplit

from suveren.checks import GROUP_LAWS, Check, Status
from suveren.page import Page, page_code
from suveren.utils import registrable_domain

TITLE = "Вход через иностранные сервисы"
LAW = "149-ФЗ, ст. 8 ч. 10"

# Evidence kinds. Strong ones show the site actually starts a sign-in with the service.
OAUTH, PATH, WIDGET, SDK, BUTTON = "oauth", "path", "widget", "sdk", "button"
STRONG = frozenset({OAUTH, PATH, WIDGET})


@dataclass(frozen=True, slots=True)
class Provider:
    name: str
    # Authorisation endpoints: a link or script that goes there starts a sign-in.
    endpoints: tuple[str, ...] = ()
    # Markup of a configured sign-in button or widget.
    widgets: tuple[str, ...] = ()
    # A library for sign-in buttons: loaded, but maybe never shown.
    sdk: tuple[str, ...] = ()
    # The name in the site's own routes (/auth/google) and in widget settings.
    names: tuple[str, ...] = ()


FOREIGN = (
    Provider(
        "Google",
        endpoints=(r"accounts\.google\.com/(?:o/oauth2|signin/oauth)",),
        widgets=(r"\bg_id_onload\b", r"\bg_id_signin\b", r"\bg-signin2\b"),
        sdk=(r"accounts\.google\.com/gsi/client",),
        names=("google", "google-oauth2", "googleoauth", "gplus", "googleplus"),
    ),
    Provider(
        "Apple",
        endpoints=(r"appleid\.apple\.com/auth/authorize",),
        widgets=(r"\bappleid-signin\b",),
        sdk=(r"appleid\.auth\.js",),
        names=("apple", "appleid", "apple-id"),
    ),
    Provider(
        "Facebook",
        endpoints=(r"facebook\.com/(?:v\d+\.\d+/)?dialog/oauth",),
        widgets=(r"\bfb-login-button\b", r"\bFB\.login\("),
        names=("facebook", "fb"),
    ),
    Provider("GitHub", endpoints=(r"github\.com/login/oauth/authorize",), names=("github",)),
    Provider(
        "Microsoft",
        endpoints=(
            r"login\.microsoftonline\.com/[\w.-]+/oauth2",
            r"login\.live\.com/oauth20_authorize",
        ),
        sdk=(r"alcdn\.msauth\.net",),
        names=("microsoft", "azure", "azuread", "windowslive", "outlook"),
    ),
    Provider(
        "X (Twitter)",
        endpoints=(
            r"(?:api\.)?(?:twitter|x)\.com/(?:i/oauth2/authorize|oauth/authori[sz]e|"
            r"oauth/authenticate)",
        ),
        names=("twitter",),
    ),
    Provider(
        "Telegram",
        endpoints=(r"oauth\.telegram\.org/auth",),
        widgets=(r"data-telegram-login\s*=",),
        names=("telegram",),
    ),
    Provider("Steam", endpoints=(r"steamcommunity\.com/openid/login",), names=("steam",)),
    Provider(
        "Discord",
        endpoints=(r"discord(?:app)?\.com/(?:api/)?oauth2/authorize",),
        names=("discord",),
    ),
    Provider("LinkedIn", endpoints=(r"linkedin\.com/oauth/v2/authorization",), names=("linkedin",)),
    Provider(
        "Instagram", endpoints=(r"api\.instagram\.com/oauth/authorize",), names=("instagram",)
    ),
)

# Allowed by the law: Gosuslugi and Russian-owned sign-in systems. Only reported.
RUSSIAN = (
    Provider(
        "VK ID",
        endpoints=(r"(?:oauth|id)\.vk\.(?:com|ru)/authorize", r"login\.vk\.(?:com|ru)"),
        sdk=(r"@vkid/sdk", r"\bVKIDSDK\b"),
        names=("vk", "vkontakte", "vkid", "vk-id"),
    ),
    Provider(
        "Яндекс ID",
        endpoints=(r"oauth\.yandex\.(?:ru|com)/authorize",),
        sdk=(r"passport-sdk", r"\bYaAuthSuggest\b"),
        names=("yandex", "yandexid", "yandex-id"),
    ),
    Provider(
        "Госуслуги", endpoints=(r"esia\.gosuslugi\.ru/aas/oauth2",), names=("esia", "gosuslugi")
    ),
    Provider(
        "Сбер ID",
        endpoints=(r"id\.sber\.ru/", r"online\.sberbank\.ru/CSAFront/oidc"),
        names=("sber", "sberid", "sber-id"),
    ),
    Provider(
        "Т-ID",
        endpoints=(r"id\.(?:tbank|tinkoff)\.ru/auth",),
        names=("tinkoff", "tbank", "tinkoffid"),
    ),
    Provider("Mail.ru", endpoints=(r"oauth\.mail\.ru/login",), names=("mailru",)),
    Provider(
        "Одноклассники",
        endpoints=(r"connect\.ok\.ru/oauth",),
        names=("okru", "odnoklassniki"),  # a bare /sso/ok/ may be a status page
    ),
)

# Button labels in the visible text and in aria-label/title/alt/value attributes.
# Apple's own Russian label is "Вход с Apple", hence the bare "с".
_VERB = (
    r"(?<!\w)(?:войти|вход|входа|авторизоваться|авторизация|зарегистрироваться|регистрация|"
    r"продолжить|sign\s?in|sign\s?up|log\s?in|continue)"
)
_LABEL_NAMES = {
    "Google": r"google",
    "Apple": r"apple(?:\s?id)?",
    "Facebook": r"facebook",
    "GitHub": r"github",
    "Microsoft": r"microsoft",
    "X (Twitter)": r"twitter",
    "Telegram": r"telegram|телеграм\w*",
    "Steam": r"steam",
    "Discord": r"discord",
    "LinkedIn": r"linkedin",
    "Instagram": r"instagram",
}
_LABEL = re.compile(
    _VERB
    + r"\s+(?:через|с\s+помощью|с|with|using|via)\s+(?:аккаунт\w*\s+|account\s+)?("
    + "|".join(_LABEL_NAMES.values())
    + r")(?!\w)",
    re.I,
)
_ATTR_TEXT = re.compile(r"""(?:aria-label|title|alt|value)\s*=\s*["']([^"'<>]{3,100})["']""", re.I)
# Icons inside a button are long SVG paths, so the limit is generous.
_BUTTON = re.compile(r"<button\b[^>]*>(.{0,4000}?)</button\s*>", re.I | re.S)
_TAG = re.compile(r"<[^>]+>")
_MAX_LABEL = 60  # a button says "Войти через Google", an article headline says more


def _labels(html: str, page: Page, code: str) -> list[str]:
    """Short texts of links and buttons and accessible labels: where a sign-in button
    names its service. Headlines and paragraphs are left out."""
    texts = [link.text for link in page.links]
    texts += [" ".join(_TAG.sub(" ", m.group(1)).split()) for m in _BUTTON.finditer(html)]
    texts += [m.group(1) for m in _ATTR_TEXT.finditer(code)]
    return [t for t in texts if 3 <= len(t) <= _MAX_LABEL]


# The site's own sign-in routes: /auth/google, /login/apple/, /oauth/redirect/github.
_AUTH_SEGMENT = (
    r"(?:auth|oauth2?|login|signin|sign-in|sign|sso|omniauth|social-?auth|social-?login|"
    r"sociallogin|externallogin|external-login|extidp|idp)"
)
_ALL_NAMES = "|".join(
    sorted({n for p in FOREIGN + RUSSIAN for n in p.names}, key=len, reverse=True)
)
_OWN_PATH = re.compile(rf"/{_AUTH_SEGMENT}/(?:[\w-]+/)?({_ALL_NAMES})(?:[/?#.]|$)", re.I)
# Plugins name the network in a parameter (WordPress Nextend, 1C-Bitrix). A bare
# ?provider= counts only on a sign-in route: ?service=apple may be a repair shop.
_OWN_QUERY = re.compile(
    rf"[?&](?:loginSocial|auth_service_id)=({_ALL_NAMES})(?:oauth\w*)?(?:[&#]|$)", re.I
)
_AUTH_QUERY = re.compile(rf"[?&](?:provider|backend)=({_ALL_NAMES})(?:oauth\w*)?(?:[&#]|$)", re.I)
_AUTH_WORD = re.compile(r"auth|login|signin|sign-in|sso", re.I)
_PROVIDER_KEYS = {n.lower(): (p.name, True) for p in FOREIGN for n in p.names} | {
    n.lower(): (p.name, False) for p in RUSSIAN for n in p.names
}

# uLogin (a Russian widget) shows whatever networks the site lists in its settings.
_ULOGIN = re.compile(r"""data-ulogin(?:id)?\s*=\s*["']([^"']+)["']""", re.I)
_ULOGIN_NAMES = {
    "google": "Google", "googleplus": "Google", "apple": "Apple", "facebook": "Facebook",
    "github": "GitHub", "microsoft": "Microsoft", "liveid": "Microsoft", "twitter": "X (Twitter)",
    "telegram": "Telegram", "steam": "Steam", "discord": "Discord", "linkedin": "LinkedIn",
    "instagram": "Instagram",
}  # fmt: skip

_URL_TAIL = re.compile(r"[^\s\"'<>\\]*")

# Links to the sign-in page, to look at the buttons there too.
_LOGIN_TEXT = re.compile(
    r"^(?:войти|вход|вход на сайт|войти на сайт|войти в (?:личный )?кабинет|личный кабинет|"
    r"кабинет|авторизация|авторизоваться|вход \| регистрация|вход / регистрация|вход и регистрация|"
    r"войти / зарегистрироваться|войти или зарегистрироваться|log ?in|sign ?in)$",
    re.I,
)
_LOGIN_HREF = re.compile(
    r"/(?:login|signin|sign-in|sign_in|sign|auth|lk|cabinet|personal|account|user/login|"
    r"members/login)"
    r"(?:/|\.php|$)",
    re.I,
)


@dataclass(frozen=True, slots=True)
class LoginEvidence:
    provider: str
    kind: str  # OAUTH, PATH, WIDGET, SDK or BUTTON
    where: str  # page path
    sample: str = ""
    foreign: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "kind": self.kind,
            "where": self.where,
            "sample": self.sample,
            "foreign": self.foreign,
        }


def _short(url: str, limit: int = 70) -> str:
    url = re.sub(r"^(?:https?:)?//", "", unquote(url))
    return url if len(url) <= limit else url[: limit - 1] + "…"


def _own_route(url: str, site: str) -> tuple[str, bool] | None:
    """(provider, foreign) if ``url`` is the site's own route that starts a sign-in."""
    parts = urlsplit(url)
    if parts.hostname and registrable_domain(parts.hostname.lower()) != site:
        return None
    query = f"?{parts.query}"
    match = _OWN_PATH.search(parts.path) or _OWN_QUERY.search(query)
    if not match and _AUTH_WORD.search(parts.path):
        match = _AUTH_QUERY.search(query)
    return _PROVIDER_KEYS.get(match.group(1).lower()) if match else None


def find_evidence(
    html: str, page: Page, url: str, where: str, loaded_urls: list[str] | tuple[str, ...] = ()
) -> list[LoginEvidence]:
    """Signs of sign-in through foreign and Russian services on one page."""
    code = page_code(html)
    site = registrable_domain((urlsplit(url).hostname or "").lower())
    requests = "\n".join(loaded_urls)
    found: list[LoginEvidence] = []

    def add(provider: str, kind: str, sample: str, foreign: bool = True) -> None:
        if not any(e.provider == provider and e.kind == kind for e in found):
            found.append(LoginEvidence(provider, kind, where, sample, foreign))

    for foreign, providers in ((True, FOREIGN), (False, RUSSIAN)):
        for p in providers:
            for rx in p.endpoints:
                match = re.search(rf"(?<![\w-]){rx}", code, re.I)
                if match:
                    tail = _URL_TAIL.match(code, match.start())
                    add(p.name, OAUTH, _short(tail.group(0) if tail else match.group(0)), foreign)
            for rx in p.widgets:
                match = re.search(rx, code)
                if match:
                    add(p.name, WIDGET, match.group(0).rstrip("=( "), foreign)
            for rx in p.sdk:
                match = re.search(rx, code) or re.search(rx, requests)
                if match:
                    add(p.name, SDK, match.group(0), foreign)

    targets = [link.href for link in page.links] + [form.action for form in page.forms]
    for target in targets:
        target = target.strip()
        if not target or target.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        absolute = urljoin(url, target)
        route = _own_route(absolute, site)
        if route:
            add(route[0], PATH, _short(absolute), route[1])

    for match in _ULOGIN.finditer(code):
        networks = re.findall(r"(?:providers|hidden)=([\w,]+)", match.group(1).lower())
        for name in ",".join(networks).split(","):
            if name in _ULOGIN_NAMES:
                add(_ULOGIN_NAMES[name], WIDGET, "виджет uLogin")

    for text in _labels(html, page, code):
        for match in _LABEL.finditer(text):
            name = match.group(1)
            provider = next(
                (p for p, rx in _LABEL_NAMES.items() if re.fullmatch(rx, name, re.I)), None
            )
            if provider:
                add(provider, BUTTON, " ".join(match.group(0).split()))
    return found


def find_login_page(page: Page, base: str) -> str | None:
    """URL of the sign-in page on the same site, if the page links to one."""
    site = registrable_domain((urlsplit(base).hostname or "").lower())
    home = base.split("#", 1)[0].rstrip("/")
    by_href: str | None = None
    for link in page.links:
        href = link.href.strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        url = urljoin(base, href).split("#", 1)[0]
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            continue
        if registrable_domain(parts.hostname.lower()) != site or url.rstrip("/") == home:
            continue
        if _LOGIN_TEXT.match(link.text.strip()):
            return url
        if by_href is None and _LOGIN_HREF.search(parts.path):
            by_href = url
    return by_href


_KIND_RU = {
    OAUTH: "ссылка на вход",
    PATH: "ссылка на вход",
    WIDGET: "виджет входа",
    SDK: "скрипт кнопки входа",
    BUTTON: "кнопка",
}


_BEST_FIRST = (OAUTH, PATH, WIDGET, BUTTON, SDK)


def short_path(path: str) -> str:
    """A path for people: session tokens and other long segments become "…"."""
    return "/".join(s if len(s) <= 24 else "…" for s in path.split("/"))


def _describe(items: list[LoginEvidence]) -> str:
    """The best evidence per service and the pages it was seen on."""
    by_provider: dict[str, list[LoginEvidence]] = {}
    for e in items:
        by_provider.setdefault(e.provider, []).append(e)
    parts = []
    for provider, found in list(by_provider.items())[:5]:
        best = min(found, key=lambda e: _BEST_FIRST.index(e.kind))
        pages = list(dict.fromkeys(e.where for e in found if e.kind == best.kind))
        where = ", ".join(pages[:2]) + (f" и ещё {len(pages) - 2}" if len(pages) > 2 else "")
        sample = f"«{best.sample}»" if best.kind == BUTTON else best.sample
        page_word = "страница" if len(pages) == 1 else "страницы"
        parts.append(f"{provider} — {_KIND_RU[best.kind]} {sample} ({page_word} {where})")
    if len(by_provider) > 5:
        parts.append(f"и ещё {len(by_provider) - 5}")
    return "; ".join(parts)


def _is_strong(items: list[LoginEvidence]) -> bool:
    """A sign-in route or widget, or a button together with the provider's script."""
    kinds = {e.kind for e in items}
    return bool(kinds & STRONG) or {SDK, BUTTON} <= kinds


_FIX = (
    "Для пользователей из России оставьте вход только по номеру телефона, через Госуслуги "
    "или российские сервисы (VK ID, Яндекс ID, Сбер ID, Т-ID). Требование действует с "
    "1 декабря 2023 года для сайтов российских компаний и граждан."
)
_FINE = (
    "С 7 июля 2026 года за нарушение штрафуют по ст. 13.55 КоАП: юрлицо — на 500–700 тыс. ₽, "
    "должностное лицо — на 30–50 тыс. ₽, гражданина — на 10–20 тыс. ₽."
)


def login_check(
    evidence: list[LoginEvidence],
    pages: list[str],
    problem: str | None = None,
    shell: str | None = None,
) -> Check:
    """One verdict for the site. ``pages`` are the paths looked at, home page first;
    ``shell`` is the sign-in page if its content is drawn by scripts."""
    russian = list(dict.fromkeys(e.provider for e in evidence if not e.foreign))
    allowed = f" Вход через {', '.join(russian)} разрешён." if russian else ""
    by_provider: dict[str, list[LoginEvidence]] = {}
    for e in evidence:
        if e.foreign:
            by_provider.setdefault(e.provider, []).append(e)
    strong = {p: items for p, items in by_provider.items() if _is_strong(items)}
    if strong:
        shown = [e for items in strong.values() for e in items]
        return Check(
            GROUP_LAWS,
            TITLE,
            Status.FAIL,
            f"На сайте есть вход через {', '.join(strong)}: {_describe(shown)}.{allowed}",
            f"{_FIX} Если эти кнопки уже скрыты от пользователей из России, требование "
            f"соблюдено: Suveren видит сайт из той страны, где запущен. {_FINE}",
            law=LAW,
        )
    if by_provider:
        names = ", ".join(by_provider)
        found = [e for items in by_provider.values() for e in items]
        return Check(
            GROUP_LAWS,
            TITLE,
            Status.WARN,
            f"Возможен вход через {names}: {_describe(found)}. Ссылку, которая начинает вход, "
            f"найти не удалось: проверьте страницу входа вручную.{allowed}",
            f"Если вход через {names} действительно есть, это возможное нарушение. {_FIX}",
            law=LAW,
        )
    if problem and len(pages) <= 1:
        return Check(
            GROUP_LAWS,
            TITLE,
            Status.UNKNOWN,
            f"Не проверено: {problem}.",
            "Проверьте вручную или запустите проверку с параметром --browser.",
            law=LAW,
        )
    where = ", ".join(pages[:6]) + (" и др." if len(pages) > 6 else "")
    return Check(
        GROUP_LAWS,
        TITLE,
        Status.OK,
        f"Входа через Google, Apple и другие иностранные сервисы не найдено (проверено: "
        f"{where}). "
        + (
            f"Страница входа {shell} собирается скриптами: точнее проверит режим --browser."
            if shell
            else "Если вход открывается во всплывающем окне, проверьте его вручную."
        )
        + allowed,
        law=LAW,
    )
