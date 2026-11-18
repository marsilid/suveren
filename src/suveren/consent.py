"""Does the cookie banner work? A browser opens the home page with no cookies and watches
whether counters (Метрика, Google Analytics, pixels: analytics and ads in the services
database) get data before the visitor does anything; then it presses the banner's
"reject" button, as a visitor would, opens the page again and watches once more.

Russian law is milder than the GDPR here: Roskomnadzor holds counters' data to be
personal data, but many sites get by with a notice. Data sent before any action is
therefore a warning; data sent after the visitor said no is a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

from suveren.checks import GROUP_152, Check, Evidence, Status
from suveren.models import Category
from suveren.services import PAGE_SERVICES, scan_page

TITLE = "Отказ от cookies: слушаются ли его счётчики"
_TRACKING = frozenset({Category.ANALYTICS, Category.ADS})
_ADS = frozenset(s.name for s in PAGE_SERVICES if s.category is Category.ADS)
# Consent managers are filed under analytics, but their requests after a refusal are the
# banner recording it.
_CONSENT_MANAGERS = frozenset({"OneTrust", "Cookiebot", "Usercentrics", "Didomi"})
# Requests that carry a counter's data: a hit is an image, a beacon, XHR or fetch. Loading
# the counter's own script is not a hit (the script waits for consent on good sites).
_NOT_HITS = frozenset({"script", "stylesheet", "font", "document", "manifest"})

# Banner buttons that refuse, as visitors see them. Only these are ever clicked.
# The whole text must be the refusal: "Отказаться от рассылки" is not a banner button.
_COOKIES = r"(?: cookies?| файлы cookies?| куки)?"
REJECT_RE = (
    r"^(?:(?:отклонить|отказаться|запретить|не принимать|не согласен|не соглашаюсь|reject|"
    r"decline|deny|refuse)(?: все| всё| all)?" + _COOKIES + "|"
    r"(?:(?:принять|разрешить|использовать|оставить|сохранить) )?только (?:необходимые|"
    r"обязательные|технические|функциональные)" + _COOKIES + "|"
    r"(?:accept |allow |use )?(?:only )?(?:strictly )?(?:necessary|essential|required)"
    r"(?: cookies)?(?: only)?)$"
)


@dataclass(slots=True)
class Request:
    url: str
    kind: str  # Playwright's resource type: image, ping, xhr, fetch, script, ...
    ms: int  # since the page started to load


@dataclass(slots=True)
class ConsentProbe:
    url: str
    before: list[Request] = field(default_factory=list)  # first visit, no action
    button: str | None = None  # the text of the reject button pressed, None: not found
    after: list[Request] = field(default_factory=list)  # the page opened again after it
    problem: str | None = None  # why the experiment did not run
    # (status, HTML) of each opening: a bot wall in place of the page is no answer.
    loads: list[tuple[int | None, str]] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "button": self.button,
            "problem": self.problem,
            "before": [r.url for r in self.before],
            "after": [r.url for r in self.after],
        }


def _consent_mode_denied(url: str) -> bool:
    """A Google hit sent with analytics and ads storage denied (Consent Mode, gcs=G100):
    a cookieless ping Google sends by design after a refusal."""
    gcs = parse_qs(urlsplit(url).query).get("gcs", [""])[0]
    return len(gcs) == 4 and gcs.startswith("G1") and gcs[2:] == "00"


def counter_hits(requests: list[Request], host: str) -> dict[str, list[Request]]:
    """Service name -> its hits, in order; requests to the site's own hosts are not hits."""
    own = host.lower().removeprefix("www.")
    found: dict[str, list[Request]] = {}
    for r in requests:
        if r.kind in _NOT_HITS:
            continue
        for service, _ in scan_page(r.url, own):
            if service.category in _TRACKING and service.name not in _CONSENT_MANAGERS:
                found.setdefault(service.name, []).append(r)
                break
    return found


def _seconds(ms: int) -> str:
    return f"{ms / 1000:.1f}".replace(".", ",") + " с"


def _names(hits: dict[str, list[Request]], *, when: bool = False) -> str:
    if not when:
        return ", ".join(hits)
    return ", ".join(f"{name} (через {_seconds(rs[0].ms)})" for name, rs in hits.items())


def _evidence(hits: dict[str, list[Request]], label: str) -> list[Evidence]:
    return [Evidence("request", f"{label}: {name}", rs[0].url[:300]) for name, rs in hits.items()]


def consent_check(probe: ConsentProbe, host: str) -> Check:
    if probe.problem:
        return Check(GROUP_152, TITLE, Status.UNKNOWN, f"Не проверено: {probe.problem}.")
    before = counter_hits(probe.before, host)
    after_all = counter_hits(probe.after, host)
    pings = {n: rs for n, rs in after_all.items() if all(_consent_mode_denied(r.url) for r in rs)}
    after = {n: rs for n, rs in after_all.items() if n not in pings and n not in _ADS}
    ads = {n: rs for n, rs in after_all.items() if n not in pings and n in _ADS}
    pressed = f"«{probe.button}»" if probe.button else ""
    notes = ""
    if ads:
        notes += (
            f" После отказа запросы получали рекламные сервисы ({_names(ads)}): это может быть "
            "показ рекламы без персонализации, а может быть и сбор данных — по запросам не "
            "различить."
        )
    if pings:
        notes += (
            f" После отказа {_names(pings)} {'отправлял' if len(pings) == 1 else 'отправляли'} "
            "запросы без cookies (режим согласия Google, gcs=G100): так задумано Google, но IP "
            "посетителя и адрес страницы сервис всё равно получает."
        )
    evidence = (
        _evidence(before, "до действия")
        + _evidence(after, "после отказа")
        + _evidence(ads, "после отказа")
    )
    law = "152-ФЗ, ст. 9"
    if probe.button and after:
        return Check(
            GROUP_152,
            TITLE,
            Status.FAIL,
            f"Отказ не работает: после нажатия {pressed} в баннере и повторного открытия "
            f"страницы данные снова получили {_names(after)}: баннер даёт выбор, которого на "
            "деле нет. Роскомнадзор относит данные счётчиков к персональным, а без согласия "
            "обрабатывать их можно только на другом основании из ст. 6 152-ФЗ."
            + (f" До нажатия данные получали: {_names(before, when=True)}." if before else "")
            + notes,
            "Настройте баннер так, чтобы после отказа счётчики не запускались: код Метрики, "
            "Google Analytics и пикселей вызывайте только после согласия посетителя.",
            law=law,
            evidence=evidence,
        )
    if before:
        if probe.button:
            tail = (
                f" После нажатия {pressed} и повторного открытия страницы счётчики данных не "
                "получали: отказ работает."
            )
        else:
            tail = (
                " Работает ли отказ, не проверено: кнопку вроде «Отклонить» или «Только "
                "необходимые» на странице не нашли (её может не быть, или баннер устроен так, "
                "что её не распознать)."
            )
        return Check(
            GROUP_152,
            TITLE,
            Status.WARN,
            "Счётчики и рекламные сервисы получили данные сразу при загрузке страницы, до "
            f"любого действия посетителя: {_names(before, when=True)}.{tail}{notes} "
            "Роскомнадзор считает данные счётчиков персональными; закон здесь мягче "
            "европейского GDPR, и многие сайты обходятся уведомлением, но согласие, которое "
            "спрашивают уже после сбора данных, мало что значит.",
            "Запускайте счётчики после согласия посетителя в баннере, а не при загрузке страницы.",
            law=law,
            evidence=evidence,
        )
    if ads:
        return Check(
            GROUP_152,
            TITLE,
            Status.WARN,
            f"До действия посетителя счётчики данных не получали, после нажатия {pressed} "
            f"счётчики тоже молчат.{notes}",
            "Проверьте, что после отказа рекламные сервисы показывают рекламу без "
            "персонализации и не получают данных для неё.",
            law=law,
            evidence=evidence,
        )
    if probe.button:
        details = (
            f"До действия посетителя счётчики данных не получали, после нажатия {pressed} и "
            f"повторного открытия страницы — тоже.{notes}"
        )
    elif probe.before:
        details = (
            "При загрузке страницы, до действия посетителя, счётчики и рекламные сервисы "
            "данных не получали."
        )
    else:
        details = "Браузер не записал ни одного запроса страницы, проверять нечего."
    return Check(GROUP_152, TITLE, Status.OK, details, law=law, evidence=evidence)
