"""Draft documents from what a scan found: a privacy policy and a consent form.

A draft, never a finished document: it fills in what Suveren saw (the site, the
services that receive visitors' data and their countries, cookies and analytics,
where the server is) and leaves the rest as [ЗАПОЛНИТЕ: …]. Every draft starts and
ends with a warning to have it checked by a lawyer. The structure follows the
recommendations of Роскомнадзор on the contents of a policy (152-ФЗ, ст. 18.1).
"""

from __future__ import annotations

from datetime import date
from typing import Any

from suveren.utils import country_name

WARNING = (
    "> **ЧЕРНОВИК, НЕ ЮРИДИЧЕСКИЙ ДОКУМЕНТ.** Составлен Suveren автоматически по тому, что "
    "видно снаружи сайта. Проверьте и дополните его с юристом: Suveren не знает, какие "
    "данные вы собираете на самом деле, зачем и на каком основании."
)
FILL = "[ЗАПОЛНИТЕ: {}]"
KINDS = ("policy", "consent")

# Categories of dependencies whose services receive visitors' data.
DATA_CATEGORIES = frozenset(
    {"analytics", "ads", "captcha", "chat", "fonts", "js_cdn", "maps", "video", "social", "cdn",
     "payments", "auth"}
)  # fmt: skip


def _services(report: dict[str, Any]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for d in report.get("dependencies", []):
        if d.get("category") in DATA_CATEGORIES:
            seen.setdefault(d.get("service", ""), d)
    return list(seen.values())


def _hosting(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [d for d in report.get("dependencies", []) if d.get("category") == "hosting"]


def _country(d: dict[str, Any]) -> str:
    code = d.get("country")
    return country_name(code) if code else "страна не определена"


def policy(report: dict[str, Any], today: date | None = None) -> str:
    site = report.get("target", FILL.format("адрес сайта"))
    services = _services(report)
    foreign = [s for s in services if s.get("foreign")]
    hosting = _hosting(report)
    where = (
        ", ".join(f"{h.get('service')} ({_country(h)})" for h in hosting)
        if hosting
        else FILL.format("где находится сервер с базой данных")
    )
    lines = [
        f"# Политика в отношении обработки персональных данных (черновик для {site})",
        "",
        WARNING,
        "",
        f"Составлено: {(today or date.today()):%d.%m.%Y}",
        "",
        "## 1. Общие положения",
        "",
        f"Оператор — {FILL.format('полное наименование, ИНН, ОГРН, адрес')}. Политика "
        "разработана в соответствии с Федеральным законом от 27.07.2006 № 152-ФЗ «О "
        f"персональных данных» и действует для сайта {site}.",
        "",
        "## 2. Цели обработки",
        "",
        f"- {FILL.format('например: обработка заявок посетителей, исполнение договора')}",
        "",
        "## 3. Правовые основания",
        "",
        f"- {FILL.format('согласие субъекта, договор, закон — статья 6 152-ФЗ')}",
        "",
        "## 4. Категории субъектов и перечень данных",
        "",
        f"- {FILL.format('кто: посетители, клиенты; какие данные: имя, телефон, почта…')}",
        "",
        "## 5. Сервисы, которые получают данные посетителей",
        "",
    ]
    if services:
        lines += [
            f"- {s.get('service')} ({_country(s)}): {s.get('category_title', s.get('category'))}"
            for s in services
        ]
    else:
        lines.append("Сторонних сервисов, получающих данные посетителей, Suveren не увидел.")
    lines += ["", "## 6. Трансграничная передача", ""]
    if foreign:
        countries = sorted({_country(s) for s in foreign})
        lines.append(
            "Данные посетителей (IP-адрес, cookies, сведения о браузере) передаются в: "
            + ", ".join(countries)
            + f". {FILL.format('уведомление РКН о трансграничной передаче, ст. 12 152-ФЗ')}"
        )
    else:
        lines.append("Иностранных сервисов, получающих данные, Suveren не увидел.")
    lines += [
        "",
        "## 7. Хранение и локализация",
        "",
        f"Сервер сайта: {where}. Запись и хранение данных граждан РФ — в базах на территории "
        "России (ст. 18 ч. 5 152-ФЗ). " + FILL.format("сроки хранения и порядок уничтожения"),
        "",
        "## 8. Файлы cookie",
        "",
        "Сайт использует файлы cookie"
        + (
            " и сервисы аналитики: "
            + ", ".join(str(s.get("service")) for s in services if s.get("category") == "analytics")
            if any(s.get("category") == "analytics" for s in services)
            else ""
        )
        + ". Посетитель может отключить cookie в настройках браузера.",
        "",
        "## 9. Права субъекта и порядок запросов",
        "",
        f"Запросы и отзыв согласия: {FILL.format('адрес электронной почты и почтовый адрес')}.",
        "",
        "## 10. Меры защиты",
        "",
        FILL.format("правовые, организационные и технические меры, ст. 18.1 и 19 152-ФЗ"),
        "",
        WARNING,
        "",
    ]
    return "\n".join(lines)


def consent(report: dict[str, Any], today: date | None = None) -> str:
    site = report.get("target", FILL.format("адрес сайта"))
    services = _services(report)
    foreign = sorted({_country(s) for s in services if s.get("foreign")})
    lines = [
        f"# Согласие на обработку персональных данных (черновик для {site})",
        "",
        WARNING,
        "",
        "Согласие оформляется отдельно от других документов (152-ФЗ, ст. 9 ч. 1, с 01.09.2025).",
        "",
        f"Я, {FILL.format('ФИО')}, даю согласие {FILL.format('наименование и адрес оператора')} "
        f"на обработку моих персональных данных: {FILL.format('перечень данных')}, в целях "
        f"{FILL.format('цели')}, с использованием сайта {site}.",
        "",
        f"Действия с данными: {FILL.format('сбор, запись, хранение, …, уничтожение')}.",
    ]
    if foreign:
        lines += [
            "",
            "Я согласен на передачу данных (IP-адрес, cookies) сервисам в странах: "
            + ", ".join(foreign)
            + ".",
        ]
    lines += [
        "",
        f"Согласие действует {FILL.format('срок')} и может быть отозвано письмом на "
        f"{FILL.format('адрес')}.",
        "",
        WARNING,
        "",
    ]
    return "\n".join(lines)


def draft(report: dict[str, Any], kind: str, today: date | None = None) -> str:
    if kind == "policy":
        return policy(report, today)
    if kind == "consent":
        return consent(report, today)
    raise ValueError(kind)
