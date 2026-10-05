"""Data model: categories of dependencies, findings and the final report."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any

from suveren.utils import country_name


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()

    @property
    def ru(self) -> str:
        return {0: "инфо", 1: "низкий", 2: "средний", 3: "высокий"}[self.value]

    def lower(self) -> Severity:
        return Severity(max(self.value - 1, Severity.LOW.value))


@dataclass(frozen=True)
class CategoryInfo:
    title: str
    severity: Severity
    risk: str
    alternatives: str
    # Loaded in the visitor's browser, so visitor data (at least the IP) leaves the country.
    visitor_data: bool = False


class Category(str, Enum):
    ZONE = "zone"
    REGISTRAR = "registrar"
    DNS = "dns"
    MAIL = "mail"
    HOSTING = "hosting"
    CDN = "cdn"
    TLS = "tls"
    PAYMENTS = "payments"
    AUTH = "auth"
    ANALYTICS = "analytics"
    ADS = "ads"
    CAPTCHA = "captcha"
    CHAT = "chat"
    FONTS = "fonts"
    JS_CDN = "js_cdn"
    MAPS = "maps"
    VIDEO = "video"
    SOCIAL = "social"

    @property
    def info(self) -> CategoryInfo:
        return CATEGORIES[self]

    @property
    def title(self) -> str:
        return CATEGORIES[self].title


_PD_NOTE = (
    " Скрипт работает в браузере посетителя и передаёт его IP-адрес и cookies на иностранные "
    "серверы. Это может считаться трансграничной передачей персональных данных (152-ФЗ), "
    "о которой нужно уведомлять Роскомнадзор."
)

CATEGORIES: dict[Category, CategoryInfo] = {
    Category.ZONE: CategoryInfo(
        "Доменная зона",
        Severity.LOW,
        "Зоной управляет иностранный реестр. Реестр и регистраторы обязаны выполнять "
        "санкционные требования своей страны и могут заблокировать домен.",
        "Держать основной или резервный домен в зоне .ru или .рф.",
    ),
    Category.REGISTRAR: CategoryInfo(
        "Регистратор домена",
        Severity.MEDIUM,
        "Иностранный регистратор может заблокировать аккаунт или отказать в продлении домена. "
        "Например, в 2022 году Namecheap прекратил обслуживать клиентов из России.",
        "Перенести домен к российскому регистратору: RU-CENTER, REG.RU, R01, Beget.",
    ),
    Category.DNS: CategoryInfo(
        "DNS-серверы",
        Severity.HIGH,
        "Если провайдер DNS заблокирует аккаунт, перестанут работать сразу сайт, почта и все "
        "остальные сервисы домена.",
        "Перенести DNS в Yandex Cloud DNS, Selectel DNS или к российскому регистратору "
        "(RU-CENTER, REG.RU).",
    ),
    Category.MAIL: CategoryInfo(
        "Почта",
        Severity.HIGH,
        "Отключение почтового сервиса означает потерю входящих писем и доступа к архиву "
        "переписки, а вместе с ним — к восстановлению паролей от других сервисов.",
        "Яндекс 360 для бизнеса, VK WorkSpace (Mail.ru для бизнеса) или собственный "
        "почтовый сервер в России.",
    ),
    Category.HOSTING: CategoryInfo(
        "Хостинг сайта",
        Severity.HIGH,
        "Сервер сайта у иностранного провайдера. Провайдер может удалить аккаунт или перестать "
        "принимать оплату из России, и сайт пропадёт вместе с данными. Кроме того, базы с "
        "персональными данными граждан РФ по закону должны храниться в России (152-ФЗ, ст. 18).",
        "Yandex Cloud, Selectel, VK Cloud, Timeweb Cloud, Beget.",
    ),
    Category.CDN: CategoryInfo(
        "CDN и защита от DDoS",
        Severity.MEDIUM,
        "Весь трафик сайта идёт через иностранную сеть доставки. При отключении сайт будет "
        "недоступен, пока не поменяются DNS-записи. Также фиксировались замедления сайтов за "
        "иностранными CDN для пользователей из России.",
        "DDoS-Guard, Qrator, Servicepipe, NGENIX или CDN в Yandex Cloud, Selectel, VK Cloud.",
    ),
    Category.TLS: CategoryInfo(
        "SSL-сертификат",
        Severity.LOW,
        "Сертификат выпустил иностранный удостоверяющий центр. Он может отозвать сертификат "
        "или отказать в продлении: в 2022 году так поступали с рядом российских организаций.",
        "Настроить автоматический выпуск по ACME, чтобы быстро сменить УЦ. Для аудитории "
        "в России можно дополнительно выпустить сертификат НУЦ Минцифры.",
    ),
    Category.PAYMENTS: CategoryInfo(
        "Приём платежей",
        Severity.MEDIUM,
        "Иностранная платёжная система не принимает карты российских банков и может "
        "заблокировать выплаты." + _PD_NOTE,
        "ЮKassa, CloudPayments, Т-Касса, Robokassa, оплата через СБП.",
        visitor_data=True,
    ),
    Category.AUTH: CategoryInfo(
        "Вход через внешний сервис",
        Severity.MEDIUM,
        "При блокировке сервиса пользователи не смогут войти в свои аккаунты." + _PD_NOTE,
        "VK ID, Яндекс ID, Сбер ID или собственная авторизация.",
        visitor_data=True,
    ),
    Category.ANALYTICS: CategoryInfo(
        "Аналитика и пиксели",
        Severity.LOW,
        "Данные о посетителях собирает иностранный сервис." + _PD_NOTE,
        "Яндекс Метрика, Top.Mail.ru, Matomo на собственном сервере.",
        visitor_data=True,
    ),
    Category.ADS: CategoryInfo(
        "Реклама",
        Severity.LOW,
        "Рекламный скрипт иностранной сети." + _PD_NOTE,
        "Яндекс Директ и РСЯ, VK Реклама.",
        visitor_data=True,
    ),
    Category.CAPTCHA: CategoryInfo(
        "Капча",
        Severity.LOW,
        "Если капча не загрузится, посетители не смогут отправить формы." + _PD_NOTE,
        "Yandex SmartCaptcha.",
        visitor_data=True,
    ),
    Category.CHAT: CategoryInfo(
        "Онлайн-чат и виджеты",
        Severity.LOW,
        "Переписка с клиентами и их контакты хранятся у иностранного сервиса." + _PD_NOTE,
        "Jivo, Битрикс24, Carrot quest, Talk-Me.",
        visitor_data=True,
    ),
    Category.FONTS: CategoryInfo(
        "Шрифты",
        Severity.LOW,
        "При недоступности сервиса сайт будет выглядеть сломанным." + _PD_NOTE,
        "Скачать шрифты и раздавать их с собственного сервера.",
        visitor_data=True,
    ),
    Category.JS_CDN: CategoryInfo(
        "Библиотеки с внешнего CDN",
        Severity.LOW,
        "Если CDN недоступен, перестанут работать меню, формы и кнопки. Чужой CDN — ещё и "
        "риск подмены кода, как случилось с polyfill.io в 2024 году." + _PD_NOTE,
        "Собрать библиотеки в бандл и раздавать с собственного сервера.",
        visitor_data=True,
    ),
    Category.MAPS: CategoryInfo(
        "Карты",
        Severity.LOW,
        "Карта может перестать загружаться или потребовать оплату, недоступную из России."
        + _PD_NOTE,
        "Яндекс Карты, 2ГИС.",
        visitor_data=True,
    ),
    Category.VIDEO: CategoryInfo(
        "Встроенное видео",
        Severity.LOW,
        "Видео с иностранной платформы." + _PD_NOTE,
        "RUTUBE, VK Видео, Kinescope.",
        visitor_data=True,
    ),
    Category.SOCIAL: CategoryInfo(
        "Виджеты соцсетей",
        Severity.LOW,
        "Встроенный виджет иностранной соцсети." + _PD_NOTE,
        "Виджеты VK, Telegram, Одноклассников.",
        visitor_data=True,
    ),
}


@dataclass(slots=True)
class Dependency:
    """One external service the site relies on."""

    category: Category
    service: str
    country: str | None
    evidence: str
    severity: Severity | None = None  # set for foreign dependencies only
    note: str = ""
    alternative: str = ""

    @property
    def foreign(self) -> bool | None:
        if not self.country:
            return None
        return self.country.upper() != "RU"

    @property
    def country_ru(self) -> str:
        return country_name(self.country)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "category_title": self.category.title,
            "service": self.service,
            "country": self.country,
            "foreign": self.foreign,
            "evidence": self.evidence,
            "severity": self.severity.label if self.severity is not None else None,
            "note": self.note,
        }


@dataclass(slots=True)
class Finding:
    category: Category
    title: str
    severity: Severity
    description: str
    recommendation: str
    services: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "title": self.title,
            "severity": self.severity.label,
            "description": self.description,
            "recommendation": self.recommendation,
            "services": self.services,
        }


# Penalty per finding; a category produces at most one finding.
PENALTIES = {Severity.INFO: 0, Severity.LOW: 4, Severity.MEDIUM: 10, Severity.HIGH: 20}
GRADE_THRESHOLDS = (("A", 90), ("B", 75), ("C", 60), ("D", 40))


def grade_for(score: int) -> str:
    for grade, threshold in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


@dataclass(slots=True)
class Report:
    target: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    dependencies: list[Dependency] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return max(0, 100 - sum(PENALTIES[f.severity] for f in self.findings))

    @property
    def grade(self) -> str:
        return grade_for(self.score)

    @property
    def duration(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def countries(self) -> list[tuple[str, int]]:
        """Share of dependencies per country, in percent, largest first."""
        known = [d.country.upper() for d in self.dependencies if d.country]
        if not known:
            return []
        counts = Counter(known)
        total = len(known)
        return [(code, round(100 * n / total)) for code, n in counts.most_common()]

    @property
    def foreign_count(self) -> int:
        return sum(1 for d in self.dependencies if d.foreign)

    @property
    def domestic_count(self) -> int:
        return sum(1 for d in self.dependencies if d.foreign is False)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity, reverse=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "suveren",
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "score": self.score,
            "grade": self.grade,
            "countries": dict(self.countries),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "dependencies": [d.to_dict() for d in self.dependencies],
            "facts": self.facts,
            "notes": self.notes,
        }
