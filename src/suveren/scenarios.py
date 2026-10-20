"""Attack scenarios: findings from different modules joined into what an attacker
would actually do, the way a security engineer reads a report.

A scenario appears only when every link of its chain was found; each step names the
check it rests on (its ID), and the advice names the one fix that breaks the chain.
Nothing new is probed here: it is reasoning over the checks already made.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from suveren.checks import Check, Status
from suveren.models import Category, Dependency

GROUP_ATTACK = "Сценарии атак"


@dataclass(slots=True)
class Facts:
    """What the scenarios read: check statuses by ID, and the dependencies."""

    status: dict[str, Status]
    details: dict[str, str]
    deps: list[Dependency]
    domain: str

    def bad(self, check_id: str, *, warn: bool = True) -> bool:
        s = self.status.get(check_id)
        return s is Status.FAIL or (warn and s is Status.WARN)

    @property
    def collects_data(self) -> bool:
        """Forms with personal data (the forms check ran and found some) or payments."""
        forms = self.status.get("SUV-PD-003") in (Status.FAIL, Status.WARN, Status.OK)
        return forms or self.pays

    @property
    def pays(self) -> bool:
        return any(d.category is Category.PAYMENTS for d in self.deps)

    def foreign(self, *categories: Category) -> list[Dependency]:
        return [d for d in self.deps if d.foreign and d.category in categories]


@dataclass(frozen=True, slots=True)
class Scenario:
    title: str
    when: Callable[[Facts], bool]
    severe: Callable[[Facts], bool]
    steps: Callable[[Facts], list[str]]
    fix: str | Callable[[Facts], str]


def _phishing_steps(f: Facts) -> list[str]:
    target = "форму оплаты" if f.pays else "форму с личными данными"
    return [
        f"Письмо от имени любого адреса @{f.domain} не отклоняется почтовыми сервисами "
        "(SUV-MAIL-001).",
        f"Клиенты привыкли вводить данные на сайте: в письме — ссылка на копию сайта и {target}.",
        "Письмо от «вашего» адреса вызывает доверие: данные и деньги уходят злоумышленнику.",
    ]


def _script_steps(f: Facts) -> list[str]:
    if f.bad("SUV-WEB-002", warn=False):
        first = (
            "Сайт подключает скрипт с домена, который свободен для регистрации или был "
            "взломан (SUV-WEB-002): его можно купить и отдавать с него свой код."
        )
    else:
        first = (
            "Библиотеки грузятся с публичного CDN без контроля целостности (SUV-WEB-003): "
            "при взломе CDN, как polyfill.io в 2024 году, подменённый файл выполнится."
        )
    steps = [first]
    if f.bad("SUV-WEB-004"):
        steps.append(
            "Политика CSP не ограничивает, куда скрипт может отправить данные (SUV-WEB-004)."
        )
    what = "номера карт и пароли" if f.pays else "всё, что вводят посетители"
    steps.append(f"Чужой код работает у каждого посетителя и читает {what}.")
    return steps


def _takeover_steps(f: Facts) -> list[str]:
    steps = [
        "Поддомен указывает на удалённый проект или свободный домен (SUV-SUB-002): его можно "
        "занять и разместить там свою страницу на вашем адресе.",
    ]
    if f.bad("SUV-WEB-007"):
        steps.append(
            "Cookies сайта без нужных флагов (SUV-WEB-007): страница на поддомене может их "
            "читать или подменять."
        )
    steps.append("Фишинг на настоящем адресе компании не отличить от сайта.")
    return steps


def _first_visit_steps(f: Facts) -> list[str]:
    return [
        "Нет HSTS (SUV-WEB-005): первый заход по http:// можно перехватить в общественном Wi-Fi.",
        "Посетитель видит подменённую страницу на вашем адресе и вводит данные в форму.",
    ]


def _key_steps(f: Facts) -> list[str]:
    return [
        "В коде сайта лежит секрет (SUV-WEB-009): его видит браузер любого посетителя.",
        "С ним можно действовать от имени компании: слать сообщения ботом, тратить деньги "
        "на API, читать данные — в зависимости от ключа.",
    ]


WHOLE_SITE = (Category.DNS, Category.HOSTING, Category.CDN, Category.BUILDER)


def _cutoff_steps(f: Facts) -> list[str]:
    infra = f.foreign(*WHOLE_SITE)
    mail = f.foreign(Category.MAIL)
    by_category: dict[str, list[str]] = {}
    for d in infra:
        names = by_category.setdefault(d.category.title, [])
        if d.service not in names:
            names.append(d.service)
    listed = "; ".join(f"{c} ({', '.join(n)})" for c, n in by_category.items())
    steps = [f"Сайт держится на иностранной инфраструктуре: {listed}."]
    if mail:
        steps.append(
            f"Почта домена тоже у иностранного провайдера ({mail[0].service}): при отключении "
            "не придут письма для восстановления паролей от других сервисов компании."
        )
    what = "сайт с почтой пропадают" if mail else "сайт пропадает"
    steps.append(f"Одно решение провайдера — и {what}, а перенос займёт дни.")
    return steps


def _cutoff_fix(f: Facts) -> str:
    if f.foreign(Category.DNS):
        what = "сайт и почту" if f.foreign(Category.MAIL) else "сайт"
        return (
            f"Цепочку рвёт перенос DNS к российскому провайдеру: тогда {what} можно "
            "переключить за минуты, а не за дни."
        )
    kinds = ", ".join(dict.fromkeys(d.category.title.lower() for d in f.foreign(*WHOLE_SITE)))
    return f"Цепочку рвёт перенос к российскому провайдеру: {kinds}."


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        "Фишинг от имени компании",
        when=lambda f: f.bad("SUV-MAIL-001") and f.collects_data,
        severe=lambda f: f.bad("SUV-MAIL-001", warn=False),
        steps=_phishing_steps,
        fix="Цепочку рвёт DMARC с p=reject (после проверки по отчётам, что настоящая почта "
        "проходит): поддельные письма от вашего домена перестанут доходить.",
    ),
    Scenario(
        "Чужой код у всех посетителей",
        when=lambda f: (
            f.bad("SUV-WEB-002", warn=False)
            or (f.bad("SUV-WEB-003") and f.bad("SUV-WEB-004") and f.collects_data)
        ),
        severe=lambda f: f.bad("SUV-WEB-002", warn=False),
        steps=_script_steps,
        fix="Цепочку рвёт отказ от чужого скрипта: уберите его или разместите копию на своём "
        "сервере с атрибутом integrity; CSP со списком разрешённых источников — второй рубеж.",
    ),
    Scenario(
        "Захват поддомена",
        when=lambda f: f.bad("SUV-SUB-002", warn=False),
        severe=lambda f: True,
        steps=_takeover_steps,
        fix="Цепочку рвёт удаление DNS-записи поддомена, который указывает на удалённый проект.",
    ),
    Scenario(
        "Перехват при первом заходе",
        when=lambda f: f.bad("SUV-WEB-005") and f.collects_data,
        severe=lambda f: False,
        steps=_first_visit_steps,
        fix="Цепочку рвёт заголовок Strict-Transport-Security со сроком от полугода.",
    ),
    Scenario(
        "Утёкший ключ",
        when=lambda f: f.bad("SUV-WEB-009", warn=False),
        severe=lambda f: True,
        steps=_key_steps,
        fix="Цепочку рвёт отзыв ключа у провайдера; новый храните только на сервере.",
    ),
    Scenario(
        "Отключение сайта и почты",
        when=lambda f: bool(f.foreign(*WHOLE_SITE)),
        severe=lambda f: bool(f.foreign(Category.MAIL)),
        steps=_cutoff_steps,
        fix=_cutoff_fix,
    ),
)


def build(checks: list[Check], deps: list[Dependency], domain: str) -> list[Check]:
    """One check per scenario whose whole chain was found."""
    f = Facts(
        status={c.id: c.status for c in checks if c.id},
        details={c.id: c.details for c in checks if c.id},
        deps=deps,
        domain=domain,
    )
    found = []
    for s in SCENARIOS:
        if not s.when(f):
            continue
        steps = s.steps(f)
        text = " ".join(f"{i}) {step}" for i, step in enumerate(steps, 1))
        found.append(
            Check(
                GROUP_ATTACK,
                s.title,
                Status.FAIL if s.severe(f) else Status.WARN,
                text,
                s.fix(f) if callable(s.fix) else s.fix,
            )
        )
    return found
