"""The catalogue of checks: a stable ID, section, tags and one line about each.

An ID never changes once released, so reports, CI rules and documentation can refer
to a finding by it ("SUV-MAIL-003"), like NSE script names in Nmap. Titles may be
reworded; IDs stay. A check object gets its ID from here by its section and title,
so modules don't repeat IDs, and the tests fail on a check missing from the catalogue.

The ``module`` says which part of ``suveren scan`` (or ``company``) produces the
check; selecting checks with ``--checks`` runs only the modules they need. Checks
ending in ``-000`` report that a whole module could not run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Section names as shown in reports. They match the constants in checks.py,
# mailsec.py, websec.py, subdomains.py and company.py (a test keeps them in step).
PD = "Персональные данные (152-ФЗ)"
LAWS = "Другие требования законов"
BLOCK = "Блокировки в России"
MAIL = "Защита почты от подделки"
WEB = "Безопасность сайта"
SUB = "Поддомены"
CUT = "Отключение иностранных сервисов"
ATTACK = "Сценарии атак"
COMPANY = "Проверка компании"

# Modules of `suveren scan`, as switched by --no-152fz, --no-mail and the like;
# "cutoff" runs with --cutoff or the deep profile; "company" is `suveren company`;
# "core" needs nothing beyond the dependency scan every run does.
MODULES = ("core", "compliance", "blocklist", "mail", "security", "subdomains", "cutoff", "company")


@dataclass(frozen=True, slots=True)
class CheckSpec:
    id: str
    group: str
    title: str  # exact title, or a regular expression when ``pattern`` is set
    module: str
    tags: tuple[str, ...]
    summary: str
    pattern: bool = False

    def matches(self, group: str, title: str) -> bool:
        if group != self.group:
            return False
        return bool(re.fullmatch(self.title, title)) if self.pattern else title == self.title


def _spec(
    id: str, group: str, title: str, module: str, tags: str, summary: str, pattern: bool = False
) -> CheckSpec:
    return CheckSpec(id, group, title, module, tuple(tags.split()), summary, pattern)


CATALOG: tuple[CheckSpec, ...] = (
    # --- 152-ФЗ -------------------------------------------------------------------------
    _spec("SUV-PD-000", PD, "Проверка 152-ФЗ", "compliance", "pd law",
          "Проверка 152-ФЗ не выполнена: главная страница не загрузилась."),
    _spec("SUV-PD-001", PD, "Политика обработки персональных данных", "compliance", "pd law",
          "Опубликована ли политика обработки персональных данных (152-ФЗ, ст. 18.1)."),
    _spec("SUV-PD-002", PD, "Содержание политики", "compliance", "pd law",
          "Есть ли в политике разделы, которые рекомендует Роскомнадзор."),
    _spec("SUV-PD-003", PD, "Согласие на обработку в формах", "compliance", "pd law forms",
          "Просят ли согласие на обработку в формах, собирающих персональные данные."),
    _spec("SUV-PD-004", PD, "Отдельное согласие на обработку", "compliance", "pd law forms",
          "Оформлено ли согласие отдельно от оферты и других документов (с 01.09.2025)."),
    _spec("SUV-PD-005", PD, "Уведомление о cookies", "compliance", "pd law cookies",
          "Есть ли уведомление о cookies при метрических и рекламных сервисах."),
    _spec("SUV-PD-006", PD, "Трансграничная передача данных", "compliance", "pd law foreign",
          "Получают ли данные посетителей иностранные сервисы."),
    _spec("SUV-PD-007", PD, "Хранение данных в России", "compliance", "pd law foreign",
          "Находится ли сервер сайта в России (152-ФЗ, ст. 18 ч. 5)."),
    _spec("SUV-PD-008", PD, "Защищённое соединение", "compliance", "pd law tls",
          "Работает ли сайт по HTTPS."),
    _spec("SUV-PD-009", PD, "Реестр операторов персональных данных", "compliance", "pd law",
          "Есть ли компания с сайта в реестре операторов персональных данных РКН."),
    _spec("SUV-PD-010", PD, "Куда уходят данные посетителя", "compliance", "pd law foreign",
          "В какие страны и каким сервисам браузер посетителя передаёт IP и cookies."),
    # --- other laws ---------------------------------------------------------------------
    _spec("SUV-LAW-001", LAWS, "Вход через иностранные сервисы", "compliance",
          "law foreign auth",
          "Вход через Google, Apple и другие иностранные сервисы (149-ФЗ, ст. 8 ч. 10)."),
    # --- block lists --------------------------------------------------------------------
    _spec("SUV-BLK-000", BLOCK, "Реестр блокировок Роскомнадзора", "blocklist", "blocklist",
          "Реестр блокировок не загрузился, проверка не выполнена."),
    _spec("SUV-BLK-001", BLOCK, "Домен в реестре блокировок", "blocklist", "blocklist",
          "Есть ли домен сайта в реестре блокировок РКН."),
    _spec("SUV-BLK-002", BLOCK, "IP-адреса сайта", "blocklist", "blocklist",
          "Есть ли IP-адреса сайта в реестре блокировок РКН."),
    _spec("SUV-BLK-003", BLOCK, "Сторонние сервисы в реестре блокировок", "blocklist", "blocklist",
          "Какие сторонние домены, с которых грузится сайт, уже заблокированы в России."),
    # --- mail ---------------------------------------------------------------------------
    _spec("SUV-MAIL-001", MAIL, r"Можно ли подделать письмо от имени @.+", "mail",
          "mail spoofing", "Итог: можно ли подделать письмо от имени домена.", pattern=True),
    _spec("SUV-MAIL-002", MAIL, "SPF: кто может отправлять почту", "mail", "mail spf",
          "Запись SPF: синтаксис, ~all/-all, лимит в 10 DNS-запросов."),
    _spec("SUV-MAIL-003", MAIL, "DMARC: что делать с поддельными письмами", "mail",
          "mail dmarc", "Политика DMARC: none, quarantine или reject, pct и отчёты."),
    _spec("SUV-MAIL-004", MAIL, "DKIM: цифровая подпись писем", "mail", "mail dkim",
          "Ключи DKIM среди распространённых селекторов."),
    _spec("SUV-MAIL-005", MAIL, "Шифрование входящей почты (MTA-STS)", "mail",
          "mail tls", "MTA-STS и TLS-RPT: защита входящей почты от понижения до открытого текста."),
    # --- web security -------------------------------------------------------------------
    _spec("SUV-WEB-000", WEB, "Заголовки безопасности (CSP, HSTS и другие)", "security",
          "web", "Проверка безопасности сайта не выполнена."),
    _spec("SUV-WEB-001", WEB, "Сторонний код на сайте", "security", "web scripts supply-chain",
          "Скрипты с чужих доменов: каждый может выполнить на сайте любой код."),
    _spec("SUV-WEB-002", WEB, "Скрипты с брошенных и скомпрометированных доменов", "security",
          "web scripts supply-chain",
          "Скрипты с доменов, которые свободны для регистрации или были взломаны."),
    _spec("SUV-WEB-003", WEB, "Контроль целостности библиотек с CDN (SRI)", "security",
          "web scripts supply-chain", "Библиотеки с публичных CDN без атрибута integrity."),
    _spec("SUV-WEB-004", WEB, "Политика безопасности контента (CSP)", "security",
          "web headers", "Заголовок Content-Security-Policy и его слабые места."),
    _spec("SUV-WEB-005", WEB, "Принудительный HTTPS (HSTS)", "security", "web headers tls",
          "Заголовок Strict-Transport-Security и его срок."),
    _spec("SUV-WEB-006", WEB, "Защитные заголовки", "security", "web headers",
          "X-Frame-Options или frame-ancestors, X-Content-Type-Options."),
    _spec("SUV-WEB-007", WEB, "Флаги cookies", "security", "web cookies",
          "Secure, HttpOnly и SameSite у cookies сайта."),
    _spec("SUV-WEB-008", WEB, "TLS: сертификат и протоколы", "security", "web tls",
          "Версии TLS, срок сертификата, отключены ли TLS 1.0 и 1.1."),
    _spec("SUV-WEB-009", WEB, "Ключи и секреты в коде сайта", "security",
          "web secrets scripts",
          "Секреты (токены, приватные и API-ключи) в JavaScript, который получает посетитель."),
    _spec("SUV-WEB-010", WEB, "Уязвимые версии библиотек", "security", "web scripts cve",
          "jQuery, Bootstrap, lodash и др. с явной версией, у которой есть известные CVE."),
    _spec("SUV-WEB-011", WEB, "Цепочки сторонних скриптов", "security",
          "web scripts supply-chain browser",
          "Код, который подключил не сайт, а чужие скрипты (только в режиме --browser)."),
    # --- subdomains ---------------------------------------------------------------------
    _spec("SUV-SUB-000", SUB, "Поддомены и их захват", "subdomains", "subdomains",
          "Проверка поддоменов не выполнена."),
    _spec("SUV-SUB-001", SUB, "Поддомены в публичных журналах сертификатов", "subdomains",
          "subdomains ct", "Поддомены из журналов Certificate Transparency."),
    _spec("SUV-SUB-002", SUB, "Захват поддоменов", "subdomains", "subdomains takeover",
          "Поддомены, указывающие на удалённые проекты или свободные домены."),
    # --- attack scenarios (reasoning over the other checks) ----------------------------
    _spec("SUV-ATK-001", ATTACK, "Фишинг от имени компании", "mail", "scenario mail",
          "Подделываемая почта + формы или оплата на сайте: фишинг клиентов."),
    _spec("SUV-ATK-002", ATTACK, "Чужой код у всех посетителей", "security",
          "scenario scripts supply-chain",
          "Брошенный домен скрипта или CDN без SRI и CSP: чужой код на сайте."),
    _spec("SUV-ATK-003", ATTACK, "Захват поддомена", "subdomains", "scenario subdomains",
          "Поддомен можно занять: фишинг на настоящем адресе, доступ к cookies."),
    _spec("SUV-ATK-004", ATTACK, "Перехват при первом заходе", "security", "scenario tls",
          "Нет HSTS + формы с данными: подмена страницы в общественном Wi-Fi."),
    _spec("SUV-ATK-005", ATTACK, "Утёкший ключ", "security", "scenario secrets",
          "Секрет в коде сайта: действия от имени компании."),
    _spec("SUV-ATK-006", ATTACK, "Отключение сайта и почты", "core", "scenario foreign",
          "Иностранные DNS, хостинг или CDN (и почта): сайт и почта пропадают разом."),
    # --- cutoff experiment (--cutoff) --------------------------------------------------
    _spec("SUV-CUT-001", CUT, "Отключение: сайт и почта целиком", "cutoff", "cutoff",
          "Отключат ли сайт или почту целиком иностранные DNS, хостинг, CDN, почта."),
    _spec("SUV-CUT-002", CUT, "Отключение: что перестанет работать на странице", "cutoff",
          "cutoff browser",
          "Эксперимент в браузере: страница без иностранных сервисов — что пропало и сломалось."),
    # --- company (`suveren company`) ----------------------------------------------------
    _spec("SUV-CO-001", COMPANY, "ЕГРЮЛ / ЕГРИП", "company", "company egrul",
          "Статус организации в ЕГРЮЛ/ЕГРИП: действует или ликвидирована."),
    _spec("SUV-CO-002", COMPANY, "Возраст компании", "company", "company egrul",
          "Как давно зарегистрирована компания."),
    _spec("SUV-CO-003", COMPANY, "Санкционные списки", "company", "company sanctions",
          "Компания в санкционных списках США, ЕС и Великобритании."),
    _spec("SUV-CO-004", COMPANY, "Руководитель в санкционных списках", "company",
          "company sanctions", "Руководитель компании в санкционных списках."),
    _spec("SUV-CO-005", COMPANY, "Управляющая организация в санкционных списках", "company",
          "company sanctions", "Управляющая организация в санкционных списках."),
    _spec("SUV-CO-006", COMPANY, "Реестр операторов персональных данных", "company",
          "company pd", "Есть ли компания в реестре операторов персональных данных РКН."),
    _spec("SUV-CO-007", COMPANY, "Сайт и компания", "company", "company",
          "Связан ли сайт с компанией: ИНН на сайте и домен в ЕГРЮЛ."),
)  # fmt: skip

BY_ID = {spec.id: spec for spec in CATALOG}
_EXACT = {(s.group, s.title): s for s in CATALOG if not s.pattern}
_PATTERNS = [s for s in CATALOG if s.pattern]


def spec_for(group: str, title: str) -> CheckSpec | None:
    """The catalogue entry of a check, by its section and title."""
    found = _EXACT.get((group, title))
    if found is None:
        found = next((s for s in _PATTERNS if s.matches(group, title)), None)
    return found


class SelectionError(ValueError):
    pass


def select(expr: str) -> set[str]:
    """IDs chosen by ``--checks``: comma-separated IDs, ID prefixes (SUV-MAIL), tags
    (mail, headers) or modules (security). Unknown words are an error, not silence."""
    chosen: set[str] = set()
    for word in (w.strip() for w in expr.split(",")):
        if not word:
            continue
        upper, lower = word.upper(), word.lower()
        hits = {
            s.id
            for s in CATALOG
            if s.id == upper
            or s.id.startswith(upper.rstrip("-") + "-")
            or lower in s.tags
            or lower == s.module
        }
        if not hits:
            raise SelectionError(
                f"--checks: «{word}» не похоже ни на ID, ни на тег проверки "
                "(список: suveren checks)"
            )
        chosen |= hits
    return chosen


# Scenarios read checks from several modules; choosing one runs what it needs.
REQUIRES = {
    "SUV-ATK-001": {"mail", "compliance"},
    "SUV-ATK-002": {"security", "compliance"},
    "SUV-ATK-003": {"subdomains", "security"},
    "SUV-ATK-004": {"security", "compliance"},
    "SUV-ATK-005": {"security"},
}


def modules_for(ids: set[str]) -> set[str]:
    return {m for i in ids for m in REQUIRES.get(i, {BY_ID[i].module})}


MODULE_RU = {
    "core": "основная проверка (запускается всегда)",
    "compliance": "152-ФЗ и законы (`--no-152fz` отключает)",
    "blocklist": "реестр блокировок (`--no-blocklist`)",
    "mail": "защита почты (`--no-mail`)",
    "security": "безопасность сайта (`--no-security`)",
    "subdomains": "поддомены (`--no-subdomains`)",
    "cutoff": "эксперимент `--cutoff` или `--profile deep`",
    "company": "`suveren company`",
}


def markdown() -> str:
    """docs/checks.md: every check with its ID, like the NSE script pages of Nmap.
    Generated from this catalogue; a test keeps the file in step."""
    lines = [
        "# Проверки Suveren",
        "",
        "Файл создаётся командой `suveren checks --markdown > docs/checks.md` из каталога "
        "`src/suveren/catalog.py`. ID проверки не меняется между версиями: на него можно "
        "ссылаться в отчётах, задачах и правилах CI (`suveren scan сайт --checks ID`).",
        "",
        "Статусы: **проблема** — нарушение или уязвимость найдены; **внимание** — возможная "
        "проблема, нужна ручная проверка; **не проверено** — данных не хватило (это лучше "
        "ложной тревоги); **в порядке**.",
    ]
    group = None
    for s in CATALOG:
        if s.group != group:
            group = s.group
            lines += ["", f"## {group}", ""]
            lines += ["| ID | Проверка | Что проверяет | Модуль | Теги |", "|---|---|---|---|---|"]
        title = s.summary if s.pattern else s.title
        tags = ", ".join(f"`{t}`" for t in s.tags)
        lines.append(f"| `{s.id}` | {title} | {s.summary} | {MODULE_RU[s.module]} | {tags} |")
    lines += [
        "",
        "## Иностранные зависимости",
        "",
        "Находки об иностранных сервисах имеют ID по категории: `SUV-DEP-DNS`, "
        "`SUV-DEP-HOSTING`, `SUV-DEP-MAIL`, `SUV-DEP-CDN`, `SUV-DEP-ANALYTICS` и т. д. "
        "(`SUV-DEP-` и название категории). Они есть в JSON (`findings[].id`) и SARIF.",
        "",
    ]
    return "\n".join(lines)


def all_tags() -> list[str]:
    return sorted({t for s in CATALOG for t in s.tags})
