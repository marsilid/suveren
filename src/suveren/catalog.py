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
# "cutoff" runs with --cutoff or the deep profile, "formleaks" only with --form-leaks
# (it types into the site's forms); "company" is `suveren company`;
# "core" needs nothing beyond the dependency scan every run does.
MODULES = (
    "core", "compliance", "blocklist", "mail", "security", "subdomains", "cutoff", "formleaks",
    "company",
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class CheckSpec:
    id: str
    group: str
    title: str  # exact title, or a regular expression when ``pattern`` is set
    module: str
    tags: tuple[str, ...]
    summary: str
    pattern: bool = False

    @property
    def site(self) -> str:
        """What the check does to the site: a key of SITE_ACTIONS."""
        return LABELS.get(self.id, MODULE_LABELS[self.module])[0]

    @property
    def runner(self) -> str:
        """What the person who runs it risks: a key of RUNNER_RISKS."""
        return LABELS.get(self.id, MODULE_LABELS[self.module])[1]

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
    _spec("SUV-PD-011", PD, "Политика и реальность", "compliance", "pd law",
          "Сходится ли политика с сайтом: оператор и сайт, данные из форм, cookies, третьи лица, "
          "страны."),
    _spec("SUV-PD-012", PD, "Данные из форм до отправки", "formleaks", "pd law forms browser",
          "Эксперимент в браузере: уходят ли имя, телефон, почта, пароль сторонним сервисам "
          "до отправки формы."),
    # --- other laws ---------------------------------------------------------------------
    _spec("SUV-LAW-001", LAWS, "Вход через иностранные сервисы", "compliance",
          "law foreign auth",
          "Вход через Google, Apple и другие иностранные сервисы (149-ФЗ, ст. 8 ч. 10)."),
    _spec("SUV-LAW-002", LAWS, "Рекомендательные технологии", "compliance", "law",
          "Персональные рекомендации без опубликованных правил их применения "
          "(149-ФЗ, ст. 10.2-2; КоАП, ст. 13.56)."),
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
          "Ключи DKIM среди распространённых селекторов, иначе узел _domainkey в DNS."),
    _spec("SUV-MAIL-005", MAIL, "Шифрование входящей почты (MTA-STS)", "mail",
          "mail tls", "MTA-STS и TLS-RPT: защита входящей почты от понижения до открытого текста."),
    _spec("SUV-MAIL-006", MAIL, "DKIM: длина ключа", "mail", "mail dkim",
          "Найденные ключи DKIM: RSA не короче 1024 бит (лучше 2048), не только SHA-1 "
          "(RFC 8301)."),
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
          "Версии TLS, срок и отзыв сертификата (OCSP, CRL), отключены ли TLS 1.0 и 1.1."),
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


# Two labels on every check (roadmap 1.1.2, item 3), so a reader knows before running it
# what it does to the site and what it costs the one who runs it. Taken from the code of
# each module (2026-10-31), not from what it is meant to do.
SITE_ACTIONS = {
    "none": (
        "не обращается к сайту",
        "только DNS, публичные реестры и журналы сертификатов",
    ),
    "look": (
        "только смотрит",
        "открывает страницы и файлы сайта, как посетитель, поисковый робот или почтовый сервер",
    ),
    "probe": (
        "прощупывает",
        "делает запросы, которых обычный посетитель не делает: соединения по устаревшим "
        "TLS 1.0 и 1.1, страницы поддоменов",
    ),
    "input": (
        "вводит данные",
        "печатает тестовые значения в формы сайта и не отправляет их",
    ),
}
RUNNER_RISKS = {
    "none": (
        "сайт вас не видит",
        "запросы идут в DNS и публичные реестры, сайт о проверке не узнает",
    ),
    "ip": (
        "сайт видит ваш IP",
        "как при обычном заходе: в журналах сайта останется ваш IP-адрес",
    ),
    "js": (
        "выполняется JavaScript сайта",
        "страница открывается в браузере на вашем компьютере, и её скрипты работают; браузеру "
        "закрыты внутренние адреса вашей сети и загрузка файлов",
    ),
}
# (site action, runner risk) of a module's checks; LABELS overrides single checks. A
# module's "-000" ("could not run") carries the labels of the module's checks.
MODULE_LABELS = {
    "core": ("look", "ip"),  # the dependency scan: the home page and the site's DNS
    "compliance": ("look", "ip"),  # the home page and up to --pages internal ones
    "blocklist": ("none", "none"),  # a downloaded copy of the register
    "mail": ("none", "none"),  # DNS records only
    "security": ("look", "ip"),  # headers, cookies and scripts of the fetched pages
    "subdomains": ("none", "none"),  # CT logs
    "cutoff": ("look", "ip"),
    "formleaks": ("input", "js"),
    "company": ("none", "none"),  # ЕГРЮЛ, RKN register, sanctions lists
}
LABELS = {
    "SUV-BLK-003": ("look", "ip"),  # third-party domains are read from the pages
    "SUV-MAIL-005": ("look", "ip"),  # fetches https://mta-sts.<domain>/.well-known/...
    "SUV-WEB-008": ("probe", "ip"),  # handshakes with TLS 1.0 and 1.1 on purpose
    "SUV-WEB-011": ("look", "js"),  # only with --browser
    "SUV-SUB-000": ("probe", "ip"),
    "SUV-SUB-002": ("probe", "ip"),  # opens the pages of subdomains pointing to services
    "SUV-ATK-001": ("look", "ip"),  # mail records plus the site's forms
    "SUV-ATK-003": ("probe", "ip"),
    "SUV-CUT-002": ("look", "js"),  # the page in a browser, foreign services refused
    "SUV-CO-007": ("look", "ip"),  # the INN on the site
}


MODULE_RU = {
    "core": "основная проверка (запускается всегда)",
    "compliance": "152-ФЗ и законы (`--no-152fz` отключает)",
    "blocklist": "реестр блокировок (`--no-blocklist`)",
    "mail": "защита почты (`--no-mail`)",
    "security": "безопасность сайта (`--no-security`)",
    "subdomains": "поддомены (`--no-subdomains`)",
    "cutoff": "эксперимент `--cutoff` или `--profile deep`",
    "formleaks": "эксперимент `--form-leaks` (только по флагу)",
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
        "",
        "У каждой проверки две метки. **С сайтом** — что она делает с проверяемым сайтом:",
        "",
        *(f"- *{short}* — {long}." for short, long in SITE_ACTIONS.values()),
        "",
        "**Для вас** — чем рискует тот, кто запускает проверку:",
        "",
        *(f"- *{short}* — {long}." for short, long in RUNNER_RISKS.values()),
        "",
        "Любой `suveren scan` открывает главную страницу сайта и читает его DNS: из них "
        "собираются иностранные сервисы. Поэтому сайт видит ваш IP при любом скане, даже "
        "если выбраны только проверки «не обращается к сайту». С `--browser` страницы "
        "открывает браузер, и JavaScript сайта выполняется у всех проверок, которые читают "
        "страницы.",
    ]
    group = None
    for s in CATALOG:
        if s.group != group:
            group = s.group
            lines += ["", f"## {group}", ""]
            lines += [
                "| ID | Проверка | Что проверяет | С сайтом | Для вас | Модуль | Теги |",
                "|---|---|---|---|---|---|---|",
            ]
        title = s.summary if s.pattern else s.title
        tags = ", ".join(f"`{t}`" for t in s.tags)
        site, runner = SITE_ACTIONS[s.site][0], RUNNER_RISKS[s.runner][0]
        lines.append(
            f"| `{s.id}` | {title} | {s.summary} | {site} | {runner} | {MODULE_RU[s.module]} "
            f"| {tags} |"
        )
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
