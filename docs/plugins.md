# Плагины: свои проверки в Suveren

Плагин — это Python-файл с проверками, которые Suveren запускает вместе со своими, как
скрипты NSE в Nmap. Результаты попадают в тот же отчёт (HTML, JSON, SARIF) в раздел
«Проверки из плагинов».

```bash
suveren scan site.ru --plugin examples/plugins/security_txt.py
```

`--plugin` можно указать несколько раз. Вместо файла можно указать имя
установленного модуля: `--plugin acme_checks.web`.

## Как написать

```python
from suveren.checks import Check, Status
from suveren.plugins import GROUP_PLUGINS, PluginContext

NAME = "Мой плагин"          # так он называется в сообщениях об ошибках


async def run(ctx: PluginContext) -> list[Check]:
    resp = await ctx.client.get(f"https://{ctx.host}/robots.txt")
    if resp.status_code == 200:
        return [Check(GROUP_PLUGINS, "robots.txt", Status.OK, "Файл есть.", id="ACME-WEB-001")]
    return [Check(GROUP_PLUGINS, "robots.txt", Status.WARN, "Файла нет.", "Добавьте.", id="ACME-WEB-001")]
```

Что есть в `ctx` (`PluginContext`): `host`, `domain`, `final_url`, `html` главной
страницы (пусто, если её закрыла защита от ботов), `headers` её ответа, `services` —
найденные сервисы (как в JSON-отчёте) и `client` — HTTP-клиент Suveren с честным
User-Agent.

## Правила

- **ID** — свой префикс: `ACME-WEB-001` (буквы и цифры, три цифры в конце). Префикс
  `SUV-` занят проверками Suveren: такая проверка не попадёт в отчёт, вместо неё
  будет «не проверено» с объяснением.
- **Пассивно.** Плагин читает то, что сайт отдаёт любому посетителю. Перебор, отправка
  форм и сканирование портов противоречат принципам Suveren.
- **Статус не обманывает.** «Проблема» — только когда она доказана. Если сайт не
  ответил или закрыт защитой от ботов, нужен «не проверено». Пример: в
  `security_txt.py` код 403 — это «не проверено», а «файла нет» — только при 404 или 410.
- **Доказательство.** Покажите, на чём основан вывод: `Check(..., evidence=[Evidence("url",
  "robots.txt", str(resp.url))])` (`from suveren.checks import Evidence`). Вид — одно из `dns`,
  `header`, `url`, `request`, `html`, `tls`, `registry`; значение — как увидено, пустое — «этого
  нет». В HTML-отчёте оно раскрывается под проверкой.
- **Ошибка плагина не роняет проверку.** Исключение, ответ не в виде списка `Check` или
  работа дольше 60 секунд превращаются в одну строку «не проверено» с причиной.
- **Код плагина выполняется.** Подключайте только плагины, которым доверяете, как и
  любую программу. Suveren сам ничего не подгружает: только то, что указано в
  `--plugin`.

## Пример

`examples/plugins/security_txt.py` проверяет файл `security.txt` по RFC 9116: адрес
`/.well-known/security.txt` по HTTPS, тип `text/plain`, поле `Contact` и одно поле
`Expires` с датой в будущем. Тесты плагинов — в `tests/test_plugins.py`.

Когда задано `--checks`, в отчёт попадают только выбранные проверки Suveren;
проверки плагинов при этом не показываются.
