# Как участвовать в разработке Suveren

CLI-аудит сайта и компании для работы в России: зависимость от иностранных сервисов
(оценка A–F и план миграции), 152-ФЗ, блокировки РКН, почтовая подделка (SPF/DMARC/DKIM),
захват поддоменов, веб-безопасность, ЕГРЮЛ и санкционные списки (OFAC, ЕС, UK).
Python 3.11+, пакет `src/suveren`, точка входа `suveren = suveren.cli:app` (Typer + Rich).
Интерфейс и отчёты на русском; код, комментарии и коммиты на английском. Лицензия AGPL-3.0.

## Архитектура

Поток `suveren scan` (`scan.py: run_scan`):
1. `collect.py` собирает сырые факты о домене (`Facts`): DNS, HTTP, TLS, страницы;
   `crawl.py` добирает внутренние страницы, `render.py` — режим `--browser` (Playwright).
2. `analyze.py` превращает факты в зависимости и находки → `Report` (`models.py`).
   Провайдеры распознаются по базе `data/services.json` (`services.py`).
3. Дополнительные проверки добавляют `Check` в `report.checks`: `compliance.py`/`pdpolicy.py`
   (152-ФЗ), `dataflow.py`, `blocklist.py`, `mailsec.py`, `websec.py`/`leaks.py`/`vulns.py`,
   `subdomains.py`, `cutoff.py` (эксперимент с отключением иностранных сервисов), `plugins.py`.
   Что именно запускать, решает `plan.py` (профили quick/standard/deep, `--checks`, `--no-*`).
4. Поверх: `advice.py` (приоритеты, итоговая оценка), `scenarios.py` (сценарии атак),
   `fines.py` (штрафы), `migration.py` (план ухода), `audit.py` (самопроверка отчёта).
5. Вывод: `view.py` (терминал), `report.py` + `templates/*.j2` (HTML/JSON, схема
   `data/report.schema.json`), `sarif.py`.

Отдельные команды: `company.py` (по ИНН/ОГРН/домену), `history.py` (diff), `doctor.py`
(живы ли внешние источники), `menu.py` (меню для `Suveren.bat`/exe), `cache.py` (загрузка
больших датасетов). Каждая проверка обязана иметь стабильный ID (`SUV-MAIL-003`) в
`catalog.py`; в тестах это включено строго (`SUVEREN_STRICT_CHECK_IDS=1` в `conftest.py`).

## Команды

```bash
pip install -e ".[dev]"            # разработка; ".[browser]" — для --browser
ruff check . && ruff format --check .
mypy                               # проверяет src/suveren
coverage run -m pytest -q && coverage report   # порог покрытия 90%
pip-audit --skip-editable
suveren services                   # дымовой тест CLI, как в CI
suveren scan example.ru [--quick|--browser]
```

Именно эти шаги гоняет CI (`.github/workflows/ci.yml`, Python 3.11–3.14 + Windows).
Пока ничего не пушится, CI не запускается: перед слиянием ветки гоняй всё разом —
`.venv/Scripts/python tools/ci.py` (`--fast` — без тестов, `--no-audit` — без сети).

После правки `.py` запускайте `ruff check --fix .` и `ruff format .`.

## Тесты

- Тесты офлайн: сеть подменяется httpx MockTransport, фейковым DNS и TLS.
- `tests/lab.py` — полигон синтетических сайтов с заранее записанным правильным ответом;
  `test_lab.py` падает при расхождении (известные промахи — в `KNOWN` с причиной).
  `python tests/lab.py --markdown` обновляет таблицу в `docs/accuracy.md`.
- `tests/golden.py` — запись реальных сайтов в `corpus/` (только локально, в .gitignore),
  `test_corpus.py` их проигрывает.
- `tools/nightly.py` — ночной прогон реальных сайтов, отчёт в `reports/nightly/<date>/`.

## Соглашения

- Ruff: длина строки 100, target py311; mypy с `warn_unused_ignores`.
- Коммиты: короткая английская фраза о сути изменения; запись в `CHANGELOG.md` (на русском,
  раздел «Не выпущено») — отдельным коммитом `CHANGELOG: ...`.
- Новая проверка или смена её ответа: ID в `catalog.py`, код, случаи полигона в `tests/lab.py`
  (ожидание пишется до кода), тесты, `docs/checks.md` (генерируется), `docs/accuracy.md`,
  CHANGELOG.
- Windows: вывод с кириллицей требует `PYTHONUTF8=1`.
