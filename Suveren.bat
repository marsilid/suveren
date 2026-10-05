@echo off
rem "<nul" matters: without it chcp swallows the rest of the input stream.
chcp 65001 >nul <nul
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title Suveren
set empty=0
rem Bump the marker name whenever dependencies change, so old installs get updated.
set "deps_marker=.venv\.deps-2"

rem --- First run: create the virtual environment and install the tool ---
if not exist "%deps_marker%" (
    echo Устанавливаю Suveren и зависимости, это займёт около минуты...
    where python >nul 2>nul || (
        echo.
        echo Python не найден. Установи Python 3.10+ с https://www.python.org/downloads/
        echo и при установке поставь галочку "Add Python to PATH".
        pause
        exit /b 1
    )
    if not exist ".venv\Scripts\python.exe" python -m venv .venv || goto :install_failed
    ".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -e ".[browser]" || goto :install_failed
    type nul > "%deps_marker%"
)

:menu
cls
echo.
echo   ======================================
echo               S u v e r e n
echo       аудит сайта и компании для РФ
echo   ======================================
echo.
echo   1  Проверить сайт (сервисы, 152-ФЗ, блокировки)
echo   2  Проверить список сайтов
echo   3  Проверить компанию (ИНН, ОГРН или сайт)
echo   4  Сравнить два отчёта (JSON)
echo   5  Показать базу сервисов
echo   6  Обновить санкционные списки и реестр блокировок
echo   7  Открыть папку с отчётами
echo   8  Запустить автотесты
echo   0  Выход
echo.
set "choice="
set /p "choice=  Выбери пункт и нажми Enter: "
if defined choice goto :dispatch
rem Nothing entered. If this keeps happening the input stream is closed: stop looping.
set /a empty=empty+1
if %empty% GEQ 5 exit /b 0
goto :menu

:dispatch
set empty=0
if "!choice!"=="1" goto :scan
if "!choice!"=="2" goto :batch
if "!choice!"=="3" goto :company
if "!choice!"=="4" goto :diff
if "!choice!"=="5" goto :services
if "!choice!"=="6" goto :update
if "!choice!"=="7" goto :reports
if "!choice!"=="8" goto :tests
if "!choice!"=="0" exit /b 0
goto :menu

:scan
echo.
set "target="
set /p "target=  Домен или ссылка: "
if not defined target goto :menu
if not exist reports mkdir reports
for /f "tokens=1-3 delims=/.- " %%a in ("%date%") do set "stamp=%%c%%b%%a"
set "stamp=!stamp!-%time:~0,2%%time:~3,2%%time:~6,2%"
set "stamp=!stamp: =0!"
echo.
".venv\Scripts\suveren.exe" scan "!target!" --browser --json "reports\scan-!stamp!.json"
echo.
echo   Отчёт открыт в браузере. HTML и JSON сохранены в папке reports.
pause
goto :menu

:batch
echo.
echo   Нужен текстовый файл: по одному сайту в строке.
echo   Перетащи его в это окно или просто нажми Enter, чтобы создать шаблон.
echo.
set "list="
set /p "list=  Файл со списком: "
if not defined list (
    if not exist reports mkdir reports
    if not exist "reports\sites.txt" (
        > "reports\sites.txt" echo # Впиши сайты, по одному в строке, сохрани файл и запусти пункт 2 снова.
        >> "reports\sites.txt" echo example.ru
    )
    start "" notepad "reports\sites.txt"
    echo.
    echo   Открыл reports\sites.txt. Заполни, сохрани и выбери пункт 2 ещё раз,
    echo   указав этот файл.
    pause
    goto :menu
)
echo.
".venv\Scripts\suveren.exe" batch !list! --browser
echo.
echo   Сводка открыта в браузере. Отчёты по каждому сайту лежат в папке reports.
pause
goto :menu

:company
echo.
echo   Первая проверка скачивает санкционные списки (около 100 МБ), это займёт минуту.
echo.
set "target="
set /p "target=  ИНН, ОГРН или сайт компании: "
if not defined target goto :menu
echo.
".venv\Scripts\suveren.exe" company "!target!"
echo.
echo   Отчёт открыт в браузере и сохранён в папке reports.
pause
goto :menu

:update
echo.
".venv\Scripts\suveren.exe" update
echo.
pause
goto :menu

:diff
echo.
echo   Перетащи файлы JSON из папки reports в это окно или введи пути.
echo.
set "old="
set /p "old=  Старый отчёт: "
if not defined old goto :menu
set "new="
set /p "new=  Новый отчёт: "
if not defined new goto :menu
echo.
".venv\Scripts\suveren.exe" diff !old! !new!
echo.
pause
goto :menu

:services
echo.
".venv\Scripts\suveren.exe" services
echo.
pause
goto :menu

:reports
if not exist reports mkdir reports
start "" explorer "%~dp0reports"
goto :menu

:tests
echo.
if not exist ".venv\Scripts\pytest.exe" (
    ".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -e ".[dev]"
)
".venv\Scripts\python.exe" -m pytest -q
echo.
pause
goto :menu

:install_failed
echo.
echo Не получилось установить зависимости. Проверь интернет и попробуй ещё раз.
pause
exit /b 1
