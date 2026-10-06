@echo off
rem Run Suveren from the source code: installs it on first launch, then opens the
rem same menu as Suveren.exe (`suveren menu`), so both look and behave alike.
rem "<nul" matters: without it chcp swallows the rest of the input stream.
chcp 65001 >nul <nul
cd /d "%~dp0"
title Suveren
rem Bump the marker name whenever dependencies change, so old installs get updated.
set "deps_marker=.venv\.deps-2"

if not exist "%deps_marker%" (
    echo Устанавливаю Suveren и зависимости, это займёт около минуты...
    where python >nul 2>nul || (
        echo.
        echo Python не найден. Установи Python 3.10+ с https://www.python.org/downloads/
        echo и при установке поставь галочку "Add Python to PATH".
        echo Или скачай готовый Suveren.exe: https://github.com/marsilid/suveren/releases
        pause
        exit /b 1
    )
    if not exist ".venv\Scripts\python.exe" python -m venv .venv || goto :install_failed
    ".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -e ".[browser]" || goto :install_failed
    type nul > "%deps_marker%"
)

".venv\Scripts\suveren.exe" menu
exit /b 0

:install_failed
echo.
echo Не получилось установить зависимости. Проверь интернет и попробуй ещё раз.
pause
exit /b 1
