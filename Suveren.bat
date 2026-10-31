@echo off
rem Run Suveren from the source code: installs it on first launch, then opens the
rem same menu as Suveren.exe (`suveren menu`), so both look and behave alike.
rem "<nul" matters: without it chcp swallows the rest of the input stream.
chcp 65001 >nul <nul
cd /d "%~dp0"
title Suveren
rem Bump the marker name whenever dependencies change, so old installs get updated.
set "deps_marker=.venv\.deps-3"

rem Suveren needs Python 3.11+: an older .venv (made for 1.0 by Python 3.10) fails later
rem with a pip error nobody can read, so say it here.
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import sys; sys.exit(sys.version_info < (3, 11))" || goto :old_venv
)

if not exist "%deps_marker%" (
    echo Устанавливаю Suveren и зависимости, это займёт около минуты...
    where python >nul 2>nul || (
        echo.
        echo Python не найден. Установи Python 3.11+ с https://www.python.org/downloads/
        echo и при установке поставь галочку "Add Python to PATH".
        echo Или скачай готовый Suveren.exe: https://github.com/marsilid/suveren/releases
        pause
        exit /b 1
    )
    python -c "import sys; sys.exit(sys.version_info < (3, 11))" || goto :old_python
    if not exist ".venv\Scripts\python.exe" python -m venv .venv || goto :install_failed
    rem Dependencies at the versions and hashes of the lock: a package swapped on PyPI
    rem fails the install instead of running on your computer. Then Suveren itself.
    ".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check --require-hashes -r packaging\requirements-browser.txt || goto :install_failed
    ".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check --no-deps -e . || goto :install_failed
    type nul > "%deps_marker%"
)

".venv\Scripts\suveren.exe" menu
exit /b 0

:old_python
echo.
for /f "delims=" %%v in ('python --version 2^>^&1') do echo Найден %%v, а Suveren нужен Python 3.11 или новее.
echo Установи свежий Python с https://www.python.org/downloads/
echo Или скачай готовый Suveren.exe: https://github.com/marsilid/suveren/releases
pause
exit /b 1

:old_venv
echo.
echo Папка .venv создана старым Python, а Suveren нужен Python 3.11 или новее.
echo Удали папку .venv рядом с Suveren.bat и запусти Suveren.bat снова.
pause
exit /b 1

:install_failed
echo.
echo Не получилось установить зависимости. Проверь интернет и попробуй ещё раз.
pause
exit /b 1
