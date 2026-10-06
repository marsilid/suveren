@echo off
rem Build dist\Suveren.exe locally. Run from the repository root.
chcp 65001 >nul <nul
cd /d "%~dp0.."
if not exist ".venv\Scripts\python.exe" python -m venv .venv || exit /b 1
".venv\Scripts\python.exe" -m pip install -q -e ".[browser]" pyinstaller || exit /b 1
".venv\Scripts\pyinstaller.exe" --noconfirm --onefile --name Suveren ^
    --collect-data suveren --collect-submodules dns --collect-all playwright ^
    --workpath build\pyinstaller --specpath build ^
    packaging\suveren_exe.py || exit /b 1
echo.
echo Готово: dist\Suveren.exe
