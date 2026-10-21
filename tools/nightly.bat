@echo off
rem Nightly run for Windows Task Scheduler: scans tools\nightly-sites.txt, audits the
rem reports and writes reports\nightly\<date>\changes.md. The log is appended to
rem reports\nightly\nightly.log.
cd /d "%~dp0.."
if not exist "reports\nightly" mkdir "reports\nightly"
echo ==== %date% %time% >> "reports\nightly\nightly.log"
".venv\Scripts\python.exe" tools\nightly.py >> "reports\nightly\nightly.log" 2>&1
echo exit %errorlevel% >> "reports\nightly\nightly.log"
