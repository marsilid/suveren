@echo off
rem Nightly run for Windows Task Scheduler: scans tools\nightly-sites.txt, audits the
rem reports and writes reports\nightly\<date>\changes.md. The log is appended to
rem reports\nightly\nightly.log.
cd /d "%~dp0.."
if not exist "reports\nightly" mkdir "reports\nightly"
echo ==== %date% %time% >> "reports\nightly\nightly.log"
".venv\Scripts\python.exe" tools\nightly.py >> "reports\nightly\nightly.log" 2>&1
echo exit %errorlevel% >> "reports\nightly\nightly.log"
rem Only the scheduled night run passes "shutdown": a manual run never turns the laptop off.
rem Ten minutes' warning on screen; cancel with: shutdown /a
if /i "%~1"=="shutdown" (
  echo shutdown in 10 min >> "reports\nightly\nightly.log"
  shutdown /s /t 600 /c "Suveren: nightly run finished. The laptop shuts down in 10 minutes. To cancel: Win+R, shutdown /a"
)
