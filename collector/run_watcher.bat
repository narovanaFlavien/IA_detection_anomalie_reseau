@echo off
cd /d "%~dp0"
python -m collector.csv_watcher
pause
