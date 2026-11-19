@echo off
cd /d "%~dp0"
python -m collector.capture
pause
