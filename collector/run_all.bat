@echo off
cd /d "%~dp0"
echo Lancement du CSV Watcher dans une nouvelle fenetre...
start "CSV Watcher - FastAPI" /D "%~dp0" cmd /k "uv run py -m collector.csv_watcher"
timeout /t 2 /nobreak >nul
echo Lancement de CICFlowMeter Live Capture dans une nouvelle fenetre...
start "CICFlowMeter Live Capture" /D "%~dp0" cmd /k "uv run py -m collector.capture"
echo.
echo Deux fenetres ont ete ouvertes.
echo Fermez/arretez la capture avec Ctrl+C dans sa fenetre.
