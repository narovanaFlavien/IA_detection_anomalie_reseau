@echo off
setlocal
echo CICFlowMeter - capture Live
echo.
set /p IFACE=Index ou nom exact de l'interface (ex: 0 ou Wi-Fi) :
if "%IFACE%"=="" (
  echo Interface obligatoire.
  exit /b 2
)
set /p OUTPUT=Chemin CSV [data/live_flows.csv] :
if "%OUTPUT%"=="" set OUTPUT=data/live_flows.csv
echo.
echo Interface : %IFACE%
echo Sortie    : %OUTPUT%
echo.
call gradlew.bat executeLive -Piface="%IFACE%" -Poutput="%OUTPUT%"
pause
endlocal
