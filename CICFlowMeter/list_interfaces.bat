@echo off
setlocal
call gradlew.bat executeLive -PlistInterfaces
pause
endlocal
