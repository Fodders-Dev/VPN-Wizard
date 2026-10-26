@echo off
setlocal
set "SCRIPT=%~dp0Set-VpnServerIp.ps1"
where pwsh >nul 2>nul
if not errorlevel 1 (
    pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
)
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="0" echo Operation failed with code %RESULT%.
pause
exit /b %RESULT%
