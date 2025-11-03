@echo off
echo WiFi Penetration Testing Tool for Windows
echo ========================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [+] Running with administrator privileges
) else (
    echo [-] This tool requires administrator privileges
    echo [-] Please right-click and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo [*] Starting WiFi Penetration Testing Tool...
echo.

python wifi_penetration_tool_windows\main.py %*

echo.
echo [*] WiFi Penetration Tool finished.
pause