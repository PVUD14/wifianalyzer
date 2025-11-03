@echo off
title WiFi Penetration Tool Setup for Windows

echo WiFi Penetration Tool Setup for Windows
echo ======================================
echo.
echo This script will help set up the WiFi Penetration Testing Tool on Windows.
echo.
echo Prerequisites:
echo - Python 3.8 or higher
echo - Administrator privileges
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorLevel% == 0 (
    for /f "tokens=*" %%i in ('python --version') do set PYTHON_VERSION=%%i
    echo [+] Found %PYTHON_VERSION%
) else (
    echo [-] Python not found. Please install Python 3.8 or higher.
    echo    Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [+] Running with administrator privileges
) else (
    echo [-] Administrator privileges required for full functionality
    echo [-] Some features may not work without administrator privileges
    echo.
)

echo.
echo Setup Options:
echo 1. Basic setup (check dependencies only)
echo 2. Full setup (install additional tools - requires internet)
echo.
choice /c 12 /m "Select setup option"
if errorlevel 2 goto full_setup
if errorlevel 1 goto basic_setup

:basic_setup
echo.
echo [*] Performing basic setup...
echo [*] Checking for required system tools...

REM Check for netsh (should be available on all Windows systems)
netsh wlan show drivers >nul 2>&1
if %errorLevel% == 0 (
    echo [+] netsh is available
) else (
    echo [-] netsh not available. This tool requires Windows with wireless support.
    pause
    exit /b 1
)

echo.
echo [*] Basic setup completed successfully!
echo [*] You can now run the tool with:
echo    wifi_tool_windows.bat
goto end

:full_setup
echo.
echo [*] Performing full setup...
echo [*] This will download and install additional tools.
echo.

echo [*] Checking for aircrack-ng for Windows...
where aircrack-ng >nul 2>&1
if %errorLevel% == 0 (
    echo [+] aircrack-ng is already installed
) else (
    echo [-] aircrack-ng not found.
    echo [-] For full functionality, please download aircrack-ng for Windows from:
    echo    https://www.aircrack-ng.org/
    echo.
)

echo [*] Checking for Npcap...
reg query "HKLM\SOFTWARE\Npcap" >nul 2>&1
if %errorLevel% == 0 (
    echo [+] Npcap is already installed
) else (
    echo [-] Npcap not found.
    echo [-] For packet capture functionality, please download Npcap from:
    echo    https://nmap.org/npcap/
    echo.
)

echo.
echo [*] Full setup completed!
echo [*] Note: Some tools require manual installation.
echo [*] You can now run the tool with:
echo    wifi_tool_windows.bat

:end
echo.
echo Setup finished.
pause