@echo off
title WiFi Penetration Tool - Complete Setup
echo WiFi Penetration Tool Complete Setup
echo ==================================
echo.

echo [*] Checking Python installation...
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

echo.
echo [*] Checking for required Python packages...

echo [*] Checking for tkinter (should be included with Python)...
python -c "import tkinter; print('[+] tkinter is available')" 2>nul
if %errorLevel% == 0 (
    echo [+] tkinter is available
) else (
    echo [-] tkinter not found. It should be included with Python.
)

echo.
echo [*] Installing required Python packages...
echo [*] Installing paramiko for SSH connectivity...
pip install paramiko
if %errorLevel% == 0 (
    echo [+] paramiko installed successfully
) else (
    echo [-] Failed to install paramiko
)

echo.
echo [*] Creating desktop shortcuts...

echo [*] Setup complete!
echo.
echo You can now run:
echo 1. run_gui.bat - For local Windows GUI
echo 2. run_ssh_gui.bat - For SSH connection GUI
echo.
pause