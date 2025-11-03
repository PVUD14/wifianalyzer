@echo off
title Install Fern-WiFi-Cracker on Kali Linux VM
echo Installing Fern-WiFi-Cracker on Kali Linux VM
echo ==========================================
echo.

set KALI_IP=172.18.0.1
set USERNAME=vaptrix
set PASSWORD=Xevyte@2025

echo [*] Uploading setup script to Kali VM...
scp e:\WIFI\setup_fern_wifi_cracker.sh %USERNAME%@%KALI_IP%:/tmp/setup_fern_wifi_cracker.sh
if %errorLevel% == 0 (
    echo [+] Setup script uploaded successfully
) else (
    echo [-] Failed to upload setup script
    echo [*] Make sure your Kali VM is running and accessible
    pause
    exit /b 1
)

echo.
echo [*] Running setup script on Kali VM...
ssh %USERNAME%@%KALI_IP% "chmod +x /tmp/setup_fern_wifi_cracker.sh && sudo /tmp/setup_fern_wifi_cracker.sh"
if %errorLevel% == 0 (
    echo [+] Fern-WiFi-Cracker installed successfully
) else (
    echo [-] Installation failed
    pause
    exit /b 1
)

echo.
echo [*] Installation complete!
echo [*] You can now use fern-wifi-cracker on your Kali VM
pause