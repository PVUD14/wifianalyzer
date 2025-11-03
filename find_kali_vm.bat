@echo off
title Kali Linux VM Discovery Tool
echo Kali Linux VM Discovery Tool
echo ===========================
echo.
echo [*] Scanning for Kali Linux VMs on common IP ranges...
echo [*] This may take a few minutes...
echo.
python find_kali_vm.py
echo.
pause