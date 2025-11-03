#!/usr/bin/env python3
"""
Fern-WiFi-Cracker Integration Module

This module provides integration with the fern-wifi-cracker tool,
allowing the main application to leverage fern's capabilities
for wireless network penetration testing.
"""

import subprocess
import os
import sys
import time
from typing import Optional, List


class FernIntegration:
    """Integration class for fern-wifi-cracker tool."""

    def __init__(self):
        """Initialize the FernIntegration."""
        self.fern_process = None
        self.is_installed = self._check_installation()

    def _check_installation(self) -> bool:
        """
        Check if fern-wifi-cracker is installed.
        
        Returns:
            bool: True if installed, False otherwise
        """
        try:
            result = subprocess.run(['which', 'fern-wifi-cracker'], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def is_fern_available(self) -> bool:
        """
        Check if fern-wifi-cracker is available for use.
        
        Returns:
            bool: True if available, False otherwise
        """
        return self.is_installed

    def start_fern_gui(self) -> bool:
        """
        Start the fern-wifi-cracker GUI.
        
        Returns:
            bool: True if started successfully, False otherwise
        """
        if not self.is_installed:
            print("[-] fern-wifi-cracker is not installed")
            return False

        try:
            print("[*] Starting fern-wifi-cracker GUI...")
            # Start fern-wifi-cracker in the background
            self.fern_process = subprocess.Popen(['fern-wifi-cracker'], 
                                               stdout=subprocess.DEVNULL, 
                                               stderr=subprocess.DEVNULL)
            print("[+] fern-wifi-cracker GUI started successfully")
            return True
        except Exception as e:
            print(f"[-] Failed to start fern-wifi-cracker: {e}")
            return False

    def stop_fern_gui(self) -> bool:
        """
        Stop the fern-wifi-cracker GUI.
        
        Returns:
            bool: True if stopped successfully, False otherwise
        """
        if self.fern_process and self.fern_process.poll() is None:
            try:
                self.fern_process.terminate()
                self.fern_process.wait(timeout=5)
                print("[+] fern-wifi-cracker GUI stopped")
                return True
            except subprocess.TimeoutExpired:
                self.fern_process.kill()
                self.fern_process.wait()
                print("[+] fern-wifi-cracker GUI forcefully stopped")
                return True
        elif self.fern_process:
            print("[*] fern-wifi-cracker GUI is not running")
            return True
        else:
            print("[*] No fern-wifi-cracker process to stop")
            return True

    def run_fern_scan(self, interface: str = "") -> Optional[str]:
        """
        Run a network scan using fern-wifi-cracker.
        
        Args:
            interface (str): Wireless interface to use (optional)
            
        Returns:
            Optional[str]: Output from the scan or None if failed
        """
        if not self.is_installed:
            print("[-] fern-wifi-cracker is not installed")
            return None

        try:
            print("[*] Running fern-wifi-cracker scan...")
            cmd = ['fern-wifi-cracker', '--cli', '--scan']
            if interface:
                cmd.extend(['--interface', interface])
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print("[+] Scan completed successfully")
                return result.stdout
            else:
                print(f"[-] Scan failed: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print("[-] Scan timed out")
            return None
        except Exception as e:
            print(f"[-] Scan failed: {e}")
            return None

    def run_fern_attack(self, target_bssid: str, wordlist: str, 
                       interface: str = "") -> Optional[str]:
        """
        Run a WPA/WPA2 cracking attack using fern-wifi-cracker.
        
        Args:
            target_bssid (str): Target network BSSID
            wordlist (str): Path to wordlist file
            interface (str): Wireless interface to use (optional)
            
        Returns:
            Optional[str]: Output from the attack or None if failed
        """
        if not self.is_installed:
            print("[-] fern-wifi-cracker is not installed")
            return None

        try:
            print(f"[*] Running fern-wifi-cracker attack on {target_bssid}...")
            cmd = ['fern-wifi-cracker', '--cli', '--attack', target_bssid, 
                   '--wordlist', wordlist]
            if interface:
                cmd.extend(['--interface', interface])
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if result.returncode == 0:
                print("[+] Attack completed successfully")
                return result.stdout
            else:
                print(f"[-] Attack failed: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print("[-] Attack timed out")
            return None
        except Exception as e:
            print(f"[-] Attack failed: {e}")
            return None

    def get_fern_version(self) -> Optional[str]:
        """
        Get the version of fern-wifi-cracker.
        
        Returns:
            Optional[str]: Version string or None if failed
        """
        if not self.is_installed:
            return None

        try:
            result = subprocess.run(['fern-wifi-cracker', '--version'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return None
        except Exception:
            return None

    def install_fern(self) -> bool:
        """
        Attempt to install fern-wifi-cracker.
        
        Returns:
            bool: True if installed successfully, False otherwise
        """
        try:
            print("[*] Installing fern-wifi-cracker...")
            # Try using apt first
            result = subprocess.run(['sudo', 'apt', 'install', '-y', 'fern-wifi-cracker'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                self.is_installed = True
                print("[+] fern-wifi-cracker installed successfully")
                return True
            else:
                print("[-] Failed to install via apt")
                return False
        except Exception as e:
            print(f"[-] Installation failed: {e}")
            return False


def main():
    """Main function for testing the FernIntegration."""
    fern = FernIntegration()
    
    if not fern.is_fern_available():
        print("[-] fern-wifi-cracker is not available")
        print("[*] Attempting to install...")
        if not fern.install_fern():
            print("[-] Installation failed")
            return
    
    print(f"[+] fern-wifi-cracker version: {fern.get_fern_version()}")
    
    # Example usage
    print("[*] Starting fern-wifi-cracker GUI...")
    if fern.start_fern_gui():
        time.sleep(5)  # Let it run for a bit
        print("[*] Stopping fern-wifi-cracker GUI...")
        fern.stop_fern_gui()


if __name__ == "__main__":
    main()