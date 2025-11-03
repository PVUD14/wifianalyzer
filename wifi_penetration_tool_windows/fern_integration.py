#!/usr/bin/env python3
"""
Fern-WiFi-Cracker Integration Module (Windows Version)

This module provides integration with the fern-wifi-cracker tool
running on a remote Kali Linux system, allowing the Windows application
to leverage fern's capabilities for wireless network penetration testing.
"""

import subprocess
import os
import sys
import time
from typing import Optional, List


class FernIntegration:
    """Integration class for fern-wifi-cracker tool (remote access)."""

    def __init__(self, host: str = "172.18.0.1", username: str = "vaptrix", 
                 password: str = "Xevyte@2025", port: int = 22):
        """
        Initialize the FernIntegration.
        
        Args:
            host (str): Kali Linux VM IP address
            username (str): SSH username
            password (str): SSH password
            port (int): SSH port
        """
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.is_connected = False

    def _check_ssh_connection(self) -> bool:
        """
        Check if SSH connection to Kali VM is possible.
        
        Returns:
            bool: True if connection is possible, False otherwise
        """
        try:
            # Test TCP connection to SSH port
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def is_fern_available(self) -> bool:
        """
        Check if fern-wifi-cracker is available on the remote system.
        
        Returns:
            bool: True if available, False otherwise
        """
        if not self._check_ssh_connection():
            return False

        try:
            cmd = f"ssh -p {self.port} {self.username}@{self.host} 'which fern-wifi-cracker'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def run_fern_command(self, command: str) -> Optional[str]:
        """
        Run a fern-wifi-cracker command on the remote system.
        
        Args:
            command (str): Command to run
            
        Returns:
            Optional[str]: Output from the command or None if failed
        """
        if not self._check_ssh_connection():
            print("[-] Cannot connect to Kali Linux VM")
            return None

        try:
            full_cmd = f"ssh -p {self.port} {self.username}@{self.host} '{command}'"
            result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return result.stdout
            else:
                print(f"[-] Command failed: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print("[-] Command timed out")
            return None
        except Exception as e:
            print(f"[-] Command failed: {e}")
            return None

    def start_fern_scan(self, interface: str = "") -> Optional[str]:
        """
        Run a network scan using fern-wifi-cracker on the remote system.
        
        Args:
            interface (str): Wireless interface to use (optional)
            
        Returns:
            Optional[str]: Output from the scan or None if failed
        """
        cmd = "sudo fern-wifi-cracker --cli --scan"
        if interface:
            cmd += f" --interface {interface}"
            
        print(f"[*] Running remote fern-wifi-cracker scan...")
        return self.run_fern_command(cmd)

    def run_fern_attack(self, target_bssid: str, wordlist: str, 
                       interface: str = "") -> Optional[str]:
        """
        Run a WPA/WPA2 cracking attack using fern-wifi-cracker on the remote system.
        
        Args:
            target_bssid (str): Target network BSSID
            wordlist (str): Path to wordlist file
            interface (str): Wireless interface to use (optional)
            
        Returns:
            Optional[str]: Output from the attack or None if failed
        """
        cmd = f"sudo fern-wifi-cracker --cli --attack {target_bssid} --wordlist {wordlist}"
        if interface:
            cmd += f" --interface {interface}"
            
        print(f"[*] Running remote fern-wifi-cracker attack on {target_bssid}...")
        return self.run_fern_command(cmd)

    def get_fern_version(self) -> Optional[str]:
        """
        Get the version of fern-wifi-cracker on the remote system.
        
        Returns:
            Optional[str]: Version string or None if failed
        """
        return self.run_fern_command("fern-wifi-cracker --version")

    def install_fern(self) -> bool:
        """
        Attempt to install fern-wifi-cracker on the remote system.
        
        Returns:
            bool: True if installed successfully, False otherwise
        """
        install_cmd = "sudo apt update && sudo apt install -y fern-wifi-cracker"
        print("[*] Installing fern-wifi-cracker on remote system...")
        result = self.run_fern_command(install_cmd)
        return result is not None

    def check_required_tools(self) -> Optional[str]:
        """
        Check if required tools are installed on the remote system.
        
        Returns:
            Optional[str]: Output from the check or None if failed
        """
        cmd = "which aircrack-ng airodump-ng aireplay-ng iw macchanger"
        return self.run_fern_command(cmd)


def main():
    """Main function for testing the FernIntegration."""
    fern = FernIntegration()
    
    if not fern._check_ssh_connection():
        print("[-] Cannot connect to Kali Linux VM (172.18.0.1)")
        print("[*] Please ensure the VM is running and accessible")
        return
    
    print("[+] Connected to Kali Linux VM")
    
    if not fern.is_fern_available():
        print("[-] fern-wifi-cracker is not available on the remote system")
        print("[*] Attempting to install...")
        if not fern.install_fern():
            print("[-] Installation failed")
            return
        else:
            print("[+] fern-wifi-cracker installed successfully")
    
    version = fern.get_fern_version()
    if version:
        print(f"[+] fern-wifi-cracker version: {version}")
    else:
        print("[-] Could not retrieve fern-wifi-cracker version")


if __name__ == "__main__":
    main()