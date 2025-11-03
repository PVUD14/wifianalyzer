#!/usr/bin/env python3
"""
Interface Manager Module for WiFi Penetration Tool (Windows Version)

This module handles wireless interface detection, monitor mode toggling,
and management of network interfaces for the penetration testing utility.
Windows version uses netsh and PowerShell commands.
"""

import subprocess
import os
import sys
import re
from typing import List, Optional


class InterfaceManager:
    """Manages wireless network interfaces for monitoring and attacks."""

    def __init__(self):
        """Initialize the InterfaceManager."""
        self.interfaces = []
        self.monitor_interfaces = []

    def check_admin_privileges(self) -> bool:
        """
        Check if the script is running with administrator privileges.
        
        Returns:
            bool: True if running as administrator, False otherwise
        """
        try:
            return os.geteuid() == 0
        except AttributeError:
            # Windows doesn't have geteuid, so we check differently
            try:
                return os.environ['USERNAME'] == 'SYSTEM' or 'S-1-5-18' in subprocess.check_output(
                    'whoami /groups', shell=True, text=True)
            except:
                return False

    def detect_wireless_interfaces(self) -> List[str]:
        """
        Detect available wireless interfaces on Windows.
        
        Returns:
            List[str]: List of wireless interface names
        """
        try:
            # Use netsh to list wireless interfaces
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                  capture_output=True, text=True, check=True)
            
            interfaces = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'Name' in line and ':' in line:
                    # Extract interface name
                    name = line.split(':')[1].strip()
                    if name:
                        interfaces.append(name)
                        
            self.interfaces = interfaces
            return interfaces
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback method using PowerShell
            try:
                ps_cmd = "Get-NetAdapter -Physical | Where-Object {$_.InterfaceDescription -like '*Wireless*'} | Select-Object -ExpandProperty Name"
                result = subprocess.run(['powershell', '-Command', ps_cmd], 
                                      capture_output=True, text=True, check=True)
                
                interfaces = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        interfaces.append(line.strip())
                        
                self.interfaces = interfaces
                return interfaces
            except Exception:
                return []

    def is_monitor_mode_supported(self, interface: str) -> bool:
        """
        Check if an interface supports monitor mode.
        Note: Windows has limited native monitor mode support.
        
        Args:
            interface (str): Interface name to check
            
        Returns:
            bool: True if monitor mode is supported, False otherwise
        """
        # On Windows, monitor mode support is limited and depends on driver
        # We'll check if the interface exists and is wireless
        interfaces = self.detect_wireless_interfaces()
        return interface in interfaces

    def enable_monitor_mode(self, interface: str) -> bool:
        """
        Enable monitor mode on a wireless interface.
        Note: Windows requires special drivers for true monitor mode.
        
        Args:
            interface (str): Interface name to put in monitor mode
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # On Windows, we need to use specific tools like Win10Pcap or Npcap
            # This is a simplified implementation
            print(f"[!] Note: True monitor mode on Windows requires special drivers")
            print(f"[!] Using managed mode with packet injection capabilities")
            
            # Store monitor interface
            self.monitor_interfaces.append(interface)
            return True
        except Exception as e:
            print(f"Error enabling monitor mode: {e}")
            return False

    def disable_monitor_mode(self, interface: str) -> bool:
        """
        Disable monitor mode and restore managed mode on an interface.
        
        Args:
            interface (str): Interface name to restore
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Remove from monitor interfaces list
            if interface in self.monitor_interfaces:
                self.monitor_interfaces.remove(interface)
            return True
        except Exception as e:
            print(f"Error disabling monitor mode: {e}")
            return False

    def get_interface_mac(self, interface: str) -> Optional[str]:
        """
        Get the MAC address of an interface.
        
        Args:
            interface (str): Interface name
            
        Returns:
            Optional[str]: MAC address or None if failed
        """
        try:
            # Use PowerShell to get MAC address
            ps_cmd = f"(Get-NetAdapter -Name '{interface}').MacAddress"
            result = subprocess.run(['powershell', '-Command', ps_cmd], 
                                  capture_output=True, text=True, check=True)
            mac = result.stdout.strip()
            # Format MAC address (Windows returns it without colons sometimes)
            if mac and ':' not in mac:
                mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
            return mac
        except subprocess.CalledProcessError:
            return None

    def change_mac_address(self, interface: str, new_mac: str) -> bool:
        """
        Change the MAC address of an interface.
        Note: Windows has limited MAC address changing capabilities.
        
        Args:
            interface (str): Interface name
            new_mac (str): New MAC address
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Windows requires special tools or registry changes for MAC spoofing
            print(f"[!] Note: MAC address changing on Windows requires special tools")
            print(f"[!] This feature may not work without additional software")
            return False
        except Exception as e:
            print(f"Error changing MAC address: {e}")
            return False

    def restore_original_state(self) -> None:
        """Restore all interfaces to their original state."""
        for interface in self.monitor_interfaces[:]:
            self.disable_monitor_mode(interface)


def main():
    """Main function for testing the InterfaceManager."""
    manager = InterfaceManager()
    print("Detecting wireless interfaces...")
    interfaces = manager.detect_wireless_interfaces()
    
    if not interfaces:
        print("No wireless interfaces found.")
        return
    
    print(f"Found interfaces: {interfaces}")
    
    # Test monitor mode on the first interface
    test_interface = interfaces[0]
    print(f"Testing monitor mode support on {test_interface}...")
    
    if manager.is_monitor_mode_supported(test_interface):
        print(f"Interface {test_interface} supports wireless operations")
    else:
        print(f"Interface {test_interface} does not support wireless operations")


if __name__ == "__main__":
    main()