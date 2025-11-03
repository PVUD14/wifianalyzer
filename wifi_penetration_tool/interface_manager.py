#!/usr/bin/env python3
"""
Interface Manager Module for WiFi Penetration Tool

This module handles wireless interface detection, monitor mode toggling,
and management of network interfaces for the penetration testing utility.
"""

import subprocess
import os
import sys
from typing import List, Optional


class InterfaceManager:
    """Manages wireless network interfaces for monitoring and attacks."""

    def __init__(self):
        """Initialize the InterfaceManager."""
        self.interfaces = []
        self.monitor_interfaces = []

    def check_root_privileges(self) -> bool:
        """
        Check if the script is running with root privileges.
        
        Returns:
            bool: True if running as root, False otherwise
        """
        return os.geteuid() == 0

    def detect_wireless_interfaces(self) -> List[str]:
        """
        Detect available wireless interfaces on the system.
        
        Returns:
            List[str]: List of wireless interface names
        """
        try:
            # Use iw command to list wireless interfaces
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, check=True)
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    interface = line.split()[1]
                    interfaces.append(interface)
            self.interfaces = interfaces
            return interfaces
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to parsing /proc/net/dev
            try:
                with open('/proc/net/dev', 'r') as f:
                    lines = f.readlines()[2:]  # Skip header lines
                interfaces = []
                for line in lines:
                    interface = line.split(':')[0].strip()
                    if interface.startswith('wl'):
                        interfaces.append(interface)
                self.interfaces = interfaces
                return interfaces
            except Exception:
                return []

    def is_monitor_mode_supported(self, interface: str) -> bool:
        """
        Check if an interface supports monitor mode.
        
        Args:
            interface (str): Interface name to check
            
        Returns:
            bool: True if monitor mode is supported, False otherwise
        """
        try:
            result = subprocess.run(['iw', 'phy', f'phy{interface[-1]}', 'info'], 
                                  capture_output=True, text=True, check=True)
            return 'monitor' in result.stdout
        except (subprocess.CalledProcessError, IndexError):
            return False

    def enable_monitor_mode(self, interface: str) -> bool:
        """
        Enable monitor mode on a wireless interface.
        
        Args:
            interface (str): Interface name to put in monitor mode
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Bring interface down
            subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                         capture_output=True, check=True)
            
            # Set interface to monitor mode
            subprocess.run(['iw', interface, 'set', 'monitor', 'control'], 
                         capture_output=True, check=True)
            
            # Bring interface up
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                         capture_output=True, check=True)
            
            # Store monitor interface
            self.monitor_interfaces.append(interface)
            return True
        except subprocess.CalledProcessError:
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
            # Bring interface down
            subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                         capture_output=True, check=True)
            
            # Set interface to managed mode
            subprocess.run(['iw', interface, 'set', 'type', 'managed'], 
                         capture_output=True, check=True)
            
            # Bring interface up
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                         capture_output=True, check=True)
            
            # Remove from monitor interfaces list
            if interface in self.monitor_interfaces:
                self.monitor_interfaces.remove(interface)
            return True
        except subprocess.CalledProcessError:
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
            result = subprocess.run(['cat', f'/sys/class/net/{interface}/address'], 
                                  capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    def change_mac_address(self, interface: str, new_mac: str) -> bool:
        """
        Change the MAC address of an interface.
        
        Args:
            interface (str): Interface name
            new_mac (str): New MAC address
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                         capture_output=True, check=True)
            subprocess.run(['macchanger', '-m', new_mac, interface], 
                         capture_output=True, check=True)
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                         capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def restore_original_state(self) -> None:
        """Restore all interfaces to their original state."""
        for interface in self.monitor_interfaces[:]:
            self.disable_monitor_mode(interface)


def main():
    """Main function for testing the InterfaceManager."""
    if not os.geteuid() == 0:
        print("This script requires root privileges.")
        sys.exit(1)
    
    manager = InterfaceManager()
    print("Detecting wireless interfaces...")
    interfaces = manager.detect_wireless_interfaces()
    
    if not interfaces:
        print("No wireless interfaces found.")
        return
    
    print(f"Found interfaces: {interfaces}")
    
    # Test monitor mode on the first interface
    test_interface = interfaces[0]
    print(f"Testing monitor mode on {test_interface}...")
    
    if manager.enable_monitor_mode(test_interface):
        print(f"Successfully enabled monitor mode on {test_interface}")
        
        # Restore managed mode
        if manager.disable_monitor_mode(test_interface):
            print(f"Successfully restored managed mode on {test_interface}")
        else:
            print(f"Failed to restore managed mode on {test_interface}")
    else:
        print(f"Failed to enable monitor mode on {test_interface}")


if __name__ == "__main__":
    main()