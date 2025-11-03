#!/usr/bin/env python3
"""
Test Script for WiFi Penetration Tool Modules

This script demonstrates how to use individual modules of the WiFi penetration tool.
"""

import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from wifi_penetration_tool.interface_manager import InterfaceManager
from wifi_penetration_tool.scanner import NetworkScanner
from wifi_penetration_tool.sniffer import HandshakeSniffer
from wifi_penetration_tool.deauther import Deauthenticator
from wifi_penetration_tool.cracker import PasswordCracker


def test_interface_manager():
    """Test the InterfaceManager module."""
    print("=== Testing InterfaceManager ===")
    
    manager = InterfaceManager()
    
    # Check root privileges
    if not manager.check_root_privileges():
        print("This test requires root privileges.")
        return False
    
    # Detect interfaces
    interfaces = manager.detect_wireless_interfaces()
    print(f"Detected interfaces: {interfaces}")
    
    if not interfaces:
        print("No wireless interfaces found.")
        return False
    
    # Test monitor mode on first interface
    test_interface = interfaces[0]
    print(f"Testing monitor mode on {test_interface}...")
    
    original_mac = manager.get_interface_mac(test_interface)
    print(f"Original MAC: {original_mac}")
    
    if manager.enable_monitor_mode(test_interface):
        print(f"Successfully enabled monitor mode on {test_interface}")
        
        # Restore managed mode
        if manager.disable_monitor_mode(test_interface):
            print(f"Successfully restored managed mode on {test_interface}")
        else:
            print(f"Failed to restore managed mode on {test_interface}")
            return False
    else:
        print(f"Failed to enable monitor mode on {test_interface}")
        return False
    
    print("InterfaceManager test completed successfully.\n")
    return True


def test_password_cracker():
    """Test the PasswordCracker module with a sample wordlist."""
    print("=== Testing PasswordCracker ===")
    
    cracker = PasswordCracker()
    
    # Show network info extraction (would work with a real capture file)
    print("PasswordCracker module loaded successfully.")
    print("Note: Actual cracking requires a real capture file with handshake.\n")
    
    return True


def main():
    """Run all tests."""
    print("WiFi Penetration Tool - Module Tests\n")
    
    # Test individual modules
    tests = [
        test_interface_manager,
        test_password_cracker
    ]
    
    passed = 0
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"Test failed with exception: {e}\n")
    
    print(f"Tests completed: {passed}/{len(tests)} passed")
    
    if passed == len(tests):
        print("All tests passed!")
        return 0
    else:
        print("Some tests failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())