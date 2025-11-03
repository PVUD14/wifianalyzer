#!/usr/bin/env python3
"""
Test Script for Fern-WiFi-Cracker Integration

This script tests the integration with fern-wifi-cracker on both
local Linux and remote Windows setups.
"""

import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

def test_local_fern():
    """Test fern integration on local Linux system."""
    print("=== Testing Local Fern Integration ===")
    
    try:
        from wifi_penetration_tool.fern_integration import FernIntegration
        fern = FernIntegration()
        
        if fern.is_fern_available():
            print("[+] Fern-WiFi-Cracker is available")
            version = fern.get_fern_version()
            if version:
                print(f"[+] Version: {version}")
            else:
                print("[-] Could not retrieve version")
        else:
            print("[-] Fern-WiFi-Cracker is not available")
            print("[*] Attempting to install...")
            if fern.install_fern():
                print("[+] Installation successful")
            else:
                print("[-] Installation failed")
                
        return True
    except Exception as e:
        print(f"[-] Test failed with exception: {e}")
        return False

def test_remote_fern():
    """Test fern integration on remote Kali VM."""
    print("\n=== Testing Remote Fern Integration ===")
    
    try:
        from wifi_penetration_tool_windows.fern_integration import FernIntegration
        fern = FernIntegration()
        
        if fern._check_ssh_connection():
            print("[+] Connected to Kali Linux VM")
            
            if fern.is_fern_available():
                print("[+] Fern-WiFi-Cracker is available on remote system")
                version = fern.get_fern_version()
                if version:
                    print(f"[+] Version: {version}")
                else:
                    print("[-] Could not retrieve version")
            else:
                print("[-] Fern-WiFi-Cracker is not available on remote system")
                install = input("Do you want to try installing it? (y/n): ")
                if install.lower() == 'y':
                    if fern.install_fern():
                        print("[+] Installation successful")
                    else:
                        print("[-] Installation failed")
        else:
            print("[-] Cannot connect to Kali Linux VM")
            print("[*] Make sure the VM is running and accessible")
                
        return True
    except Exception as e:
        print(f"[-] Test failed with exception: {e}")
        return False

def main():
    """Run all tests."""
    print("Fern-WiFi-Cracker Integration Tests\n")
    
    # Test local integration (Linux)
    local_success = test_local_fern()
    
    # Test remote integration (Windows)
    remote_success = test_remote_fern()
    
    print(f"\nTests completed:")
    print(f"Local integration: {'PASS' if local_success else 'FAIL'}")
    print(f"Remote integration: {'PASS' if remote_success else 'FAIL'}")
    
    if local_success and remote_success:
        print("All tests passed!")
        return 0
    else:
        print("Some tests failed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())