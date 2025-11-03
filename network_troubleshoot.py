#!/usr/bin/env python3
"""
Network Troubleshooting Tool for WiFi Penetration Testing Environment

This tool helps diagnose network connectivity issues between the Windows host
and the Kali Linux VM, and provides guidance for establishing SSH connections.
"""

import subprocess
import sys
import socket
import time


def check_network_connectivity(target_ip):
    """Check basic network connectivity to the target IP."""
    print(f"[*] Checking network connectivity to {target_ip}...")
    
    try:
        # Try to ping the target
        result = subprocess.run(['ping', '-n', '4', target_ip], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("[+] Ping successful")
            return True
        else:
            print("[-] Ping failed")
            print(f"   Error: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("[-] Ping timed out")
        return False
    except Exception as e:
        print(f"[-] Error during ping: {e}")
        return False


def check_port_connectivity(target_ip, port):
    """Check if a specific port is open on the target."""
    print(f"[*] Checking port {port} connectivity to {target_ip}...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        
        if result == 0:
            print(f"[+] Port {port} is open")
            return True
        else:
            print(f"[-] Port {port} is closed or filtered")
            return False
    except Exception as e:
        print(f"[-] Error checking port {port}: {e}")
        return False


def check_ssh_client():
    """Check if SSH client is available."""
    print("[*] Checking SSH client availability...")
    
    try:
        result = subprocess.run(['ssh', '-V'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode in [0, 1]:  # SSH version command often returns 1
            print(f"[+] SSH client found: {result.stderr.strip()}")
            return True
        else:
            print("[-] SSH client not found")
            return False
    except Exception as e:
        print(f"[-] Error checking SSH client: {e}")
        return False


def test_ssh_connection(username, ip, password=None):
    """Test SSH connection to the target."""
    print(f"[*] Testing SSH connection to {username}@{ip}...")
    
    try:
        # Test SSH connection with a simple command (non-interactive)
        cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', 
               f'{username}@{ip}', 'echo "SSH connection test successful"']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            print("[+] SSH connection successful")
            print(f"   Output: {result.stdout.strip()}")
            return True
        else:
            print("[-] SSH connection failed")
            if "Permission denied" in result.stderr:
                print("   Reason: Authentication failed")
            elif "Connection refused" in result.stderr:
                print("   Reason: Connection refused (SSH service may be down)")
            elif "Connection timed out" in result.stderr:
                print("   Reason: Connection timed out (network issue)")
            else:
                print(f"   Error: {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        print("[-] SSH connection timed out")
        return False
    except Exception as e:
        print(f"[-] Error during SSH test: {e}")
        return False


def check_vm_status():
    """Check if the VM might be running in a specific environment."""
    print("[*] Checking virtualization environment...")
    
    # Check if this might be a Docker environment
    try:
        result = subprocess.run(['docker', 'version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("[+] Docker environment detected")
            return "docker"
    except:
        pass
    
    # Check if this might be a WSL environment
    try:
        result = subprocess.run(['wsl', '--list'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("[+] WSL environment detected")
            return "wsl"
    except:
        pass
    
    print("[*] Standard Windows environment detected")
    return "windows"


def main():
    # Configuration
    KALI_IP = "172.18.0.1"
    USERNAME = "vaptrix"
    SSH_PORT = 22
    
    print("Network Troubleshooting Tool for Kali Linux VM")
    print("=" * 50)
    print(f"Target IP: {KALI_IP}")
    print(f"Username: {USERNAME}")
    print(f"SSH Port: {SSH_PORT}")
    print()
    
    # Check environment
    env = check_vm_status()
    print()
    
    # Check SSH client
    if not check_ssh_client():
        print("\n[!] SSH client not found. Please install OpenSSH client.")
        if env == "windows":
            print("    Run in PowerShell as Administrator:")
            print("    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0")
        return
    
    print()
    
    # Check network connectivity
    if not check_network_connectivity(KALI_IP):
        print("\n[!] Network connectivity issue detected.")
        print("    Possible solutions:")
        print("    1. Check if the Kali Linux VM is running")
        print("    2. Verify network settings (Bridged/NAT/Host-only)")
        print("    3. Check Windows Firewall settings")
        print("    4. Verify the IP address is correct")
        return
    
    print()
    
    # Check SSH port
    if not check_port_connectivity(KALI_IP, SSH_PORT):
        print("\n[!] SSH port is not accessible.")
        print("    Possible solutions:")
        print("    1. Ensure SSH service is running on the Kali VM")
        print("    2. Check SSH service status: sudo systemctl status ssh")
        print("    3. Check SSH configuration: /etc/ssh/sshd_config")
        print("    4. Verify firewall settings on the Kali VM")
        return
    
    print()
    
    # Test SSH connection
    if not test_ssh_connection(USERNAME, KALI_IP):
        print("\n[!] SSH connection test failed.")
        print("    Possible solutions:")
        print("    1. Verify username and password")
        print("    2. Check if key-based authentication is required")
        print("    3. Ensure SSH service is properly configured")
        print("    4. Check for network restrictions")
        return
    
    print("\n[+] All checks passed! SSH connection should work.")
    print("\nTo connect to your Kali VM, use:")
    print(f"   ssh {USERNAME}@{KALI_IP}")


if __name__ == "__main__":
    main()