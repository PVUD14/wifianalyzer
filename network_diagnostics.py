#!/usr/bin/env python3
"""
Network Diagnostics Tool for WiFi Penetration Testing Environment

This tool helps diagnose network connectivity issues between the Windows host
and the Kali Linux VM, and provides guidance for establishing connections.
"""

import subprocess
import sys
import socket
import time
import platform


def check_vm_status():
    """Check if virtualization software is installed."""
    print("[*] Checking virtualization environment...")
    
    # Check for VirtualBox
    try:
        result = subprocess.run(['VBoxManage', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"[+] VirtualBox detected: {result.stdout.strip()}")
            return "VirtualBox"
    except FileNotFoundError:
        pass
    
    # Check for VMware
    try:
        result = subprocess.run(['vmrun', 'list'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("[+] VMware detected")
            return "VMware"
    except FileNotFoundError:
        pass
    
    # Check for Hyper-V
    if platform.system() == "Windows":
        try:
            result = subprocess.run(['powershell', '-Command', 'Get-VM'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                print("[+] Hyper-V detected")
                return "Hyper-V"
        except FileNotFoundError:
            pass
    
    print("[*] No virtualization software detected or VM not running")
    return None


def check_network_interfaces():
    """Check network interfaces on the Windows host."""
    print("\n[*] Checking network interfaces...")
    
    try:
        if platform.system() == "Windows":
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            print("[*] Network interfaces:")
            for line in result.stdout.split('\n'):
                if 'IPv4 Address' in line or 'Ethernet adapter' in line:
                    print(f"  {line.strip()}")
        else:
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
            print("[*] Network interfaces:")
            for line in result.stdout.split('\n'):
                if 'inet ' in line or 'eth' in line or 'wlan' in line:
                    print(f"  {line.strip()}")
    except Exception as e:
        print(f"[-] Error checking network interfaces: {e}")


def check_network_connectivity(target_ip):
    """Check basic network connectivity to the target IP."""
    print(f"\n[*] Checking network connectivity to {target_ip}...")
    
    try:
        # Try to ping the target
        if platform.system() == "Windows":
            result = subprocess.run(['ping', '-n', '4', target_ip], 
                                  capture_output=True, text=True, timeout=30)
        else:
            result = subprocess.run(['ping', '-c', '4', target_ip], 
                                  capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("[+] Ping successful")
            print(f"  {result.stdout}")
            return True
        else:
            print("[-] Ping failed")
            print(f"  Error: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("[-] Ping timed out")
        return False
    except Exception as e:
        print(f"[-] Error during ping: {e}")
        return False


def check_port_connectivity(target_ip, port):
    """Check if a specific port is open on the target."""
    print(f"\n[*] Checking port {port} connectivity to {target_ip}...")
    
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


def check_ssh_service(target_ip, port=22):
    """Check if SSH service is running on the target."""
    print(f"\n[*] Checking SSH service on {target_ip}:{port}...")
    
    try:
        # Try SSH connection with a simple command
        cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', 
               f'user@{target_ip}', 'exit']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("[+] SSH service is accessible")
            return True
        else:
            if "Permission denied" in result.stderr:
                print("[+] SSH service is running (authentication required)")
                return True
            elif "Connection refused" in result.stderr:
                print("[-] SSH service is not running or blocked")
                return False
            elif "Connection timed out" in result.stderr:
                print("[-] SSH service is not accessible (network issue)")
                return False
            else:
                print(f"[?] SSH check result: {result.stderr.strip()}")
                return False
    except subprocess.TimeoutExpired:
        print("[-] SSH connection timed out")
        return False
    except FileNotFoundError:
        print("[-] SSH client not found")
        return False
    except Exception as e:
        print(f"[-] Error during SSH check: {e}")
        return False


def suggest_solutions(vm_type, target_ip):
    """Suggest solutions based on the detected environment."""
    print("\n[*] Suggested solutions:")
    
    if not vm_type:
        print("1. Ensure your Kali Linux VM is running")
        print("2. Install virtualization software (VirtualBox, VMware, or Hyper-V)")
        print("3. Create and start a Kali Linux VM")
        return
    
    print(f"1. Verify {vm_type} is properly configured")
    
    if vm_type == "VirtualBox":
        print("2. Check VirtualBox network settings:")
        print("   - Ensure the VM is using 'Bridged' or 'NAT' adapter")
        print("   - For Bridged: VM gets IP on your local network")
        print("   - For NAT: VM gets IP like 10.0.2.x")
        print("3. Check VM network adapter status in VirtualBox settings")
        
    elif vm_type == "VMware":
        print("2. Check VMware network settings:")
        print("   - Ensure the VM is using 'Bridged' or 'NAT' adapter")
        print("   - Verify VMware Network Adapter VMnet8 is enabled")
        
    elif vm_type == "Hyper-V":
        print("2. Check Hyper-V network settings:")
        print("   - Ensure the VM has a virtual switch assigned")
        print("   - Check if the virtual switch is external or internal")
    
    print(f"4. Verify Kali Linux VM is running and accessible")
    print(f"5. Check if IP address {target_ip} is correct for your VM")
    print(f"6. Try accessing the VM through its console to verify network settings")
    print(f"7. In Kali VM, run: ip addr show to check assigned IP addresses")
    print(f"8. In Kali VM, ensure SSH is running: sudo systemctl status ssh")


def find_kali_vm_ips():
    """Try to find Kali Linux VM IP addresses."""
    print("\n[*] Attempting to discover Kali VM IP addresses...")
    
    # Common IP ranges for VMs
    common_ranges = [
        "192.168.1.",  # Typical router network
        "10.0.2.",     # VirtualBox NAT
        "172.16.0.",   # Private network range
        "192.168.56."  # VirtualBox host-only
    ]
    
    print("[*] Common VM IP ranges to check:")
    for range_prefix in common_ranges:
        print(f"  - {range_prefix}1 to {range_prefix}254")
    
    print("\n[*] To find your Kali VM IP:")
    print("  1. Access the VM console directly")
    print("  2. Run in Kali terminal: ip addr show")
    print("  3. Look for eth0, enp0s3, or similar interface with an IP")
    print("  4. Note the IP address and try connecting with that")


def main():
    # Configuration
    TARGET_IP = "172.18.0.1"
    SSH_PORT = 22
    
    print("Network Diagnostics Tool for Kali Linux VM")
    print("=" * 50)
    print(f"Target IP: {TARGET_IP}")
    print(f"SSH Port: {SSH_PORT}")
    print()
    
    # Check virtualization environment
    vm_type = check_vm_status()
    
    # Check network interfaces
    check_network_interfaces()
    
    # Check network connectivity
    if not check_network_connectivity(TARGET_IP):
        print("\n[!] Network connectivity issue detected.")
        suggest_solutions(vm_type, TARGET_IP)
        find_kali_vm_ips()
        return
    
    # Check SSH port
    if not check_port_connectivity(TARGET_IP, SSH_PORT):
        print("\n[!] SSH port is not accessible.")
        print("    Possible solutions:")
        print("    1. Ensure SSH service is running on the Kali VM")
        print("    2. Check SSH service status: sudo systemctl status ssh")
        print("    3. Check SSH configuration: /etc/ssh/sshd_config")
        print("    4. Verify firewall settings on the Kali VM")
        return
    
    # Check SSH service
    if not check_ssh_service(TARGET_IP):
        print("\n[!] SSH service check failed.")
        print("    Possible solutions:")
        print("    1. Verify username and password")
        print("    2. Check if key-based authentication is required")
        print("    3. Ensure SSH service is properly configured")
        print("    4. Check for network restrictions")
        return
    
    print("\n[+] All checks passed! SSH connection should work.")
    print("\nTo connect to your Kali VM, use:")
    print(f"   ssh vaptrix@{TARGET_IP}")


if __name__ == "__main__":
    main()