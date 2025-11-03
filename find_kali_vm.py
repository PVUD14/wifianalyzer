#!/usr/bin/env python3
"""
Kali Linux VM Discovery Tool

This tool helps discover the IP address of a running Kali Linux VM
by scanning common IP ranges used by virtualization software.
"""

import subprocess
import sys
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class KaliVMDetector:
    def __init__(self):
        self.found_ips = []
        self.scanning = False
        
    def ping_host(self, ip):
        """Ping a host to check if it's alive."""
        try:
            # Use ping command
            if sys.platform.startswith('win'):
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, timeout=2)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, timeout=2)
            
            return result.returncode == 0
        except:
            return False
            
    def check_ssh_port(self, ip, port=22):
        """Check if SSH port is open on the host."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
            
    def check_kali_indicators(self, ip):
        """Check for indicators that suggest this is a Kali Linux system."""
        try:
            # Try to get SSH banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, 22))
            banner = sock.recv(1024).decode('utf-8').lower()
            sock.close()
            
            # Kali Linux SSH banners often contain "debian" or "kali"
            if 'debian' in banner or 'kali' in banner:
                return True
        except:
            pass
            
        return False
        
    def scan_ip(self, ip):
        """Scan a single IP for Kali Linux indicators."""
        if self.ping_host(ip):
            if self.check_ssh_port(ip):
                # Found a host with SSH open, check if it's Kali
                if self.check_kali_indicators(ip):
                    print(f"[+] Found Kali Linux VM at: {ip} (SSH with Kali banner)")
                    self.found_ips.append((ip, "Kali with SSH"))
                    return True
                else:
                    print(f"[+] Found host with SSH at: {ip} (manual verification needed)")
                    self.found_ips.append((ip, "SSH open"))
                    return True
        return False
        
    def scan_range(self, base_ip, start=1, end=254):
        """Scan a range of IP addresses."""
        print(f"[*] Scanning {base_ip}{start}-{end}...")
        
        # Create list of IPs to scan
        ips = [f"{base_ip}{i}" for i in range(start, end + 1)]
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            # Submit all tasks
            future_to_ip = {executor.submit(self.scan_ip, ip): ip for ip in ips}
            
            # Process completed tasks
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[-] Error scanning {ip}: {e}")
                    
    def scan_common_ranges(self):
        """Scan common VM IP ranges."""
        print("[*] Scanning common VM IP ranges...")
        
        # Common VM network ranges
        ranges = [
            ("192.168.1.", 1, 254),    # Typical home network
            ("10.0.2.", 1, 254),       # VirtualBox NAT
            ("172.16.0.", 1, 254),     # Private network
            ("192.168.56.", 1, 254),   # VirtualBox host-only
            ("172.18.0.", 1, 254),     # Your specified range
        ]
        
        for base_ip, start, end in ranges:
            self.scan_range(base_ip, start, end)
            
    def display_results(self):
        """Display the results of the scan."""
        print("\n" + "="*50)
        print("SCAN RESULTS")
        print("="*50)
        
        if self.found_ips:
            print("[+] Found potential Kali VMs:")
            for ip, info in self.found_ips:
                print(f"  - {ip} ({info})")
        else:
            print("[-] No Kali Linux VMs found in common IP ranges")
            print("\n[*] Troubleshooting tips:")
            print("  1. Ensure your Kali Linux VM is running")
            print("  2. Check VM network settings (Bridged/NAT/Host-only)")
            print("  3. Access VM console directly and run: ip addr show")
            print("  4. Look for active network interfaces with IP addresses")
            
    def run_discovery(self):
        """Run the complete discovery process."""
        print("Kali Linux VM Discovery Tool")
        print("=" * 40)
        print("This tool will scan common IP ranges for Kali Linux VMs")
        print("with SSH services running.")
        print()
        
        try:
            self.scan_common_ranges()
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        finally:
            self.display_results()


def main():
    detector = KaliVMDetector()
    detector.run_discovery()


if __name__ == "__main__":
    main()