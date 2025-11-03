#!/usr/bin/env python3
"""
Network Scanner Module for WiFi Penetration Tool (Windows Version)

This module handles network discovery scanning using Windows-native tools
and provides interactive target selection.
"""

import subprocess
import os
import time
import signal
import sys
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class NetworkTarget:
    """Represents a discovered network target."""
    bssid: str
    essid: str
    channel: str
    encryption: str
    power: str
    clients: List[str]


class NetworkScanner:
    """Performs network discovery scans and manages targets."""

    def __init__(self, interface: str):
        """
        Initialize the NetworkScanner.
        
        Args:
            interface (str): Wireless interface name
        """
        self.interface = interface
        self.targets = []
        self.scan_process = None

    def _signal_handler(self, sig, frame):
        """Handle interrupt signals."""
        if self.scan_process:
            self.scan_process.terminate()
            self.scan_process.wait()
        sys.exit(0)

    def start_scan(self, output_file: str = "scan_output") -> bool:
        """
        Start a network discovery scan using Windows netsh.
        
        Args:
            output_file (str): Base name for output files (not used in Windows version)
            
        Returns:
            bool: True if scan started successfully, False otherwise
        """
        try:
            # Set up signal handler for graceful termination
            # signal.signal(signal.SIGINT, self._signal_handler)
            
            print("[*] Scanning for wireless networks...")
            print("[*] This may take a few seconds...")
            
            # Use netsh to scan for networks
            result = subprocess.run([
                'netsh', 'wlan', 'show', 'networks', 'mode=Bssid'
            ], capture_output=True, text=True, check=True)
            
            # Save output to file for parsing
            with open(f"{output_file}.txt", 'w') as f:
                f.write(result.stdout)
            
            return True
        except Exception as e:
            print(f"Error during scan: {e}")
            return False

    def parse_scan_output(self, scan_file: str) -> List[NetworkTarget]:
        """
        Parse the scan output from netsh.
        
        Args:
            scan_file (str): Path to the scan output file
            
        Returns:
            List[NetworkTarget]: List of discovered network targets
        """
        targets = []
        
        try:
            with open(scan_file, 'r') as f:
                content = f.read()
                
            # Parse the netsh output
            # This is a simplified parser for Windows netsh wlan show networks output
            lines = content.split('\n')
            
            current_ssid = ""
            current_bssid = ""
            current_channel = ""
            current_signal = ""
            current_auth = ""
            
            for line in lines:
                line = line.strip()
                
                if line.startswith("SSID"):
                    # Extract SSID
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        current_ssid = parts[1].strip()
                        
                elif line.startswith("BSSID") and not line.startswith("BSSID 1"):
                    # Extract BSSID
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        current_bssid = parts[1].strip()
                        
                elif line.startswith("Signal"):
                    # Extract signal strength
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        current_signal = parts[1].strip().replace('%', '')
                        
                elif line.startswith("Channel"):
                    # Extract channel
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        current_channel = parts[1].strip()
                        
                elif line.startswith("Authentication"):
                    # Extract authentication type
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        current_auth = parts[1].strip()
                        
                        # If we have all the information, create a target
                        if current_ssid and current_bssid and current_channel:
                            targets.append(NetworkTarget(
                                bssid=current_bssid,
                                essid=current_ssid,
                                channel=current_channel,
                                encryption=current_auth,
                                power=current_signal,
                                clients=[]
                            ))
                            
                            # Reset for next network
                            current_bssid = ""
                            current_signal = ""
                            current_auth = ""
                            
            self.targets = targets
            return targets
        except Exception as e:
            print(f"Error parsing scan output: {e}")
            return targets

    def display_targets(self, targets: List[NetworkTarget]) -> None:
        """
        Display discovered targets in a formatted table.
        
        Args:
            targets (List[NetworkTarget]): List of targets to display
        """
        if not targets:
            print("No targets found.")
            return
            
        print("\nDiscovered Networks:")
        print("-" * 80)
        print(f"{'#':<3} {'BSSID':<17} {'Channel':<7} {'Signal':<6} {'Encryption':<15} {'ESSID'}")
        print("-" * 80)
        
        for i, target in enumerate(targets, 1):
            print(f"{i:<3} {target.bssid:<17} {target.channel:<7} {target.power:<6} "
                  f"{target.encryption:<15} {target.essid}")

    def select_target_interactively(self, targets: List[NetworkTarget]) -> Optional[NetworkTarget]:
        """
        Allow user to interactively select a target.
        
        Args:
            targets (List[NetworkTarget]): List of available targets
            
        Returns:
            Optional[NetworkTarget]: Selected target or None if cancelled
        """
        if not targets:
            return None
            
        self.display_targets(targets)
        
        while True:
            try:
                choice = input(f"\nSelect target (1-{len(targets)}) or 'q' to quit: ").strip()
                if choice.lower() == 'q':
                    return None
                    
                index = int(choice) - 1
                if 0 <= index < len(targets):
                    return targets[index]
                else:
                    print("Invalid selection. Please try again.")
            except ValueError:
                print("Invalid input. Please enter a number.")
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                return None

    def get_target_by_bssid(self, bssid: str) -> Optional[NetworkTarget]:
        """
        Find a target by its BSSID.
        
        Args:
            bssid (str): BSSID to search for
            
        Returns:
            Optional[NetworkTarget]: Found target or None
        """
        for target in self.targets:
            if target.bssid.lower() == bssid.lower():
                return target
        return None


def main():
    """Main function for testing the NetworkScanner."""
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <interface_name>")
        sys.exit(1)
        
    interface = sys.argv[1]
    scanner = NetworkScanner(interface)
    
    print("Starting network scan...")
    if scanner.start_scan("test_scan"):
        print("Scan completed. Parsing results...")
        targets = scanner.parse_scan_output("test_scan.txt")
        scanner.display_targets(targets)
    else:
        print("Scan failed.")


if __name__ == "__main__":
    main()