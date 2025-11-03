#!/usr/bin/env python3
"""
Network Scanner Module for WiFi Penetration Tool

This module handles network discovery scanning using airodump-ng,
parses the CSV output, and provides interactive target selection.
"""

import subprocess
import csv
import os
import time
import signal
import sys
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
            interface (str): Wireless interface in monitor mode
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
        Start a network discovery scan using airodump-ng.
        
        Args:
            output_file (str): Base name for output files
            
        Returns:
            bool: True if scan started successfully, False otherwise
        """
        try:
            # Set up signal handler for graceful termination
            signal.signal(signal.SIGINT, self._signal_handler)
            
            # Run airodump-ng in the background
            self.scan_process = subprocess.Popen([
                'airodump-ng',
                '--output-format', 'csv',
                '-w', output_file,
                self.interface
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Let it run for a bit to collect data
            time.sleep(10)
            
            # Terminate the process
            self.scan_process.terminate()
            self.scan_process.wait()
            
            return True
        except Exception as e:
            print(f"Error during scan: {e}")
            return False

    def parse_csv_output(self, csv_file: str) -> List[NetworkTarget]:
        """
        Parse the CSV output from airodump-ng.
        
        Args:
            csv_file (str): Path to the CSV file
            
        Returns:
            List[NetworkTarget]: List of discovered network targets
        """
        targets = []
        
        try:
            with open(csv_file, 'r') as f:
                content = f.read()
                
            # Split the content into AP section and client section
            sections = content.split('\n\n')
            if len(sections) < 2:
                return targets
                
            ap_section = sections[0]
            
            # Parse the AP section
            lines = ap_section.strip().split('\n')
            if len(lines) < 2:
                return targets
                
            # Skip header lines
            for line in lines[2:]:
                if line.strip():
                    parts = [part.strip() for part in line.split(',')]
                    if len(parts) >= 14:
                        bssid = parts[0]
                        power = parts[3]
                        channel = parts[5]
                        encryption = parts[6] + parts[7] if len(parts) > 7 else parts[6]
                        essid = parts[13] if len(parts) > 13 else ""
                        
                        targets.append(NetworkTarget(
                            bssid=bssid,
                            essid=essid,
                            channel=channel,
                            encryption=encryption,
                            power=power,
                            clients=[]
                        ))
                        
            self.targets = targets
            return targets
        except Exception as e:
            print(f"Error parsing CSV: {e}")
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
        print(f"{'#':<3} {'BSSID':<17} {'Channel':<7} {'Power':<5} {'Encryption':<12} {'ESSID'}")
        print("-" * 80)
        
        for i, target in enumerate(targets, 1):
            print(f"{i:<3} {target.bssid:<17} {target.channel:<7} {target.power:<5} "
                  f"{target.encryption:<12} {target.essid}")

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
        print("Usage: python3 scanner.py <monitor_interface>")
        sys.exit(1)
        
    interface = sys.argv[1]
    scanner = NetworkScanner(interface)
    
    print("Starting network scan...")
    if scanner.start_scan("test_scan"):
        print("Scan completed. Parsing results...")
        targets = scanner.parse_csv_output("test_scan-01.csv")
        scanner.display_targets(targets)
    else:
        print("Scan failed.")


if __name__ == "__main__":
    main()