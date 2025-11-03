#!/usr/bin/env python3
"""
Packet Sniffer Module for WiFi Penetration Tool

This module handles targeted packet capture for handshake grabbing
using airodump-ng and provides status logging.
"""

import subprocess
import time
import signal
import sys
import os
from typing import Optional
import threading


class HandshakeSniffer:
    """Captures WPA/WPA2 handshakes for targeted networks."""

    def __init__(self, interface: str):
        """
        Initialize the HandshakeSniffer.
        
        Args:
            interface (str): Wireless interface in monitor mode
        """
        self.interface = interface
        self.capture_process = None
        self.is_capturing = False
        self.output_file = ""
        self.handshake_detected = False

    def _signal_handler(self, sig, frame):
        """Handle interrupt signals."""
        self.stop_capture()
        sys.exit(0)

    def start_capture(self, bssid: str, channel: str, output_file: str = "handshake_capture") -> bool:
        """
        Start targeted packet capture on a specific BSSID/channel.
        
        Args:
            bssid (str): Target BSSID
            channel (str): Target channel
            output_file (str): Base name for capture files
            
        Returns:
            bool: True if capture started successfully, False otherwise
        """
        try:
            # Set up signal handler for graceful termination
            signal.signal(signal.SIGINT, self._signal_handler)
            
            self.output_file = output_file
            self.is_capturing = True
            self.handshake_detected = False
            
            # Run airodump-ng in targeted mode
            self.capture_process = subprocess.Popen([
                'airodump-ng',
                '--bssid', bssid,
                '--channel', channel,
                '--write', output_file,
                '--output-format', 'cap',
                self.interface
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            print(f"Started capturing on {bssid} (channel {channel})...")
            print(f"Output file: {output_file}-01.cap")
            print("Press Ctrl+C to stop capture")
            
            return True
        except Exception as e:
            print(f"Error starting capture: {e}")
            self.is_capturing = False
            return False

    def stop_capture(self) -> bool:
        """
        Stop the ongoing packet capture.
        
        Returns:
            bool: True if stopped successfully, False otherwise
        """
        if self.capture_process and self.capture_process.poll() is None:
            try:
                self.capture_process.terminate()
                self.capture_process.wait(timeout=5)
                self.is_capturing = False
                print("Capture stopped.")
                return True
            except subprocess.TimeoutExpired:
                self.capture_process.kill()
                self.capture_process.wait()
                self.is_capturing = False
                print("Capture forcefully stopped.")
                return True
        return False

    def check_handshake_status(self) -> bool:
        """
        Check if a handshake has been captured.
        
        Returns:
            bool: True if handshake detected, False otherwise
        """
        if not self.output_file:
            return False
            
        cap_file = f"{self.output_file}-01.cap"
        try:
            # Use aircrack-ng to check for handshake
            result = subprocess.run([
                'aircrack-ng', cap_file
            ], capture_output=True, text=True)
            
            # Check if handshake is present in output
            if "1 handshake" in result.stdout or "handshake" in result.stdout.lower():
                self.handshake_detected = True
                return True
            return False
        except Exception:
            return False

    def monitor_handshake(self, check_interval: int = 5) -> None:
        """
        Continuously monitor for handshake capture in a separate thread.
        
        Args:
            check_interval (int): Seconds between checks
        """
        def _monitor():
            while self.is_capturing:
                if self.check_handshake_status():
                    print("[+] Handshake captured!")
                    # We could stop capture here, but let's continue to get more frames
                time.sleep(check_interval)
                
        monitor_thread = threading.Thread(target=_monitor, daemon=True)
        monitor_thread.start()

    def get_capture_file(self) -> str:
        """
        Get the path to the capture file.
        
        Returns:
            str: Path to the capture file
        """
        return f"{self.output_file}-01.cap" if self.output_file else ""


def main():
    """Main function for testing the HandshakeSniffer."""
    if len(sys.argv) < 4:
        print("Usage: python3 sniffer.py <monitor_interface> <bssid> <channel>")
        sys.exit(1)
        
    interface = sys.argv[1]
    bssid = sys.argv[2]
    channel = sys.argv[3]
    
    sniffer = HandshakeSniffer(interface)
    
    if sniffer.start_capture(bssid, channel, "test_capture"):
        # Monitor for handshake in background
        sniffer.monitor_handshake()
        
        try:
            # Keep running until interrupted
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping capture...")
            sniffer.stop_capture()


if __name__ == "__main__":
    main()