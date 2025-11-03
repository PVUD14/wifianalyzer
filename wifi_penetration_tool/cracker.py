#!/usr/bin/env python3
"""
Password Cracking Module for WiFi Penetration Tool

This module handles offline dictionary-based WPA/WPA2 PSK cracking
using aircrack-ng and provides results parsing.
"""

import subprocess
import re
import sys
from typing import Optional, Tuple
from dataclasses import dataclass


@dataclass
class CrackResult:
    """Represents the result of a password cracking attempt."""
    success: bool
    password: Optional[str] = None
    key_found: bool = False
    keys_tested: int = 0


class PasswordCracker:
    """Performs offline dictionary-based WPA/WPA2 PSK cracking."""

    def __init__(self):
        """Initialize the PasswordCracker."""
        self.crack_process = None

    def crack_handshake(self, capture_file: str, wordlist: str) -> CrackResult:
        """
        Attempt to crack a captured handshake using a wordlist.
        
        Args:
            capture_file (str): Path to the .cap file with handshake
            wordlist (str): Path to the dictionary wordlist file
            
        Returns:
            CrackResult: Result of the cracking attempt
        """
        try:
            # Run aircrack-ng with wordlist
            result = subprocess.run([
                'aircrack-ng',
                '-w', wordlist,
                capture_file
            ], capture_output=True, text=True, timeout=3600)  # 1 hour timeout
            
            return self._parse_crack_output(result.stdout)
        except subprocess.TimeoutExpired:
            return CrackResult(success=False, password=None, key_found=False)
        except Exception as e:
            print(f"Error during cracking: {e}")
            return CrackResult(success=False, password=None, key_found=False)

    def _parse_crack_output(self, output: str) -> CrackResult:
        """
        Parse the output from aircrack-ng to determine cracking results.
        
        Args:
            output (str): Output from aircrack-ng command
            
        Returns:
            CrackResult: Parsed cracking result
        """
        result = CrackResult(success=False, password=None, key_found=False)
        
        # Check if key was found
        if "KEY FOUND" in output:
            result.key_found = True
            result.success = True
            
            # Extract the password
            key_pattern = r"KEY FOUND! \[ ([^\]]+) \]"
            match = re.search(key_pattern, output)
            if match:
                result.password = match.group(1)
                
        # Extract number of keys tested
        keys_pattern = r"(\d+) keys tested"
        match = re.search(keys_pattern, output)
        if match:
            result.keys_tested = int(match.group(1))
            
        return result

    def check_handshake_quality(self, capture_file: str) -> Tuple[bool, str]:
        """
        Check if a capture file contains a valid handshake.
        
        Args:
            capture_file (str): Path to the .cap file
            
        Returns:
            Tuple[bool, str]: (has_handshake, quality_info)
        """
        try:
            result = subprocess.run([
                'aircrack-ng', capture_file
            ], capture_output=True, text=True)
            
            output = result.stdout
            
            if "1 handshake" in output:
                return True, "Good quality handshake captured"
            elif "handshake" in output.lower():
                return True, "Handshake present but quality may vary"
            else:
                return False, "No handshake found in capture file"
        except Exception as e:
            return False, f"Error checking handshake: {e}"

    def get_network_info(self, capture_file: str) -> dict:
        """
        Extract network information from a capture file.
        
        Args:
            capture_file (str): Path to the .cap file
            
        Returns:
            dict: Network information (ESSID, BSSID, etc.)
        """
        info = {}
        try:
            result = subprocess.run([
                'aircrack-ng', capture_file
            ], capture_output=True, text=True)
            
            output = result.stdout
            
            # Extract ESSID
            essid_pattern = r"ESSID \(length: \d+\) *: *(.+)"
            match = re.search(essid_pattern, output)
            if match:
                info['essid'] = match.group(1).strip()
                
            # Extract BSSID
            bssid_pattern = r"BSSID:([0-9A-F:]+)"
            match = re.search(bssid_pattern, output)
            if match:
                info['bssid'] = match.group(1)
                
        except Exception as e:
            print(f"Error extracting network info: {e}")
            
        return info


def main():
    """Main function for testing the PasswordCracker."""
    if len(sys.argv) < 3:
        print("Usage: python3 cracker.py <capture_file.cap> <wordlist.txt>")
        sys.exit(1)
        
    capture_file = sys.argv[1]
    wordlist = sys.argv[2]
    
    cracker = PasswordCracker()
    
    print(f"Checking handshake in {capture_file}...")
    has_handshake, quality = cracker.check_handshake_quality(capture_file)
    print(f"Handshake status: {quality}")
    
    if not has_handshake:
        print("No valid handshake found. Cannot proceed with cracking.")
        return
        
    print(f"Attempting to crack with wordlist: {wordlist}")
    result = cracker.crack_handshake(capture_file, wordlist)
    
    if result.success:
        print(f"[+] SUCCESS! Password found: {result.password}")
    else:
        print("[-] Password not found in wordlist")
        
    print(f"Keys tested: {result.keys_tested}")


if __name__ == "__main__":
    main()