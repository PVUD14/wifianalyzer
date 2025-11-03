<<<<<<< HEAD
# WiFi Penetration Testing Tool

A modular Python-based penetration testing utility targeting IEEE 802.11 networks. The tool performs passive/active handshake grabbing followed by offline dictionary-based WPA/WPA2 PSK cracking while maintaining connectivity through an alternate NIC.

## Features

- **Interface Management**: Detects wireless interfaces and enables/disables monitor mode
- **Network Scanning**: Performs discovery scans and parses results for target selection
- **Handshake Capture**: Targets specific networks for packet capture
- **Client Deauthentication**: Sends directed or broadcast deauthentication packets
- **Password Cracking**: Offline dictionary-based WPA/WPA2 PSK cracking
- **Graceful Cleanup**: Handles interrupts and restores original interface state

## Prerequisites

- Kali Linux (or similar penetration testing distribution)
- Python 3.8+
- aircrack-ng suite (airodump-ng, aireplay-ng, aircrack-ng)
- iw, macchanger, tshark

Install required tools on Kali Linux:
```bash
sudo apt update
sudo apt install aircrack-ng iw macchanger tshark
```

## Installation

Clone the repository:
```bash
git clone <repository-url>
cd wifi_penetration_tool
```

## Usage

Run the tool with:
```bash
sudo python3 wifi_penetration_tool/main.py [OPTIONS]
```

### Command Line Options

- `-i, --interface`: Monitor-mode enabled NIC (default: auto-detect)
- `-t, --target-bssid`: Skip scanner phase (optional fast entry)
- `-c, --channel`: Skip scanner-phase (required with --target-bssid)
- `-d, --dictionary`: Set custom wordlist path (default: rockyou.txt)
- `-o, --output-filename`: Base name for cap/dump/log storage

### Examples

1. **Auto-detect interface and scan for targets:**
   ```bash
   sudo python3 wifi_penetration_tool/main.py
   ```

2. **Use specific interface:**
   ```bash
   sudo python3 wifi_penetration_tool/main.py -i wlan1
   ```

3. **Target specific network (skip scanning):**
   ```bash
   sudo python3 wifi_penetration_tool/main.py -t 00:11:22:33:44:55 -c 6
   ```

4. **Use custom wordlist:**
   ```bash
   sudo python3 wifi_penetration_tool/main.py -d /path/to/wordlist.txt
   ```

## Module Structure

- `interface_manager.py`: Handles wireless interface detection and monitor mode
- `scanner.py`: Performs network discovery scans and target selection
- `sniffer.py`: Captures handshakes on targeted networks
- `deauther.py`: Sends deauthentication packets to clients
- `cracker.py`: Performs offline dictionary-based password cracking
- `main.py`: Orchestrates all modules and provides CLI interface

## Testing Setup

To test this tool manually inside Kali Linux/VirtualBox with two ALFA-compatible NICs:

### Hardware Setup

1. **Primary NIC** (e.g., ALFA AWUS036ACS): Used for monitoring and attacks
2. **Secondary NIC** (e.g., ALFA AWUS036ACM): Maintains internet connectivity

### VirtualBox Configuration

1. Connect both USB wireless adapters to the VM:
   - Machine → Settings → USB → Add both devices
   - Ensure USB 3.0 controller is enabled

2. Verify device recognition:
   ```bash
   lsusb
   iw dev
   ```

### Testing Procedure

1. **Verify interface detection:**
   ```bash
   sudo python3 wifi_penetration_tool/interface_manager.py
   ```

2. **Run a complete penetration test:**
   ```bash
   sudo python3 wifi_penetration_tool/main.py -i wlan1
   ```

3. **Manual testing of individual modules:**
   ```bash
   # Test scanner
   sudo python3 wifi_penetration_tool/scanner.py wlan1
   
   # Test sniffer (replace with actual BSSID and channel)
   sudo python3 wifi_penetration_tool/sniffer.py wlan1 00:11:22:33:44:55 6
   
   # Test deauther (replace with actual BSSID)
   sudo python3 wifi_penetration_tool/deauther.py wlan1 00:11:22:33:44:55
   
   # Test cracker (replace with actual capture file and wordlist)
   sudo python3 wifi_penetration_tool/cracker.py capture.cap wordlist.txt
   ```

## Security Notes

- This tool is for educational and authorized penetration testing purposes only
- Only use on networks you own or have explicit permission to test
- Be aware of legal implications in your jurisdiction
- Use responsibly and ethically

## Future Enhancements

- Captive Portal phishing integration
- Advanced MITM hooks
- Hashcat export functionality
- Web-based GUI interface
- Additional attack vectors (WEP, WPS, etc.)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
=======
# wifianalyzer
>>>>>>> ec0ba782094c10a3153e8d0bf65511b32cea47c6
