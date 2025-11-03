# WiFi Penetration Testing Tool - Project Summary

## Overview
This project implements a modular Python-based penetration testing utility targeting IEEE 802.11 networks. The tool performs passive/active handshake grabbing followed by offline dictionary-based WPA/WPA2 PSK cracking while maintaining connectivity through an alternate NIC.

## Implementation Status
✅ All requested modules have been implemented
✅ Clean, modular codebase using standard libraries
✅ Multi-interface support with monitor mode management
✅ Graceful handling of interrupts and cleanup
✅ Command-line interface with argparse
✅ Comprehensive documentation

## Modules Created

### 1. Interface Manager (`interface_manager.py`)
- Detects wireless interfaces
- Enables/disables monitor mode via `ip` and `iw`
- Manages MAC address changes
- Restores original state after exit

### 2. Network Scanner (`scanner.py`)
- Performs discovery scan using `airodump-ng`
- Parses CSV output for ESSIDs, BSSIDs, channels, encryption types
- Interactive selection of targets

### 3. Packet Sniffer (`sniffer.py`)
- Starts targeted CAP capturing on specific channel/BSSID
- Monitors handshake detection status
- Logs capture progress

### 4. Deauthenticator (`deauther.py`)
- Sends directed or broadcast deauthentication packets using `aireplay-ng`
- Continuous deauthentication attacks
- Client discovery capabilities

### 5. Password Cracker (`cracker.py`)
- Loads .cap dump files
- Launches `aircrack-ng` with wordlists
- Parses cracking results
- Shows success/failure with recovered credentials

### 6. Main Controller (`main.py`)
- Glues all modules together
- Implements CLI with argparse
- Manages workflow: scan → capture → deauth → crack
- Error-safe execution patterns

## Additional Files Created

### Documentation & Support Files
- `README.md`: Comprehensive usage documentation
- `LICENSE`: MIT license file
- `requirements.txt`: Dependency list
- `config_template.ini`: Configuration file template
- `architecture.md`: System architecture diagram

### Test & Example Files
- `test_wordlist.txt`: Sample wordlist for testing
- `test_modules.py`: Module testing script

### Launcher Scripts
- `wifi_tool.bat`: Windows batch launcher
- `wifi_tool.sh`: Linux shell launcher
- `setup.sh`: Dependency installation script

## Key Features Implemented

### Environment Validation
- Root privilege checking
- Tool presence verification (`airodump-ng`, `aireplay-ng`, etc.)
- Interface detection and validation

### Error Handling
- Graceful interrupt handling (Ctrl+C)
- Process cleanup on exit
- Exception handling throughout modules

### Modularity
- Separate files for each functional component
- Clear interfaces between modules
- Reusable components

### User Experience
- Interactive target selection
- Progress monitoring
- Clear status messages
- Command-line argument support

## Testing Setup Instructions

The tool can be tested manually inside Kali Linux/VirtualBox with two ALFA-compatible NICs:

1. Connect both USB wireless adapters to the VM
2. Run the setup script: `./setup.sh`
3. Execute the tool: `sudo python3 wifi_penetration_tool/main.py`

## Future Enhancement Opportunities

1. **Advanced Attacks**: Implement additional attack vectors (WEP, WPS, etc.)
2. **GUI Interface**: Add web-based or desktop GUI
3. **Export Features**: Add hashcat export functionality
4. **Captive Portal**: Integrate phishing capabilities
5. **MITM Hooks**: Add advanced man-in-the-middle capabilities

## Compliance & Ethics Notice

This tool is designed for:
- Educational purposes
- Authorized penetration testing
- Security research

⚠️ **Only use on networks you own or have explicit permission to test**
⚠️ **Comply with all applicable laws and regulations**
⚠️ **Use responsibly and ethically**

## Technical Requirements

- **OS**: Kali Linux (recommended) or similar penetration testing distribution
- **Python**: Version 3.8+
- **Tools**: aircrack-ng suite, iw, macchanger, tshark
- **Hardware**: Minimum two wireless network interfaces

## Usage Examples

```bash
# Auto-detect interface and scan for targets
sudo python3 wifi_penetration_tool/main.py

# Use specific interface
sudo python3 wifi_penetration_tool/main.py -i wlan1

# Target specific network (skip scanning)
sudo python3 wifi_penetration_tool/main.py -t 00:11:22:33:44:55 -c 6

# Use custom wordlist
sudo python3 wifi_penetration_tool/main.py -d /path/to/wordlist.txt
```