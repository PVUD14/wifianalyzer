# WiFi Penetration Testing Tool for Windows

A Windows-compatible version of the modular Python-based penetration testing utility targeting IEEE 802.11 networks. This tool performs passive/active handshake grabbing followed by offline dictionary-based WPA/WPA2 PSK cracking.

## Features

- **Interface Management**: Detects wireless interfaces on Windows
- **Network Scanning**: Performs discovery scans using Windows-native tools
- **Handshake Capture**: Simulated packet capture for demonstration
- **Client Deauthentication**: Simulated deauthentication attacks
- **Password Cracking**: Offline dictionary-based WPA/WPA2 PSK cracking
- **Graceful Cleanup**: Handles interrupts and restores original state

## Prerequisites

- Windows 7/8/10/11
- Python 3.8+
- Administrator privileges for full functionality

## Optional Tools for Full Functionality

- **aircrack-ng for Windows**: For actual packet capture and password cracking
- **Npcap**: For packet capture capabilities
- **Wireshark**: For advanced packet analysis

## Installation

1. Ensure Python 3.8+ is installed on your system
2. Run the setup script:
   ```cmd
   setup_windows.bat
   ```

## Usage

Run the tool with:
```cmd
wifi_tool_windows.bat [OPTIONS]
```

Or directly with Python:
```cmd
python wifi_penetration_tool_windows\main.py [OPTIONS]
```

### Command Line Options

- `-i, --interface`: Wireless interface name (default: auto-detect)
- `-t, --target-bssid`: Skip scanner phase (optional fast entry)
- `-c, --channel`: Skip scanner-phase (required with --target-bssid)
- `-d, --dictionary`: Set custom wordlist path (default: C:\Users\Public\wordlist.txt)
- `-o, --output-filename`: Base name for cap/dump/log storage

### Examples

1. **Auto-detect interface and scan for targets:**
   ```cmd
   wifi_tool_windows.bat
   ```

2. **Use specific interface:**
   ```cmd
   wifi_tool_windows.bat -i "Wi-Fi"
   ```

3. **Target specific network (skip scanning):**
   ```cmd
   wifi_tool_windows.bat -t 00:11:22:33:44:55 -c 6
   ```

4. **Use custom wordlist:**
   ```cmd
   wifi_tool_windows.bat -d C:\path\to\wordlist.txt
   ```

## Module Structure

- `interface_manager.py`: Handles wireless interface detection
- `scanner.py`: Performs network discovery scans
- `sniffer.py`: Simulates packet capture
- `deauther.py`: Simulates deauthentication attacks
- `cracker.py`: Performs offline dictionary-based password cracking
- `main.py`: Orchestrates all modules and provides CLI interface

## Important Notes for Windows

1. **Administrator Privileges**: The tool must be run as administrator for full functionality
2. **Limited Native Support**: Windows has limited native support for monitor mode and packet injection
3. **Simulation Mode**: Many functions are simulated for demonstration purposes
4. **Special Tools Required**: For actual penetration testing, additional tools like aircrack-ng for Windows and Npcap are required

## Testing Setup

To test this tool on Windows:

1. **Run as Administrator**: Right-click on `wifi_tool_windows.bat` and select "Run as administrator"
2. **Verify Interface Detection**: The tool will automatically detect wireless interfaces
3. **Run a Complete Test**: Execute the tool with no arguments to run through the full workflow

## Legal and Ethical Usage

- This tool is for educational and authorized security testing purposes only
- Only use on networks you own or have explicit permission to test
- Be aware of and comply with all applicable laws and regulations
- Use responsibly and ethically

## Limitations on Windows

Compared to the Linux version, the Windows version has several limitations:

1. **No Native Monitor Mode**: Windows does not support native monitor mode without special drivers
2. **Limited Packet Injection**: Packet injection capabilities are limited without additional tools
3. **Simulation**: Many functions are simulated rather than actually performing network operations
4. **Performance**: Performance may be reduced compared to Linux implementations

## Future Enhancements

To improve the Windows version, consider:

1. **Integration with Specialized Tools**: Better integration with aircrack-ng for Windows
2. **Driver Support**: Support for specialized wireless adapters with monitor mode
3. **Enhanced Simulation**: More realistic simulation of network operations
4. **GUI Interface**: Development of a graphical user interface

## Troubleshooting

### Common Issues

1. **"Access Denied" Errors**: Run the tool as administrator
2. **Interface Not Detected**: Ensure wireless adapter is properly installed
3. **Tool Not Found**: Install required tools like aircrack-ng for Windows

### Getting Help

If you encounter issues:

1. Check that you're running as administrator
2. Verify all prerequisites are installed
3. Check the console output for specific error messages
4. Consult the documentation for required tools

## License

This project is licensed under the MIT License - see the LICENSE file for details.