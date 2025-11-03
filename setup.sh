#!/bin/bash
# WiFi Penetration Tool Setup Script
# This script helps install required dependencies on Kali Linux

echo "WiFi Penetration Tool Setup"
echo "=========================="
echo

# Check if running on Kali Linux
if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
    echo "Warning: This script is designed for Kali Linux."
    echo "Some commands may not work on other distributions."
    echo
fi

# Update package lists
echo "Updating package lists..."
sudo apt update
echo

# Install required tools
echo "Installing required tools..."
sudo apt install -y aircrack-ng iw macchanger tshark
echo

# Check if tools are installed
echo "Verifying installations..."
for tool in airodump-ng aireplay-ng aircrack-ng iw macchanger tshark; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool is installed"
    else
        echo "✗ $tool is not installed"
    fi
done
echo

# Check Python version
echo "Checking Python version..."
python3_version=$(python3 --version 2>&1)
if [[ $python3_version == *"Python 3."* ]]; then
    echo "✓ $python3_version"
else
    echo "✗ Python 3 not found"
fi
echo

echo "Setup complete!"
echo "You can now run the WiFi penetration tool with:"
echo "sudo python3 wifi_penetration_tool/main.py"