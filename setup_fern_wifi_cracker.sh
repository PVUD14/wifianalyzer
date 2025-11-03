#!/bin/bash
# Setup script for fern-wifi-cracker on Kali Linux

echo "Setting up fern-wifi-cracker on Kali Linux..."
echo "=========================================="

# Update package list
echo "[*] Updating package list..."
sudo apt update

# Check if fern-wifi-cracker is already installed
if command -v fern-wifi-cracker &> /dev/null; then
    echo "[+] fern-wifi-cracker is already installed"
else
    echo "[*] Installing fern-wifi-cracker..."
    sudo apt install -y fern-wifi-cracker
fi

# Check if installation was successful
if command -v fern-wifi-cracker &> /dev/null; then
    echo "[+] fern-wifi-cracker installed successfully"
else
    echo "[-] Failed to install fern-wifi-cracker"
    echo "[*] Trying alternative installation method..."
    
    # Try installing from GitHub
    echo "[*] Cloning fern-wifi-cracker from GitHub..."
    cd /tmp
    git clone https://github.com/savio-code/fern-wifi-cracker.git
    cd fern-wifi-cracker
    
    # Install dependencies
    echo "[*] Installing dependencies..."
    sudo apt install -y python3-pyqt5 python3-dev python3-pip
    pip3 install pycrypto
    
    # Try to run the installer
    echo "[*] Running installer..."
    sudo python3 installer.py
    
    # Check again
    if command -v fern-wifi-cracker &> /dev/null; then
        echo "[+] fern-wifi-cracker installed successfully"
    else
        echo "[-] Installation failed"
        exit 1
    fi
fi

# Verify required tools are installed
echo "[*] Verifying required tools..."
REQUIRED_TOOLS=("aircrack-ng" "airodump-ng" "aireplay-ng" "iw" "macchanger")
for tool in "${REQUIRED_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "[+] $tool is installed"
    else
        echo "[-] $tool is not installed, installing..."
        sudo apt install -y aircrack-ng iw macchanger
    fi
done

echo "[*] Setup complete!"
echo "[*] You can now run fern-wifi-cracker with:"
echo "    sudo fern-wifi-cracker"