#!/bin/bash

echo "[*] Kali Linux Pentesting Dashboard Setup"
echo "[*] Ensuring system is up to date..."
sudo apt update

echo "[*] Installing required Kali tools (Aircrack-ng suite, Wash, Reaver)..."
sudo apt install -y aircrack-ng reaver pciutils python3-pip python3-tk

echo "[*] Installing Python dependencies..."
# We use --break-system-packages on Kali to force pip install, 
# or we can use apt for python3-customtkinter if available, but pip is standard.
sudo pip3 install customtkinter --break-system-packages

echo "[*] Setup Complete!"
echo "[*] Ensure your USB WiFi adapter is plugged in."
echo "[*] To run the dashboard: sudo python3 main.py"
