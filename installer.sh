#!/bin/bash
set -e

echo "[+] Installing MK Network Analyzer..."

# Dependencies
sudo apt update
sudo apt install -y python3 python3-tk python3-scapy

# Install location
sudo mkdir -p /opt/mk-network-analyzer
sudo cp mk_network_analyzer_gui.py /opt/mk-network-analyzer/
sudo chmod +x /opt/mk-network-analyzer/mk_network_analyzer_gui.py

# Command shortcut
sudo ln -sf /opt/mk-network-analyzer/mk_network_analyzer_gui.py /usr/local/bin/mkanalyzer

# Desktop icon
cat <<EOF | sudo tee /usr/share/applications/mkanalyzer.desktop
[Desktop Entry]
Name=MK Network Analyzer
Exec=mkanalyzer
Icon=utilities-terminal
Type=Application
Categories=Network;Security;
Terminal=false
EOF

echo "[✓] Installation complete"
echo "Run using: mkanalyzer"
