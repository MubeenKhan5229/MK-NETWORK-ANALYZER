#!/bin/bash
set -e

APP_DIR="$(pwd)"
BIN_NAME="mk_network_analyzer"

echo "[+] Installing MK Network Analyzer..."

# Install dependencies
sudo apt update
sudo apt install -y python3 python3-venv python3-tk scapy git imagemagick

# Virtual environment
python3 -m venv venv
source venv/bin/activate

# Python packages
pip install --upgrade pip
pip install pyinstaller scapy

# Build executable GUI
pyinstaller --onefile --windowed "$APP_DIR/mk_network_analyzer.py"

# Give network permissions (like Wireshark)
sudo setcap cap_net_raw,cap_net_admin=eip "$APP_DIR/dist/$BIN_NAME"

# Copy icon
mkdir -p ~/.local/share/icons
cp "$APP_DIR/icon.png" ~/.local/share/icons/mk-network-analyzer.png

# Create desktop entry
mkdir -p ~/.local/share/applications
cat << EOF > ~/.local/share/applications/mk-network-analyzer.desktop
[Desktop Entry]
Name=MK Network Analyzer
Comment=Network Sniffer by Mubeen Khan
Exec=$APP_DIR/dist/$BIN_NAME
Icon=$HOME/.local/share/icons/mk-network-analyzer.png
Terminal=false
Type=Application
Categories=Utility;Network;
EOF

chmod +x ~/.local/share/applications/mk-network-analyzer.desktop

# Terminal alias
echo 'alias mkanalyzer="$APP_DIR/dist/$BIN_NAME"' >> ~/.zshrc 2>/dev/null || echo 'alias mkanalyzer="$APP_DIR/dist/$BIN_NAME"' >> ~/.bashrc

echo
echo "✅ Installation complete!"
echo "▶ Run from terminal: mkanalyzer"
echo "▶ Or search MK Network Analyzer in Applications"
