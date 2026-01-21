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

# Pick a default system icon from Kali (like network icon)
SYSTEM_ICON="/usr/share/icons/hicolor/128x128/apps/network-workgroup.png"

# If system icon exists, use it
if [ -f "$SYSTEM_ICON" ]; then
    ICON_PATH="$SYSTEM_ICON"
else
    ICON_PATH=""
fi

# Create desktop entry
mkdir -p ~/.local/share/applications
cat << EOF > ~/.local/share/applications/mk-network-analyzer.desktop
[Desktop Entry]
Name=MK Network Analyzer
Comment=Network Sniffer by Mubeen Khan
Exec=$APP_DIR/dist/$BIN_NAME
Icon=$ICON_PATH
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
