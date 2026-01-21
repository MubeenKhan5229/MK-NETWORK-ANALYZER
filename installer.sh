#!/bin/bash
# MK Network Analyzer One-Command Installer
# Author: Mubeen Khan

set -e

APP_NAME="MK Network Analyzer"
CMD_NAME="mkanalyzer"
INSTALL_DIR="/opt/mk-network-analyzer"
DESKTOP_FILE="/usr/share/applications/mk-network-analyzer.desktop"
ICON_NAME="utilities-network-monitor"

echo "[+] Installing MK Network Analyzer..."

# 1. Check root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run installer with sudo"
  exit 1
fi

# 2. Install dependencies
echo "[+] Installing dependencies..."
apt update
apt install -y python3 python3-tk python3-pip

pip3 install --break-system-packages scapy pyinstaller

# 3. Create install directory
echo "[+] Creating install directory..."
mkdir -p "$INSTALL_DIR"

# 4. Download main GUI file from GitHub
echo "[+] Downloading application..."
curl -fsSL \
https://raw.githubusercontent.com/MubeenKhan5229/MK-Network-Analyzer/main/mk_network_analyzer.py \
-o "$INSTALL_DIR/mk_network_analyzer.py"

# 5. Build executable
echo "[+] Building executable..."
pyinstaller --onefile --windowed \
"$INSTALL_DIR/mk_network_analyzer.py" \
--distpath "$INSTALL_DIR" \
--workpath /tmp/mk_build \
--specpath /tmp

# 6. Allow packet sniffing without sudo
echo "[+] Setting capabilities..."
setcap cap_net_raw,cap_net_admin=eip "$INSTALL_DIR/mk_network_analyzer"

# 7. Create global command
echo "[+] Creating command: mkanalyzer"
ln -sf "$INSTALL_DIR/mk_network_analyzer" /usr/local/bin/mkanalyzer

# 8. Create desktop entry (uses system icon)
echo "[+] Creating desktop icon..."
cat <<EOF > "$DESKTOP_FILE"
[Desktop Entry]
Name=MK Network Analyzer
Comment=Dark GUI Network Packet Analyzer
Exec=/usr/local/bin/mkanalyzer
Icon=$ICON_NAME
Terminal=false
Type=Application
Categories=Network;Security;
EOF

chmod +x "$DESKTOP_FILE"

echo
echo "[✔] Installation completed successfully!"
echo "[✔] Run from terminal: mkanalyzer"
echo "[✔] Or open from Applications → Network → MK Network Analyzer"
