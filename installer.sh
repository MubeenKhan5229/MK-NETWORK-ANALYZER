#!/bin/bash
# MK Network Analyzer Installer - One Command Install

echo "[*] Installing MK Network Analyzer..."

# Create install directory
sudo mkdir -p /opt/mk-network-analyzer

# Copy Python GUI file
sudo cp mk_network_analyzer_gui.py /opt/mk-network-analyzer/

# Make sure python file is executable
sudo chmod +x /opt/mk-network-analyzer/mk_network_analyzer_gui.py

# Remove old launcher if exists
sudo rm -f /usr/local/bin/mkanalyzer

# Create new launcher
echo -e "#!/bin/bash\nexec python3 /opt/mk-network-analyzer/mk_network_analyzer_gui.py" | sudo tee /usr/local/bin/mkanalyzer
sudo chmod +x /usr/local/bin/mkanalyzer

# Give sniffing permissions to python3 (no sudo needed later)
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

# Create desktop icon
cat <<EOF | sudo tee /usr/share/applications/mk-network-analyzer.desktop
[Desktop Entry]
Name=MK Network Analyzer
Comment=Dark GUI Network Sniffer
Exec=/usr/local/bin/mkanalyzer
Icon=network-workgroup
Terminal=false
Type=Application
Categories=Utility;Network;
EOF

echo "[*] Installation complete!"
echo "You can now run the tool with the command: mkanalyzer"
