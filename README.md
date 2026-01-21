# MK-NETWORK-ANALYZER
# MK Network Analyzer

**MK Network Analyzer** is a Python-based dark GUI network sniffer for Kali Linux. It allows users to **capture and analyze packets (TCP/UDP/IP)** in real-time, with **start/stop controls**, desktop icon, and a **one-command installer**. Ideal for learning and professional cybersecurity analysis.

## Features
- Dark, professional GUI
- Columns: Source IP, Destination IP, Protocol, Source/Destination Ports
- Start / Stop packet capture
- Desktop icon & terminal command (`mkanalyzer`)
- Packet sniffing without sudo (via setcap)
- One-command installer for easy setup

## Installation
```bash
git clone https://github.com/YOUR-USERNAME/MK-Network-Analyzer.git
cd MK-Network-Analyzer
chmod +x installer.sh
./installer.sh
