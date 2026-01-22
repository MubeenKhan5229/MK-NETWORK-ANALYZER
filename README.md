# MK Network Analyzer

MK Network Analyzer is a professional dark-themed GUI network sniffer for Kali Linux.  
It captures and displays TCP, UDP, and IP packets in real time using a clean and modern interface.

## Features
- Dark professional GUI
- Real-time packet sniffing
- Source IP, Destination IP, Protocol, Ports
- Start / Stop / Clear / Exit buttons
- Desktop icon support
- One-command installation
- Command: `python3 network_detector.py`

## Usage
mkanalyzer

## Requirements

Kali Linux

Python 3

Scapy

Tkinter

## Author:  Mubeen Khan
Cybersecurity & Network Analysis Tool

## Disclaimer

This tool is for educational and ethical use only.
# Network Detector by Mubeen Khan

Professional GUI-based Network Sniffer  
Dark Theme | Kali Linux | Python

## STEP 1:  Install 
```bash
cat <<'EOF' > network_detector.py && python3 network_detector.py
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

sniffing = False

# ---------------- Packet Handler ----------------
def packet_handler(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = "OTHER"

        size = len(packet)
        tree.insert("", "end", values=(src, dst, proto, size))
        tree.yview_moveto(1)

# ---------------- Sniffer ----------------
def start_sniff():
    global sniffing
    sniffing = True
    sniff(prn=packet_handler, store=False,
          stop_filter=lambda x: not sniffing)

def start():
    threading.Thread(target=start_sniff, daemon=True).start()
    status.config(text="Status: RUNNING", fg="#00ff99")

def stop():
    global sniffing
    sniffing = False
    status.config(text="Status: STOPPED", fg="#ff5555")

def show_license():
    messagebox.showinfo(
        "License",
        "NETWORK DETECTOR by Mubeen Khan\n\n"
        "This tool is for educational purpose & for defensive use only.\n"
        "Unauthorized network monitoring is illegal (DEVEPLOPER IS NOT RESPONSIBLE).\n\n"
        "© 2026 Mubeen Khan"
    )

# ---------------- GUI ----------------
root = tk.Tk()
root.title("NETWORK DETECTOR by Mubeen Khan")
root.geometry("900x520")
root.configure(bg="#121212")

style = ttk.Style()
style.theme_use("default")
style.configure("Treeview",
    background="#1e1e1e",
    foreground="white",
    fieldbackground="#1e1e1e",
    rowheight=26
)
style.configure("Treeview.Heading",
    background="#333333",
    foreground="white",
    font=("Segoe UI", 10, "bold")
)

title = tk.Label(
    root,
    text="Network Detector by Mubeen Khan",
    bg="#121212",
    fg="#00e6e6",
    font=("Segoe UI", 18, "bold")
)
title.pack(pady=10)

status = tk.Label(
    root,
    text="Status: IDLE",
    bg="#121212",
    fg="#ffaa00",
    font=("Segoe UI", 10)
)
status.pack()

columns = ("SOURCE IP", "DESTINATION IP", "PROTOCOL RUNNING", "PACKET SIZE")
tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=210)
tree.pack(expand=True, fill="both", padx=12, pady=12)

btns = tk.Frame(root, bg="#121212")
btns.pack(pady=10)

tk.Button(btns, text="START", width=14, bg="#007acc", fg="white",
          font=("Segoe UI", 11, "bold"), command=start).grid(row=0, column=0, padx=8)

tk.Button(btns, text="STOP", width=14, bg="#cc0000", fg="white",
          font=("Segoe UI", 11, "bold"), command=stop).grid(row=0, column=1, padx=8)

tk.Button(btns, text="LICENSE", width=14, bg="#444444", fg="white",
          font=("Segoe UI", 11), command=show_license).grid(row=0, column=2, padx=8)

tk.Button(btns, text="EXIT", width=14, bg="#222222", fg="white",
          font=("Segoe UI", 11), command=root.destroy).grid(row=0, column=3, padx=8)

footer = tk.Label(
    root,
    text="THIS DETECTOR IS FOR EDUCATIONAL PURPOSE ONLY, DON'T RUN ON ANY UNAUTHORIZED AND GOVT NETWORKS",
    bg="#121212",
    fg="#666666",
    font=("Segoe UI", 9)
)
footer.pack(pady=5)

root.mainloop()
EOF

