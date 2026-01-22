#!/usr/bin/env python3
"""
MK Network Analyzer
Professional Dark GUI Network Sniffer
Author: Mubeen Khan
"""

import threading
from scapy.all import sniff, IP, TCP, UDP
import tkinter as tk
from tkinter import ttk

sniffing = False
sniffer_thread = None

# ---------- Packet Handler ----------
def process_packet(packet):
    if not sniffing:
        return

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "IP"

        sport = "-"
        dport = "-"

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        table.insert("", "end", values=(src, dst, proto, sport, dport))

# ---------- Sniff Control ----------
def start_sniff():
    global sniffing, sniffer_thread
    if sniffing:
        return
    sniffing = True
    status_label.config(text="Status: Running", foreground="#00ff99")
    sniffer_thread = threading.Thread(target=lambda: sniff(prn=process_packet, store=False))
    sniffer_thread.daemon = True
    sniffer_thread.start()

def stop_sniff():
    global sniffing
    sniffing = False
    status_label.config(text="Status: Stopped", foreground="orange")

def clear_table():
    for row in table.get_children():
        table.delete(row)

def exit_app():
    stop_sniff()
    root.destroy()

# ---------- GUI ----------
root = tk.Tk()
root.title("MK Network Analyzer")
root.geometry("900x500")
root.configure(bg="#1e1e1e")

style = ttk.Style()
style.theme_use("default")

style.configure(
    "Treeview",
    background="#252526",
    foreground="white",
    rowheight=25,
    fieldbackground="#252526",
    bordercolor="#3c3c3c",
    borderwidth=0
)

style.configure(
    "Treeview.Heading",
    background="#333333",
    foreground="white"
)

# ---------- Table ----------
columns = ("Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port")
table = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    table.heading(col, text=col)
    table.column(col, anchor="center")

table.pack(fill="both", expand=True, padx=10, pady=10)

# ---------- Buttons ----------
btn_frame = tk.Frame(root, bg="#1e1e1e")
btn_frame.pack(pady=5)

btn_style = {
    "font": ("Segoe UI", 10),
    "bg": "#007acc",
    "fg": "white",
    "activebackground": "#005f99",
    "width": 12
}

tk.Button(btn_frame, text="Start", command=start_sniff, **btn_style).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Stop", command=stop_sniff, **btn_style).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="Clear", command=clear_table, **btn_style).grid(row=0, column=2, padx=5)
tk.Button(btn_frame, text="Exit", command=exit_app, bg="#cc0000", fg="white", width=12).grid(row=0, column=3, padx=5)

# ---------- Status ----------
status_label = tk.Label(root, text="Status: Stopped", bg="#1e1e1e", fg="orange")
status_label.pack(pady=5)

root.mainloop()
