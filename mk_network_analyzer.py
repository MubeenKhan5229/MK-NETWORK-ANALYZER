#!/usr/bin/env python3
"""
MK Network Analyzer - Dark GUI Network Sniffer for Kali Linux
"""

import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP
import threading
import queue

# Global variables
sniffing = False
packet_queue = queue.Queue()
sniffer_thread = None

# Function to process packet
def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else "N/A")
        dport = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else "N/A")
        packet_queue.put((src, dst, proto, sport, dport))

# Thread function to sniff
def start_sniff():
    global sniffing, sniffer_thread
    if sniffing:
        return
    sniffing = True
    sniffer_thread = threading.Thread(target=lambda: sniff(prn=process_packet, store=False))
    sniffer_thread.daemon = True
    sniffer_thread.start()
    start_button.config(state="disabled")
    stop_button.config(state="normal")

def stop_sniff():
    global sniffing
    sniffing = False
    start_button.config(state="normal")
    stop_button.config(state="disabled")

def clear_table():
    for row in tree.get_children():
        tree.delete(row)

def exit_app():
    stop_sniff()
    root.destroy()

# Update table periodically
def update_table():
    while not packet_queue.empty():
        src, dst, proto, sport, dport = packet_queue.get()
        tree.insert("", "end", values=(src, dst, proto, sport, dport))
    root.after(200, update_table)

# GUI
root = tk.Tk()
root.title("MK Network Analyzer")
root.geometry("800x500")
root.configure(bg="#1e1e1e")

# Style
style = ttk.Style()
style.theme_use("default")
style.configure("Treeview", background="#252526", foreground="white", fieldbackground="#252526", rowheight=25)
style.configure("Treeview.Heading", background="#333333", foreground="white")
style.configure("TButton", background="#007acc", foreground="white")
style.map("TButton", background=[('active','#005f99')])

# Frame for buttons
btn_frame = tk.Frame(root, bg="#1e1e1e")
btn_frame.pack(pady=10)

start_button = ttk.Button(btn_frame, text="Start Sniff", command=start_sniff)
start_button.grid(row=0, column=0, padx=5)
stop_button = ttk.Button(btn_frame, text="Stop Sniff", command=stop_sniff, state="disabled")
stop_button.grid(row=0, column=1, padx=5)
clear_button = ttk.Button(btn_frame, text="Clear Table", command=clear_table)
clear_button.grid(row=0, column=2, padx=5)
exit_button = ttk.Button(btn_frame, text="Exit", command=exit_app)
exit_button.grid(row=0, column=3, padx=5)

# Table
columns = ("Source IP", "Destination IP", "Protocol", "Src Port", "Dst Port")
tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150, anchor="center")
tree.pack(fill="both", expand=True, pady=10, padx=10)

# Start updating table
root.after(200, update_table)
root.mainloop()
