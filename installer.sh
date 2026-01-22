cat <<'EOF' > install_network_detector.sh
#!/bin/bash

INSTALL_DIR="$HOME/.network_detector"
BIN_DIR="$HOME/.local/bin"
SCRIPT="$INSTALL_DIR/network_detector.py"

mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"

cat <<'PYEOF' > "$SCRIPT"
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

sniffing = False

def packet_handler(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "OTHER"
        tree.insert("", "end", values=(src, dst, proto, len(packet)))
        tree.yview_moveto(1)

def start_sniff():
    global sniffing
    sniffing = True
    sniff(prn=packet_handler, store=False, stop_filter=lambda x: not sniffing)

def start():
    threading.Thread(target=start_sniff, daemon=True).start()
    status.config(text="Status: RUNNING", fg="#00ff99")

def stop():
    global sniffing
    sniffing = False
    status.config(text="Status: STOPPED", fg="#ff5555")

def license_box():
    messagebox.showinfo(
        "License",
        "Network Detector by Mubeen Khan\n\n"
        "Educational & Defensive Use Only\n"
        "Unauthorized monitoring is illegal.\n\n© 2026 Mubeen Khan"
    )

root = tk.Tk()
root.title("Network Detector by Mubeen Khan")
root.geometry("900x520")
root.configure(bg="#121212")

style = ttk.Style()
style.theme_use("default")
style.configure("Treeview", background="#1e1e1e", foreground="white", fieldbackground="#1e1e1e", rowheight=26)
style.configure("Treeview.Heading", background="#333333", foreground="white")

tk.Label(root, text="Network Detector by Mubeen Khan", bg="#121212", fg="#00e6e6",
         font=("Segoe UI", 18, "bold")).pack(pady=10)

status = tk.Label(root, text="Status: IDLE", bg="#121212", fg="#ffaa00")
status.pack()

tree = ttk.Treeview(root, columns=("Source IP","Destination IP","Protocol","Size"), show="headings")
for c in ("Source IP","Destination IP","Protocol","Size"):
    tree.heading(c, text=c)
    tree.column(c, width=210)
tree.pack(expand=True, fill="both", padx=12, pady=12)

btn = tk.Frame(root, bg="#121212")
btn.pack(pady=10)

tk.Button(btn, text="START", width=14, bg="#007acc", fg="white", command=start).grid(row=0,column=0,padx=6)
tk.Button(btn, text="STOP", width=14, bg="#cc0000", fg="white", command=stop).grid(row=0,column=1,padx=6)
tk.Button(btn, text="LICENSE", width=14, command=license_box).grid(row=0,column=2,padx=6)
tk.Button(btn, text="EXIT", width=14, command=root.destroy).grid(row=0,column=3,padx=6)

root.mainloop()
PYEOF

chmod +x "$SCRIPT"
ln -sf "$SCRIPT" "$BIN_DIR/network-detector"

if ! echo \$PATH | grep -q "$BIN_DIR"; then
  echo "export PATH=\$PATH:$BIN_DIR" >> ~/.bashrc
fi

echo ""
echo "✅ Network Detector Installed Successfully!"
echo "👉 Run anytime using command: network-detector"
echo ""
EOF
