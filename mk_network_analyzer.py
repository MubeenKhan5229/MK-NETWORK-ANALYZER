import tkinter as tk
from scapy.all import sniff

# ---------------- GUI ----------------
root = tk.Tk()
root.title("MK Network Analyzer")
root.geometry("700x400")
root.configure(bg="#1e1e2f")  # dark background

# Table for packets
text = tk.Text(root, bg="#2e2e3e", fg="white")
text.pack(expand=True, fill=tk.BOTH)

# Start/Stop buttons
def start_sniff():
    text.insert(tk.END, "Sniffing started...\n")
    def process_packet(packet):
        try:
            src = packet[0][1].src if packet.haslayer(1) else "N/A"
            dst = packet[0][1].dst if packet.haslayer(1) else "N/A"
            proto = packet.proto if hasattr(packet, "proto") else "N/A"
            line = f"SRC: {src} | DST: {dst} | PROTO: {proto}\n"
            text.insert(tk.END, line)
        except:
            pass
    global sniff_thread
    sniff_thread = sniff(prn=process_packet, store=False, count=10)

def stop_sniff():
    text.insert(tk.END, "Sniffing stopped.\n")
    # Note: Scapy sniff thread stopping is for demo only

frame = tk.Frame(root, bg="#1e1e2f")
frame.pack()
tk.Button(frame, text="Start", command=start_sniff, bg="#3e3e5e", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(frame, text="Stop", command=stop_sniff, bg="#5e3e3e", fg="white").pack(side=tk.LEFT, padx=5)

root.mainloop()
