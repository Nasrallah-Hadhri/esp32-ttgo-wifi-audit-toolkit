import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import time
from backend import PentestBackend

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

class KaliDash(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Kali Linux WiFi Pentesting Dashboard")
        self.geometry("1100x700")

        self.backend = PentestBackend()
        self.active_interface = None
        self.scan_running = False
        self.wps_scan_running = False
        self.capture_running = False
        
        self.build_ui()

    def build_ui(self):
        # Top Bar (Interface Setup)
        self.top_frame = ctk.CTkFrame(self, height=50)
        self.top_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(self.top_frame, text="Interface:", font=("Arial", 14, "bold")).pack(side="left", padx=10)
        
        self.iface_var = ctk.StringVar(value="Select Interface")
        self.iface_menu = ctk.CTkOptionMenu(self.top_frame, variable=self.iface_var, values=self.backend.get_interfaces())
        self.iface_menu.pack(side="left", padx=10)
        
        ctk.CTkButton(self.top_frame, text="Refresh", width=80, command=self.refresh_ifaces).pack(side="left", padx=5)
        
        self.monitor_btn = ctk.CTkButton(self.top_frame, text="Enable Monitor Mode", fg_color="blue", command=self.toggle_monitor)
        self.monitor_btn.pack(side="left", padx=20)
        
        self.status_label = ctk.CTkLabel(self.top_frame, text="STATUS: Managed", text_color="red", font=("Arial", 14, "bold"))
        self.status_label.pack(side="right", padx=20)

        # Main Tabview
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.tab_wpa = self.tabview.add("WPA Pentest")
        self.tab_wps = self.tabview.add("WPS Pentest")
        self.tab_crack = self.tabview.add("Cracking Engine")
        
        self.build_wpa_tab()
        self.build_wps_tab()
        self.build_crack_tab()

    def refresh_ifaces(self):
        ifaces = self.backend.get_interfaces()
        self.iface_menu.configure(values=ifaces if ifaces else ["No Interfaces Found"])
        if ifaces:
            self.iface_var.set(ifaces[0])

    def toggle_monitor(self):
        iface = self.iface_var.get()
        if "Select" in iface or "No" in iface:
            return
            
        if self.monitor_btn.cget("text") == "Enable Monitor Mode":
            self.status_label.configure(text="Enabling...", text_color="yellow")
            self.update()
            new_iface = self.backend.start_monitor(iface)
            if new_iface:
                self.active_interface = new_iface
                self.status_label.configure(text=f"STATUS: Monitor ({new_iface})", text_color="green")
                self.monitor_btn.configure(text="Disable Monitor Mode", fg_color="red")
                self.iface_var.set(new_iface)
            else:
                self.status_label.configure(text="FAILED TO ENABLE", text_color="red")
        else:
            self.backend.stop_monitor(self.active_interface)
            self.status_label.configure(text="STATUS: Managed", text_color="red")
            self.monitor_btn.configure(text="Enable Monitor Mode", fg_color="blue")
            self.active_interface = None
            self.refresh_ifaces()

    # ================= WPA TAB =================
    def build_wpa_tab(self):
        f = self.tab_wpa
        
        # Controls
        ctrl_frame = ctk.CTkFrame(f)
        ctrl_frame.pack(fill="x", pady=5)
        
        self.wpa_scan_btn = ctk.CTkButton(ctrl_frame, text="Start Scan", command=self.toggle_wpa_scan)
        self.wpa_scan_btn.pack(side="left", padx=10)
        
        self.wpa_target_var = ctk.StringVar(value="Select Target BSSID")
        self.wpa_target_menu = ctk.CTkOptionMenu(ctrl_frame, variable=self.wpa_target_var, values=["No Targets"], width=250)
        self.wpa_target_menu.pack(side="left", padx=10)
        
        ctk.CTkButton(ctrl_frame, text="1. Capture Handshake", fg_color="purple", command=self.start_capture).pack(side="left", padx=10)
        ctk.CTkButton(ctrl_frame, text="2. Send Deauth", fg_color="red", command=self.send_deauth).pack(side="left", padx=10)
        
        # Capture Status
        self.handshake_status = ctk.CTkLabel(ctrl_frame, text="Handshake: NOT FOUND", text_color="red", font=("Arial", 14, "bold"))
        self.handshake_status.pack(side="right", padx=20)
        
        # AP List (Basic Textbox for simplicity, ideally a Treeview)
        self.wpa_ap_text = ctk.CTkTextbox(f, font=("Courier", 12))
        self.wpa_ap_text.pack(fill="both", expand=True, pady=5)

    def toggle_wpa_scan(self):
        if not self.active_interface:
            messagebox.showerror("Error", "Enable Monitor Mode first!")
            return
            
        if not self.scan_running:
            self.backend.start_wpa_scan(self.active_interface)
            self.scan_running = True
            self.wpa_scan_btn.configure(text="Stop Scan", fg_color="red")
            self.update_wpa_scan_loop()
        else:
            self.backend.stop_wpa_scan()
            self.scan_running = False
            self.wpa_scan_btn.configure(text="Start Scan", fg_color="blue")

    def update_wpa_scan_loop(self):
        if self.scan_running:
            aps, clients = self.backend.parse_wpa_scan()
            
            self.wpa_ap_text.delete("0.0", "end")
            self.wpa_ap_text.insert("end", f"{'BSSID':<20} {'PWR':<5} {'CH':<4} {'ENC':<6} {'ESSID'}\n")
            self.wpa_ap_text.insert("end", "-"*60 + "\n")
            
            targets = []
            for ap in aps:
                bssid, pwr, ch, enc, essid = ap['BSSID'], ap['Power'], ap['Channel'], ap['Privacy'], ap['ESSID']
                self.wpa_ap_text.insert("end", f"{bssid:<20} {pwr:<5} {ch:<4} {enc:<6} {essid}\n")
                targets.append(f"{bssid} (CH {ch}) - {essid}")
                
            if clients:
                self.wpa_ap_text.insert("end", "\n" + "-"*60 + "\n")
                self.wpa_ap_text.insert("end", f"{'CLIENT MAC':<20} {'BSSID':<20} {'PWR'}\n")
                self.wpa_ap_text.insert("end", "-"*60 + "\n")
                for c in clients:
                    self.wpa_ap_text.insert("end", f"{c['ClientMAC']:<20} {c['BSSID']:<20} {c['Power']}\n")
            
            if targets:
                current = self.wpa_target_var.get()
                self.wpa_target_menu.configure(values=targets)
                if current == "No Targets" or current not in targets:
                    self.wpa_target_var.set(targets[0])
            
            self.after(2000, self.update_wpa_scan_loop)

    def start_capture(self):
        if not self.active_interface:
            return
        target = self.wpa_target_var.get()
        if target == "No Targets": return
        
        bssid = target.split(' ')[0]
        ch = target.split('CH ')[1].split(')')[0]
        
        # Stop scan if running
        if self.scan_running:
            self.toggle_wpa_scan()
            
        self.backend.start_handshake_capture(self.active_interface, bssid, ch)
        self.capture_running = True
        self.handshake_status.configure(text="Handshake: WAITING...", text_color="yellow")
        self.check_handshake_loop()

    def check_handshake_loop(self):
        if self.capture_running:
            if self.backend.check_handshake_captured():
                self.handshake_status.configure(text="Handshake: CAPTURED!", text_color="#00FF00")
                self.capture_running = False
                messagebox.showinfo("Success", "WPA Handshake captured!\nSaved to /tmp/wifiaudit/capture-01.cap")
                # Stop airodump
                self.backend._kill_process("airodump")
            else:
                self.after(3000, self.check_handshake_loop)

    def send_deauth(self):
        if not self.active_interface: return
        target = self.wpa_target_var.get()
        if target == "No Targets": return
        bssid = target.split(' ')[0]
        self.backend.send_deauth(self.active_interface, bssid)
        self.handshake_status.configure(text="DEAUTH SENT...", text_color="orange")

    # ================= WPS TAB =================
    def build_wps_tab(self):
        f = self.tab_wps
        
        ctrl = ctk.CTkFrame(f)
        ctrl.pack(fill="x", pady=5)
        
        self.wps_scan_btn = ctk.CTkButton(ctrl, text="Start Wash Scan", command=self.toggle_wps_scan)
        self.wps_scan_btn.pack(side="left", padx=10)
        
        self.wps_text = ctk.CTkTextbox(f, font=("Courier", 12))
        self.wps_text.pack(fill="both", expand=True, pady=5)

    def toggle_wps_scan(self):
        if not self.active_interface: return
        
        if not self.wps_scan_running:
            self.backend.start_wps_scan(self.active_interface)
            self.wps_scan_running = True
            self.wps_scan_btn.configure(text="Stop Wash Scan", fg_color="red")
            self.update_wps_scan_loop()
        else:
            self.backend.stop_wps_scan()
            self.wps_scan_running = False
            self.wps_scan_btn.configure(text="Start Wash Scan", fg_color="blue")

    def update_wps_scan_loop(self):
        if self.wps_scan_running:
            aps = self.backend.parse_wps_scan()
            self.wps_text.delete("0.0", "end")
            self.wps_text.insert("end", f"{'BSSID':<20} {'CH':<4} {'RSSI':<5} {'WPS':<5} {'LOCKED':<6} {'ESSID'}\n")
            self.wps_text.insert("end", "-"*60 + "\n")
            for ap in aps:
                self.wps_text.insert("end", f"{ap['BSSID']:<20} {ap['Channel']:<4} {ap['RSSI']:<5} {ap['WPS_Ver']:<5} {ap['Locked']:<6} {ap['ESSID']}\n")
                
            self.after(3000, self.update_wps_scan_loop)

    # ================= CRACKING TAB =================
    def build_crack_tab(self):
        f = self.tab_crack
        
        ctrl = ctk.CTkFrame(f)
        ctrl.pack(fill="x", pady=10)
        
        self.cap_path = ctk.StringVar(value="/tmp/wifiaudit/capture-01.cap")
        self.wl_path = ctk.StringVar(value="/usr/share/wordlists/rockyou.txt")
        
        ctk.CTkLabel(ctrl, text=".CAP File:").grid(row=0, column=0, padx=5, pady=5)
        ctk.CTkEntry(ctrl, textvariable=self.cap_path, width=300).grid(row=0, column=1, padx=5)
        ctk.CTkButton(ctrl, text="Browse", width=60, command=lambda: self.cap_path.set(filedialog.askopenfilename())).grid(row=0, column=2, padx=5)
        
        ctk.CTkLabel(ctrl, text="Wordlist:").grid(row=1, column=0, padx=5, pady=5)
        ctk.CTkEntry(ctrl, textvariable=self.wl_path, width=300).grid(row=1, column=1, padx=5)
        ctk.CTkButton(ctrl, text="Browse", width=60, command=lambda: self.wl_path.set(filedialog.askopenfilename())).grid(row=1, column=2, padx=5)
        
        ctk.CTkButton(ctrl, text="START CRACKING", fg_color="darkred", hover_color="red", command=self.start_cracking).grid(row=2, column=1, pady=15)
        
        self.crack_out = ctk.CTkTextbox(f, font=("Courier", 12), fg_color="black", text_color="green")
        self.crack_out.pack(fill="both", expand=True, pady=5)

    def start_cracking(self):
        cap = self.cap_path.get()
        wl = self.wl_path.get()
        
        self.crack_out.delete("0.0", "end")
        self.crack_out.insert("end", f"[*] Starting Aircrack-ng...\n[*] Wordlist: {wl}\n[*] Capture: {cap}\n\n")
        
        proc = self.backend.crack_wpa(cap, wl)
        
        def read_output():
            for line in iter(proc.stdout.readline, ''):
                self.crack_out.insert("end", line)
                self.crack_out.see("end")
            proc.stdout.close()
            
        threading.Thread(target=read_output, daemon=True).start()

    def on_closing(self):
        self.backend.stop_wpa_scan()
        self.backend.stop_wps_scan()
        if self.active_interface:
            self.backend.stop_monitor(self.active_interface)
        self.destroy()

if __name__ == "__main__":
    app = KaliDash()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
