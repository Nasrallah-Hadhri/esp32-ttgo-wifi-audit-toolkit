import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
from serial_client import SerialClient

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("WiFi Sec Advanced Node")
        self.geometry("1100x700")
        
        self.serial_client = SerialClient(self.serial_callback)
        self.networks = {} # Key: SSID, Value: (BSSID, Channel, RSSI, Auth)
        
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # ====== TOP BAR ======
        self.top_frame = ctk.CTkFrame(self, height=50, corner_radius=0, fg_color="#1a1a1a")
        self.top_frame.grid(row=0, column=0, columnspan=2, sticky="nsew")
        
        self.port_var = ctk.StringVar(value="Select Port")
        self.port_menu = ctk.CTkOptionMenu(self.top_frame, variable=self.port_var, values=self.serial_client.get_ports())
        self.port_menu.pack(side="left", padx=10, pady=10)
        
        self.refresh_btn = ctk.CTkButton(self.top_frame, text="Refresh", width=80, command=self.refresh_ports)
        self.refresh_btn.pack(side="left", padx=5, pady=10)
        
        self.connect_btn = ctk.CTkButton(self.top_frame, text="Connect", width=100, fg_color="#8B0000", hover_color="#A52A2A", command=self.toggle_connection)
        self.connect_btn.pack(side="left", padx=10, pady=10)
        
        self.status_label = ctk.CTkLabel(self.top_frame, text="OFFLINE", text_color="red", font=ctk.CTkFont(weight="bold"))
        self.status_label.pack(side="right", padx=20, pady=10)

        # ====== SIDEBAR ======
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=1, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="ATTACK VECTORS", font=ctk.CTkFont(size=16, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.btn_cat1 = ctk.CTkButton(self.sidebar_frame, text="1. Auth Sniffing", command=lambda: self.show_frame("cat1"))
        self.btn_cat1.grid(row=1, column=0, padx=20, pady=10)
        
        self.btn_cat2 = ctk.CTkButton(self.sidebar_frame, text="2. Targeted Deauth", command=lambda: self.show_frame("cat2"))
        self.btn_cat2.grid(row=2, column=0, padx=20, pady=10)
        
        self.btn_cat3 = ctk.CTkButton(self.sidebar_frame, text="3. Evil Twin AP", command=lambda: self.show_frame("cat3"))
        self.btn_cat3.grid(row=3, column=0, padx=20, pady=10)
        
        self.btn_cat4 = ctk.CTkButton(self.sidebar_frame, text="4. Router Audit", command=lambda: self.show_frame("cat4"))
        self.btn_cat4.grid(row=4, column=0, padx=20, pady=10)

        # ====== MAIN CONTENT ======
        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="transparent")
        self.main_frame.grid(row=1, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        
        # Target Selection Bar
        self.target_frame = ctk.CTkFrame(self.main_frame, fg_color="#2b2b2b")
        self.target_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        ctk.CTkButton(self.target_frame, text="Scan Networks", width=120, command=lambda: self.serial_client.send_cmd("CMD:SCAN")).pack(side="left", padx=10, pady=10)
        self.target_var = ctk.StringVar(value="No Target Selected")
        self.target_menu = ctk.CTkOptionMenu(self.target_frame, variable=self.target_var, values=["No Target Selected"], width=300)
        self.target_menu.pack(side="left", padx=10, pady=10)
        
        # Frame container
        self.controls_frame = ctk.CTkFrame(self.main_frame, fg_color="#222222")
        self.controls_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 20))
        
        # Terminal Log
        self.log_frame = ctk.CTkFrame(self.main_frame)
        self.log_frame.grid(row=2, column=0, sticky="nsew")
        self.log_frame.grid_rowconfigure(0, weight=1)
        self.log_frame.grid_columnconfigure(0, weight=1)
        
        self.log_textbox = ctk.CTkTextbox(self.log_frame, text_color="#00FF00", fg_color="#000000", font=ctk.CTkFont(family="Courier", size=12))
        self.log_textbox.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)

        self.frames = {}
        self.setup_category_frames()
        self.show_frame("cat1")
        
        # Audit specific vars
        self.devices_found = 0

    def terminal_log(self, text):
        self.log_textbox.insert("end", text + "\n")
        self.log_textbox.see("end")

    def serial_callback(self, data):
        self.terminal_log(f"> {data}")
        
        if data.startswith("RES:SCAN_AP:"):
            # Format: RES:SCAN_AP:SSID|BSSID|CH|RSSI|AUTH
            parts = data.replace("RES:SCAN_AP:", "").split('|')
            if len(parts) >= 5:
                ssid, bssid, ch, rssi, auth = parts[0], parts[1], parts[2], parts[3], parts[4]
                if ssid.strip():
                    self.networks[ssid] = (bssid, ch, rssi, auth)
                    self.update_target_dropdown()
                    
        elif data.startswith("RES:AUDIT_SWEEP:"):
            ip = data.replace("RES:AUDIT_SWEEP:", "")
            self.devices_found += 1
            self.sweep_label.configure(text=f"Devices Found on Subnet: {self.devices_found}")
            self.audit_log.insert("end", f"[+] Found Host: {ip}\n")
            self.audit_log.see("end")
            
        elif data.startswith("RES:AUDIT_PORT:"):
            msg = data.replace("RES:AUDIT_PORT:", "")
            self.audit_log.insert("end", f"[*] Port Check: {msg}\n")
            self.audit_log.see("end")
            
        elif data.startswith("RES:SNIFF_EAPOL:"):
            macs = data.replace("RES:SNIFF_EAPOL:", "")
            self.terminal_log(f"\n[!!!] HANDSHAKE CAPTURED: {macs} [!!!]\n")

    def update_target_dropdown(self):
        opts = list(self.networks.keys())
        if opts:
            self.target_menu.configure(values=opts)

    def refresh_ports(self):
        ports = self.serial_client.get_ports()
        self.port_menu.configure(values=ports)
        if ports:
            self.port_var.set(ports[0])

    def toggle_connection(self):
        if not self.serial_client.running:
            port = self.port_var.get()
            if port and port != "Select Port":
                success, msg = self.serial_client.connect(port)
                if success:
                    self.connect_btn.configure(text="Disconnect", fg_color="green", hover_color="darkgreen")
                    self.status_label.configure(text="ONLINE", text_color="#00FF00")
                    self.terminal_log(f"[*] Uplink established on {port}")
                else:
                    self.terminal_log(f"[!] Link Error: {msg}")
        else:
            self.serial_client.disconnect()
            self.connect_btn.configure(text="Connect", fg_color="#8B0000", hover_color="#A52A2A")
            self.status_label.configure(text="OFFLINE", text_color="red")
            self.terminal_log("[*] Uplink terminated")

    def get_selected_target(self):
        t = self.target_var.get()
        if t in self.networks:
            return t, self.networks[t]
        return None, None

    def trigger_sniff(self):
        ssid, data = self.get_selected_target()
        if ssid:
            ch = data[1]
            self.serial_client.send_cmd(f"CMD:SNIFF_START:{ch}")
        else:
            self.terminal_log("[!] Please select a target network from the dropdown first.")

    def trigger_deauth(self):
        ssid, data = self.get_selected_target()
        if ssid:
            bssid, ch = data[0], data[1]
            self.serial_client.send_cmd(f"CMD:DEAUTH:{bssid}:{ch}")
        else:
            self.terminal_log("[!] Please select a target network from the dropdown first.")

    def trigger_rogue(self):
        ssid, data = self.get_selected_target()
        if ssid:
            self.serial_client.send_cmd(f"CMD:ROGUE:{ssid}")
        else:
            self.terminal_log("[!] Please select a target network from the dropdown first.")

    def trigger_audit(self):
        ssid = self.audit_ssid.get()
        pw = self.audit_pass.get()
        if ssid and pw:
            self.devices_found = 0
            self.sweep_label.configure(text="Devices Found on Subnet: 0")
            self.audit_log.delete("0.0", "end")
            self.serial_client.send_cmd(f"CMD:AUDIT:{ssid}:{pw}")
        else:
            self.terminal_log("[!] Need SSID and Password to audit router.")

    def setup_category_frames(self):
        # 1. Auth
        f1 = ctk.CTkFrame(self.controls_frame, fg_color="transparent")
        ctk.CTkLabel(f1, text="EAPOL PROMISCUOUS SNIFFER", font=ctk.CTkFont(size=18, weight="bold"), text_color="#00FF00").pack(pady=10)
        ctk.CTkLabel(f1, text="Select a target from the top dropdown, then engage the sniffer.\nThe ESP32 will lock to the target channel and intercept raw 4-way handshakes.").pack()
        ctk.CTkButton(f1, text="Engage Sniffer", fg_color="#B8860B", hover_color="#DAA520", command=self.trigger_sniff).pack(pady=10)
        ctk.CTkButton(f1, text="Halt Sniffer", command=lambda: self.serial_client.send_cmd("CMD:SNIFF_STOP")).pack()
        self.frames["cat1"] = f1

        # 2. Deauth
        f2 = ctk.CTkFrame(self.controls_frame, fg_color="transparent")
        ctk.CTkLabel(f2, text="TARGETED 802.11 DEAUTHENTICATION", font=ctk.CTkFont(size=18, weight="bold"), text_color="#FF4500").pack(pady=10)
        ctk.CTkLabel(f2, text="Select a target network. The ESP32 will impersonate the AP\nand broadcast Reason 7 Deauth frames to disconnect all clients on that BSSID.").pack()
        ctk.CTkButton(f2, text="FIRE DEAUTH PAYLOAD", fg_color="red", hover_color="darkred", command=self.trigger_deauth).pack(pady=20)
        self.frames["cat2"] = f2

        # 3. Rogue AP
        f3 = ctk.CTkFrame(self.controls_frame, fg_color="transparent")
        ctk.CTkLabel(f3, text="EVIL TWIN / ROGUE AP", font=ctk.CTkFont(size=18, weight="bold"), text_color="#1E90FF").pack(pady=10)
        ctk.CTkLabel(f3, text="Select a target network. The ESP32 will launch an open SoftAP\nwith the exact same SSID to trick devices into auto-joining.").pack()
        ctk.CTkButton(f3, text="Launch Evil Twin", fg_color="#1E90FF", hover_color="#4682B4", command=self.trigger_rogue).pack(pady=10)
        ctk.CTkButton(f3, text="Disable SoftAP", command=lambda: self.serial_client.send_cmd("CMD:ROGUE_STOP")).pack()
        self.frames["cat3"] = f3

        # 4. Audit
        f4 = ctk.CTkFrame(self.controls_frame, fg_color="transparent")
        ctk.CTkLabel(f4, text="PERSONAL ROUTER & SUBNET AUDIT", font=ctk.CTkFont(size=18, weight="bold"), text_color="#9932CC").grid(row=0, column=0, columnspan=2, pady=10)
        
        self.audit_ssid = ctk.CTkEntry(f4, placeholder_text="Personal SSID")
        self.audit_ssid.grid(row=1, column=0, padx=10, pady=5)
        self.audit_pass = ctk.CTkEntry(f4, placeholder_text="WiFi Password", show="*")
        self.audit_pass.grid(row=1, column=1, padx=10, pady=5)
        
        ctk.CTkButton(f4, text="Connect & Audit", fg_color="#8A2BE2", command=self.trigger_audit).grid(row=2, column=0, columnspan=2, pady=10)
        
        self.sweep_label = ctk.CTkLabel(f4, text="Devices Found on Subnet: 0", font=ctk.CTkFont(weight="bold"))
        self.sweep_label.grid(row=3, column=0, columnspan=2, pady=5)
        
        self.audit_log = ctk.CTkTextbox(f4, height=100, width=500, fg_color="#111111", text_color="#00FFFF")
        self.audit_log.grid(row=4, column=0, columnspan=2, padx=10, pady=10)
        self.frames["cat4"] = f4

    def show_frame(self, name):
        for f in self.frames.values():
            f.pack_forget()
        self.frames[name].pack(fill="both", expand=True)

if __name__ == "__main__":
    app = App()
    app.mainloop()
