"""
audit_engine.py — Kali-side WiFi router audit engine
Runs entirely from Kali's network stack (no ESP32 needed).
"""
import socket, subprocess, threading, time, os, datetime
import cve_db

# ── Common port table ──────────────────────────────────────────────────────────
COMMON_PORTS = {
    21:   "FTP",        22:   "SSH",         23:   "Telnet",
    25:   "SMTP",       53:   "DNS",          67:   "DHCP",
    80:   "HTTP",       110:  "POP3",         123:  "NTP",
    143:  "IMAP",       161:  "SNMP",         443:  "HTTPS",
    445:  "SMB",        500:  "IKE/VPN",      554:  "RTSP",
    1194: "OpenVPN",    1723: "PPTP",          1900: "UPnP",
    3306: "MySQL",      3389: "RDP",           4443: "HTTPS-Alt",
    7547: "TR-069",     8080: "HTTP-Proxy",    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",   9090: "HTTP-Alt",
}

# High-risk services for flagging
HIGH_RISK_PORTS = {23, 21, 161, 7547, 1900, 445, 3389}
MEDIUM_RISK_PORTS = {22, 80, 3306, 8080, 8888, 9090}

# ── Network helpers ────────────────────────────────────────────────────────────

def detect_gateway():
    """Return (gateway_ip, interface) from the default route."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
        # e.g. "default via 192.168.1.1 dev wlan0 ..."
        parts = out.split()
        idx_via = parts.index("via") if "via" in parts else -1
        idx_dev = parts.index("dev") if "dev" in parts else -1
        gw  = parts[idx_via + 1] if idx_via >= 0 else ""
        dev = parts[idx_dev + 1] if idx_dev >= 0 else "?"
        return gw, dev
    except Exception:
        return "", "?"

def detect_local_ip(interface):
    """Return local IP on given interface."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", interface], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return ""

def build_subnet(gateway):
    """Build /24 subnet from gateway, e.g. 192.168.1.255 -> 192.168.1"""
    parts = gateway.rsplit(".", 1)
    return parts[0] if len(parts) == 2 else gateway

# ── Port scanner ───────────────────────────────────────────────────────────────

def scan_port(host, port, timeout=0.8):
    """Return (port, open, banner)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        if result == 0:
            banner = ""
            try:
                s.settimeout(0.5)
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                raw = s.recv(256)
                banner = raw.decode(errors="ignore").split("\n")[0].strip()[:80]
            except Exception:
                pass
            s.close()
            return port, True, banner
        s.close()
    except Exception:
        pass
    return port, False, ""

def scan_ports_threaded(host, ports, timeout=0.8, callback=None):
    """Scan ports in parallel. callback(port, open, banner, service) per result."""
    results = []
    lock = threading.Lock()

    def _worker(p):
        port, is_open, banner = scan_port(host, p, timeout)
        svc = COMMON_PORTS.get(port, "Unknown")
        if callback:
            callback(port, is_open, banner, svc)
        if is_open:
            with lock:
                results.append({"port": port, "service": svc, "banner": banner,
                                 "risk": "HIGH" if port in HIGH_RISK_PORTS else
                                         "MEDIUM" if port in MEDIUM_RISK_PORTS else "LOW"})

    threads = [threading.Thread(target=_worker, args=(p,), daemon=True) for p in ports]
    for t in threads: t.start()
    for t in threads: t.join()
    return sorted(results, key=lambda x: x["port"])

# ── Host discovery (ping sweep) ────────────────────────────────────────────────

def ping_host(ip, timeout=0.5):
    """Return True if host responds to ping."""
    try:
        ret = subprocess.call(
            ["ping", "-c", "1", "-W", str(int(timeout*2)), ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return ret == 0
    except Exception:
        return False

def host_discovery(subnet, callback=None, max_hosts=254):
    """Ping-sweep a /24 subnet. callback(ip, alive) per host."""
    live = []
    lock = threading.Lock()

    def _check(i):
        ip = f"{subnet}.{i}"
        alive = ping_host(ip)
        if callback:
            callback(ip, alive)
        if alive:
            with lock:
                live.append(ip)

    threads = [threading.Thread(target=_check, args=(i,), daemon=True)
               for i in range(1, min(max_hosts + 1, 255))]
    for t in threads: t.start()
    for t in threads: t.join(timeout=30)
    return sorted(live, key=lambda ip: int(ip.split(".")[-1]))

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

# ── PDF report generator ───────────────────────────────────────────────────────

def generate_pdf(out_path, findings: dict):
    """
    findings = {
        "target": str, "gateway": str, "interface": str, "local_ip": str,
        "scan_time": str,
        "open_ports": [{"port":int,"service":str,"banner":str,"risk":str}],
        "live_hosts": [str],
        "networks": [{"ssid":str,"bssid":str,"ch":str,"rssi":str,"security":str,"risk":str,"score":int}],
        "session_log": [(key,status,ts,detail)],
    }
    Returns (True, path) or (False, error_msg)
    """
    try:
        from fpdf import FPDF
    except ImportError:
        return False, "fpdf2 not installed — run: pip install fpdf2"

    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # ── Cover ──────────────────────────────────────────────────────────────────
        pdf.set_fill_color(13, 13, 30)
        pdf.rect(0, 0, 210, 297, "F")

        pdf.set_font("Courier", "B", 22)
        pdf.set_text_color(0, 200, 120)
        pdf.set_xy(0, 40)
        pdf.cell(210, 12, "WiFi Penetration Test", align="C")
        pdf.ln(12)
        pdf.cell(210, 12, "Audit Report", align="C")
        pdf.ln(12)

        pdf.set_font("Courier", "", 11)
        pdf.set_text_color(180, 180, 180)
        pdf.ln(8)
        pdf.cell(210, 7, f"Target Gateway : {findings.get('gateway','N/A')}", align="C")
        pdf.ln(7)
        pdf.cell(210, 7, f"Interface      : {findings.get('interface','N/A')}", align="C")
        pdf.ln(7)
        pdf.cell(210, 7, f"Local IP       : {findings.get('local_ip','N/A')}", align="C")
        pdf.ln(7)
        pdf.cell(210, 7, f"Date           : {findings.get('scan_time', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}", align="C")
        pdf.ln(7)

        # Risk summary box
        open_ports = findings.get("open_ports", [])
        high   = sum(1 for p in open_ports if p["risk"] == "HIGH")
        medium = sum(1 for p in open_ports if p["risk"] == "MEDIUM")
        low    = sum(1 for p in open_ports if p["risk"] == "LOW")
        hosts  = len(findings.get("live_hosts", []))

        pdf.ln(14)
        pdf.set_font("Courier", "B", 12)
        pdf.set_text_color(255, 80, 80) if high > 0 else pdf.set_text_color(255, 180, 0)
        risk_label = "CRITICAL RISK" if high > 0 else "MEDIUM RISK" if medium > 0 else "LOW RISK"
        pdf.cell(210, 10, f"[ {risk_label} ]", align="C")
        pdf.ln(10)

        pdf.set_font("Courier", "", 10)
        pdf.set_text_color(160, 160, 160)
        pdf.cell(210, 6, f"Open Ports: {len(open_ports)}  |  HIGH: {high}  MEDIUM: {medium}  LOW: {low}  |  Live Hosts: {hosts}", align="C")
        pdf.ln(6)

        # Security grade badge
        sec = cve_db.calculate_security_score(open_ports)
        pdf.ln(10)
        pdf.set_font("Courier", "B", 48)
        pdf.set_text_color(*sec["color"])
        pdf.cell(210, 20, sec["grade"], align="C")
        pdf.ln(20)
        pdf.set_font("Courier", "B", 13)
        pdf.cell(210, 8, f"Security Score: {sec['score']}/100  -  {sec['label']}", align="C")
        pdf.ln(8)
        # Score bar
        bar_x, bar_w, bar_h = 40, 130, 6
        pdf.ln(4)
        y_bar = pdf.get_y()
        pdf.set_fill_color(40, 40, 60)
        pdf.rect(bar_x, y_bar, bar_w, bar_h, "F")
        filled = int(bar_w * sec["score"] / 100)
        pdf.set_fill_color(*sec["color"])
        pdf.rect(bar_x, y_bar, filled, bar_h, "F")
        pdf.ln(bar_h + 4)

        # ── Helper functions ───────────────────────────────────────────────────────
        def safe_str(s, maxlen=None):
            """Strip characters outside latin-1 range so Courier font never crashes."""
            out = "".join(c for c in str(s) if ord(c) < 256)
            return out[:maxlen] if maxlen else out

        def section(title, color=(0, 200, 120)):
            pdf.add_page()
            pdf.set_fill_color(13, 13, 30)
            pdf.rect(0, 0, 210, 297, "F")
            pdf.set_xy(10, 12)
            pdf.set_font("Courier", "B", 14)
            pdf.set_text_color(*color)
            pdf.cell(0, 10, safe_str(title))
            pdf.ln(10)
            pdf.set_draw_color(*color)
            pdf.set_line_width(0.5)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(4)

        def row_hdr(*cols_widths, bg=(30, 30, 60)):
            pdf.set_fill_color(*bg)
            pdf.set_font("Courier", "B", 9)
            pdf.set_text_color(0, 220, 130)
            for txt, w in cols_widths:
                pdf.cell(w, 6, txt, border=0, fill=True)
            pdf.ln()

        def row_data(*cols_widths, even=True):
            bg = (20, 20, 40) if even else (25, 25, 50)
            pdf.set_fill_color(*bg)
            pdf.set_font("Courier", "", 9)
            pdf.set_text_color(210, 210, 210)
            for txt, w in cols_widths:
                pdf.cell(w, 6, str(txt)[:int(w/1.8)], border=0, fill=True)
            pdf.ln()

        RISK_COLOR = {"HIGH": (255, 80, 80), "MEDIUM": (255, 180, 0), "LOW": (100, 220, 100)}

        # ── Section 1 : Open Ports ─────────────────────────────────────────────────
        section("1. Port Scan Results")
        pdf.set_xy(10, pdf.get_y())
        row_hdr(("PORT", 22), ("SERVICE", 35), ("RISK", 28), ("BANNER", 105))
        if open_ports:
            for i, p in enumerate(open_ports):
                rc = RISK_COLOR.get(p["risk"], (200, 200, 200))
                pdf.set_fill_color(20, 20, 40) if i % 2 == 0 else pdf.set_fill_color(25, 25, 50)
                pdf.set_font("Courier", "", 9)
                pdf.set_text_color(210, 210, 210)
                pdf.cell(22, 6, safe_str(p["port"]), fill=True)
                pdf.cell(35, 6, safe_str(p["service"]), fill=True)
                pdf.set_text_color(*rc)
                pdf.cell(28, 6, safe_str(p["risk"]), fill=True)
                pdf.set_text_color(150, 150, 150)
                pdf.cell(105, 6, safe_str(p["banner"] or "-", 60), fill=True)
                pdf.ln()
        else:
            pdf.set_font("Courier", "I", 10)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 8, "No open ports detected.")
            pdf.ln(8)

        # Port vulnerability notes
        pdf.ln(4)
        pdf.set_font("Courier", "B", 10)
        pdf.set_text_color(255, 80, 80)
        vuln_notes = []
        port_nums = {p["port"] for p in open_ports}
        if 23   in port_nums: vuln_notes.append("! Telnet (23) open - credentials sent in PLAINTEXT")
        if 21   in port_nums: vuln_notes.append("! FTP (21) open - data/credentials unencrypted")
        if 7547 in port_nums: vuln_notes.append("! TR-069 (7547) open - ISP management port exposed")
        if 1900 in port_nums: vuln_notes.append("! UPnP (1900) open - NAT traversal attack surface")
        if 161  in port_nums: vuln_notes.append("! SNMP (161) open - may expose config with default string")
        if 3389 in port_nums: vuln_notes.append("! RDP (3389) open - remote desktop brute-force risk")
        for note in vuln_notes:
            pdf.cell(0, 6, safe_str(note))
            pdf.ln(6)

        # ── Section 2 : CVE Analysis ───────────────────────────────────────────────
        if open_ports:
            section("2. CVE Vulnerability Analysis", color=(255, 80, 80))
            CVSS_COL = lambda s: (255,50,50) if s>=9 else (255,160,0) if s>=7 else (255,220,0) if s>=4 else (100,220,100)
            row_hdr(("PORT",20),("CVE ID",38),("CVSS",16),("SEVERITY",28),("DESCRIPTION",88))
            has_cves = False
            for p in open_ports:
                entry = cve_db.lookup(p["port"])
                if not entry:
                    continue
                for cve in entry.get("cves",[]):
                    has_cves = True
                    pdf.set_fill_color(20,20,40)
                    pdf.set_font("Courier", "", 8)
                    pdf.set_text_color(210,210,210)
                    pdf.cell(20, 5, safe_str(p["port"]), fill=True)
                    pdf.cell(38, 5, safe_str(cve["id"]), fill=True)
                    pdf.set_text_color(*CVSS_COL(cve["cvss"]))
                    pdf.cell(16, 5, safe_str(f"{cve['cvss']:.1f}"), fill=True)
                    pdf.cell(28, 5, safe_str(cve["severity"]), fill=True)
                    pdf.set_text_color(200,200,200)
                    pdf.cell(88, 5, safe_str(cve["desc"], 55), fill=True)
                    pdf.ln()
            if not has_cves:
                pdf.set_font("Courier","I",10); pdf.set_text_color(100,100,100)
                pdf.cell(0,8,"No CVEs matched the detected open ports.")
                pdf.ln(8)

        # ── Section 3 : Host Discovery ─────────────────────────────────────────────
        section("3. Connected Devices (Subnet Sweep)")
        live_hosts = findings.get("live_hosts", [])
        if live_hosts:
            row_hdr(("IP ADDRESS", 50), ("HOSTNAME", 80), ("STATUS", 30), ("NOTES", 30))
            for i, ip in enumerate(live_hosts):
                hostname = resolve_hostname(ip)
                note = "GATEWAY" if ip == findings.get("gateway") else \
                       "LOCAL"   if ip == findings.get("local_ip") else ""
                row_data((safe_str(ip), 50), (safe_str(hostname or "-"), 80),
                         ("ONLINE", 30), (safe_str(note), 30), even=(i%2==0))
        else:
            pdf.set_font("Courier", "I", 10)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 8, "No hosts discovered (ping may be blocked by firewall).")
            pdf.ln(8)

        # ── Section 3 : Discovered WiFi Networks ───────────────────────────────────
        networks = findings.get("networks", [])
        if networks:
            section("4. WiFi Network Security Assessment")
            row_hdr(("SSID", 55), ("BSSID", 42), ("CH", 12), ("RSSI", 18),
                    ("SECURITY", 28), ("RISK", 28), ("SCORE", 17))
            for i, n in enumerate(networks):
                # Strip emoji from risk label (e.g. "CRITICAL" from "🔴 CRITICAL")
                risk_txt = safe_str(n.get("risk", "")).strip()
                rc = RISK_COLOR.get(risk_txt.split()[-1] if risk_txt else "LOW", (200,200,200))
                pdf.set_fill_color(20,20,40) if i%2==0 else pdf.set_fill_color(25,25,50)
                pdf.set_font("Courier", "", 8)
                pdf.set_text_color(210, 210, 210)
                pdf.cell(55, 5, safe_str(n.get("ssid",""), 28), fill=True)
                pdf.cell(42, 5, safe_str(n.get("bssid","")), fill=True)
                pdf.cell(12, 5, safe_str(n.get("ch","")), fill=True)
                pdf.cell(18, 5, safe_str(n.get("rssi","")), fill=True)
                pdf.cell(28, 5, safe_str(n.get("security","")), fill=True)
                pdf.set_text_color(*rc)
                pdf.cell(28, 5, risk_txt[:15], fill=True)
                pdf.set_text_color(210, 210, 210)
                pdf.cell(17, 5, safe_str(n.get("score","")), fill=True)
                pdf.ln()

        # ── Section 4 : Security Recommendations ──────────────────────────────────
        section("5. Security Recommendations", color=(0, 180, 255))
        recs = [
            ("IMMEDIATE", [
                "Disable Telnet (port 23) - use SSH only.",
                "Disable FTP (port 21) - use SFTP/SCP.",
                "Disable UPnP (port 1900) - common exploitation vector.",
                "Disable WPS on all access points.",
                "Change all default admin credentials.",
            ] if high > 0 else []),
            ("IMPORTANT", [
                "Upgrade to WPA3 with PMF (802.11w) on all APs.",
                "Restrict SSH (22) access to specific IPs via firewall.",
                "Disable HTTP admin interface (80) - use HTTPS only.",
                "Update router firmware to latest version.",
                "Enable logging and intrusion detection on the router.",
            ]),
            ("BEST PRACTICE", [
                "Segment IoT devices onto a separate VLAN.",
                "Use a VPN for remote administration.",
                "Rotate WiFi passwords every 90 days.",
                "Monitor connected devices regularly.",
                "Disable SNMP or change default community strings.",
            ]),
        ]
        for priority, items in recs:
            if not items: continue
            col = (255, 80, 80) if priority == "IMMEDIATE" else \
                  (255, 180, 0) if priority == "IMPORTANT" else (100, 220, 100)
            pdf.set_font("Courier", "B", 10)
            pdf.set_text_color(*col)
            pdf.cell(0, 7, f"[{priority}]")
            pdf.ln(7)
            pdf.set_font("Courier", "", 9)
            pdf.set_text_color(200, 200, 200)
            for item in items:
                pdf.cell(8, 6, "", fill=False)
                pdf.cell(0, 6, safe_str(f"  * {item}"))
                pdf.ln(6)
            pdf.ln(2)

        # ── Session log (appendix) ─────────────────────────────────────────────────
        session_log = findings.get("session_log", [])
        if session_log:
            section("Appendix - Session Timeline", color=(100, 100, 200))
            pdf.set_font("Courier", "", 8)
            pdf.set_text_color(170, 170, 170)
            for (key, status, ts, detail) in session_log:
                line = f"[{ts}]  {key:<10}  {status:<10}  {detail}"
                pdf.cell(0, 5, line[:100])
                pdf.ln(5)

        pdf.output(out_path)
        return True, out_path
    except Exception as e:
        return False, f"PDF Generation Error: {str(e)}"
