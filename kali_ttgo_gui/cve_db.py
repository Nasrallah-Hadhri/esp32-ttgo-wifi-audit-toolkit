"""
cve_db.py — Local CVE reference for common router/service ports.
Used by audit_engine.py to enrich PDF reports with real vulnerability data.
"""

CVE_DB = {
    21: {
        "service": "FTP",
        "note": "FTP transmits credentials in PLAINTEXT. Disable immediately.",
        "cves": [
            {"id": "CVE-2011-2523", "desc": "vsftpd 2.3.4 backdoor command shell", "cvss": 10.0, "severity": "CRITICAL"},
            {"id": "CVE-2010-4221", "desc": "ProFTPD SQL injection / stack overflow", "cvss": 10.0, "severity": "CRITICAL"},
        ],
    },
    22: {
        "service": "SSH",
        "note": "Restrict SSH to specific IPs via firewall. Disable password auth.",
        "cves": [
            {"id": "CVE-2023-38408", "desc": "OpenSSH forwarding agent RCE", "cvss": 10.0, "severity": "CRITICAL"},
            {"id": "CVE-2023-48795", "desc": "Terrapin SSH prefix truncation attack", "cvss": 5.9, "severity": "MEDIUM"},
        ],
    },
    23: {
        "service": "Telnet",
        "note": "Telnet sends ALL data including passwords in plaintext. Replace with SSH.",
        "cves": [
            {"id": "CWE-319",       "desc": "Cleartext transmission of sensitive information", "cvss": 9.8, "severity": "CRITICAL"},
            {"id": "CVE-2011-4862", "desc": "Telnet encrypt_keyid() heap overflow", "cvss": 10.0, "severity": "CRITICAL"},
        ],
    },
    80: {
        "service": "HTTP",
        "note": "Admin panel over HTTP. Switch to HTTPS and restrict access by IP.",
        "cves": [
            {"id": "CVE-2022-27255", "desc": "Router HTTP stack buffer overflow RCE", "cvss": 9.8, "severity": "CRITICAL"},
            {"id": "CVE-2021-45382", "desc": "D-Link multiple RCE via HTTP interface", "cvss": 9.8, "severity": "CRITICAL"},
        ],
    },
    443: {
        "service": "HTTPS",
        "note": "Ensure OpenSSL is patched. Disable TLS < 1.2.",
        "cves": [
            {"id": "CVE-2014-0160", "desc": "Heartbleed OpenSSL memory disclosure", "cvss": 7.5, "severity": "HIGH"},
            {"id": "CVE-2021-3449", "desc": "OpenSSL NULL pointer deref DoS", "cvss": 5.9, "severity": "MEDIUM"},
        ],
    },
    161: {
        "service": "SNMP",
        "note": "Change default 'public'/'private' community strings or disable SNMP entirely.",
        "cves": [
            {"id": "CVE-2017-9097", "desc": "SNMP default community string info disclosure", "cvss": 9.8, "severity": "CRITICAL"},
            {"id": "CVE-2002-0013", "desc": "Multiple vendor SNMP DoS / overflow", "cvss": 10.0, "severity": "CRITICAL"},
        ],
    },
    445: {
        "service": "SMB",
        "note": "Disable SMBv1. Apply MS17-010. Never expose SMB to the internet.",
        "cves": [
            {"id": "CVE-2017-0144", "desc": "EternalBlue SMBv1 RCE — exploited by WannaCry", "cvss": 9.3, "severity": "CRITICAL"},
            {"id": "CVE-2020-0796", "desc": "SMBGhost SMBv3 RCE (pre-auth)", "cvss": 10.0, "severity": "CRITICAL"},
        ],
    },
    1900: {
        "service": "UPnP",
        "note": "Disable UPnP on all routers. Not required for standard setups.",
        "cves": [
            {"id": "CVE-2020-12695", "desc": "CallStranger UPnP SSRF / DDoS amplification", "cvss": 7.5, "severity": "HIGH"},
            {"id": "CVE-2019-17621", "desc": "D-Link UPnP daemon unauthenticated RCE", "cvss": 9.8, "severity": "CRITICAL"},
        ],
    },
    3306: {
        "service": "MySQL",
        "note": "Never expose MySQL to the network. Use firewall / bind to 127.0.0.1.",
        "cves": [
            {"id": "CVE-2023-21980", "desc": "Oracle MySQL Cluster RCE", "cvss": 9.8, "severity": "CRITICAL"},
            {"id": "CVE-2012-2122", "desc": "MySQL auth bypass via memcmp timing", "cvss": 5.1, "severity": "MEDIUM"},
        ],
    },
    3389: {
        "service": "RDP",
        "note": "Disable RDP if not needed. Require NLA + VPN. Patch immediately.",
        "cves": [
            {"id": "CVE-2019-0708", "desc": "BlueKeep RDP pre-auth RCE (wormable)", "cvss": 9.8, "severity": "CRITICAL"},
            {"id": "CVE-2019-1182", "desc": "DejaBlue RDP heap overflow RCE", "cvss": 9.8, "severity": "CRITICAL"},
        ],
    },
    7547: {
        "service": "TR-069",
        "note": "Block port 7547 at firewall immediately. ISP management port — high attack surface.",
        "cves": [
            {"id": "CVE-2014-9222", "desc": "Misfortune Cookie — auth bypass / RCE", "cvss": 10.0, "severity": "CRITICAL"},
            {"id": "CVE-2016-10372", "desc": "Mirai botnet TR-069 mass exploitation", "cvss": 10.0, "severity": "CRITICAL"},
        ],
    },
    8080: {
        "service": "HTTP-Alt",
        "note": "Alternative admin HTTP port. Restrict access, switch to HTTPS.",
        "cves": [
            {"id": "CVE-2021-40438", "desc": "Apache mod_proxy SSRF", "cvss": 9.0, "severity": "CRITICAL"},
            {"id": "CVE-2020-1938",  "desc": "AJP Ghostcat arbitrary file read", "cvss": 9.8, "severity": "CRITICAL"},
        ],
    },
    8443: {
        "service": "HTTPS-Alt",
        "note": "Ensure valid certificate and restrict access by source IP.",
        "cves": [
            {"id": "CVE-2021-22986", "desc": "F5 BIG-IP iControl REST unauthenticated RCE", "cvss": 9.8, "severity": "CRITICAL"},
        ],
    },
}


def lookup(port: int) -> dict:
    """Return CVE entry for port, or empty dict."""
    return CVE_DB.get(port, {})


def worst_cvss(port: int) -> float:
    """Return highest CVSS score for a port."""
    entry = CVE_DB.get(port, {})
    cves = entry.get("cves", [])
    return max((c["cvss"] for c in cves), default=0.0)


def calculate_security_score(open_ports: list, live_hosts: int = 0) -> dict:
    """
    Score 0-100. Returns dict with score, grade, label, color.
    Deductions:
      CRITICAL cvss port : -15
      HIGH cvss port     : -10
      MEDIUM cvss port   : -5
      Bonus penalties: Telnet -10 extra, TR-069 -10 extra, UPnP -5 extra
    """
    score = 100
    port_nums = {p["port"] for p in open_ports}

    for p in open_ports:
        w = worst_cvss(p["port"])
        if w >= 9.0:
            score -= 15
        elif w >= 7.0:
            score -= 10
        elif w >= 4.0:
            score -= 5
        else:
            score -= 2

    # Extra penalties for the most dangerous services
    if 23   in port_nums: score -= 10   # Telnet plaintext
    if 7547 in port_nums: score -= 10   # TR-069 wormable
    if 1900 in port_nums: score -= 5    # UPnP amplification
    if 445  in port_nums: score -= 5    # SMB EternalBlue exposure
    if 21   in port_nums: score -= 5    # FTP plaintext

    score = max(0, score)

    if score >= 85:
        grade, label, color = "A", "SECURE",        (0,  200, 100)
    elif score >= 70:
        grade, label, color = "B", "ACCEPTABLE",    (100, 200, 0)
    elif score >= 55:
        grade, label, color = "C", "MODERATE RISK", (255, 200, 0)
    elif score >= 35:
        grade, label, color = "D", "HIGH RISK",     (255, 130, 0)
    else:
        grade, label, color = "F", "CRITICAL RISK", (255, 50,  50)

    return {"score": score, "grade": grade, "label": label, "color": color}
