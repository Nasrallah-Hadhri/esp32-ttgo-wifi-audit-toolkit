# ESP32 TTGO WiFi Audit Toolkit

> A WiFi security auditing toolkit pairing custom **ESP32 (TTGO)** firmware with
> Python desktop dashboards on Kali Linux: 802.11 reconnaissance, EAPOL/PMKID
> capture, rogue-AP and deauthentication testing, router port/CVE auditing, and
> automated PDF reporting.

## Overview

This toolkit performs WiFi security assessments from two complementary angles:

- An **ESP32 TTGO** board running custom ESP-IDF firmware acts as a portable 802.11
  node, driven over USB serial with a simple `CMD:` protocol and showing status on its
  on-board SSD1306 OLED. It can scan networks, sniff EAPOL frames, hunt PMKIDs, raise a
  rogue/evil-twin AP, send deauthentication frames, and audit a router it connects to.
- **Kali-side Python GUIs** drive the board and/or the host's own wireless stack,
  parse results, enrich them with a local CVE reference database, write PCAP captures,
  and export professional PDF audit reports.

Three front-ends are included, from a minimal serial console to a full audit suite.

## Components

### ESP32 TTGO firmware (`kali_ttgo_gui/esp32_firmware/`)
ESP-IDF (C) project for the ESP32. Exposes over serial:

- `CMD:SCAN` — 802.11 reconnaissance (SSID/BSSID/channel/RSSI/auth)
- `CMD:SNIFF_START:<ch>` / `CMD:SNIFF_STOP` — promiscuous EAPOL capture
- `CMD:PMKID_HUNT:<ch>` / `CMD:PMKID_STOP` — passive PMKID (EAPOL M1) capture
- `CMD:ROGUE:<ssid>` / `CMD:ROGUE_STOP` — rogue / evil-twin SoftAP
- `CMD:DEAUTH:<bssid>:<ch>` (plus continuous and targeted-client variants)
- `CMD:AUDIT:<ssid>:<pass>` — connect to a router and port/subnet audit
- `CMD:SCAN_DEVICE:<ip>` — single-host port scan

Source: `main/main.c` (serial command loop + OLED), `main/wifi_attacks.c/.h`
(802.11 logic), `main/ssd1306.c/.h` (OLED driver).

### `kali_ttgo_gui/` — full audit suite (recommended)
The flagship dashboard (`customtkinter`). Drives the TTGO over serial **and** runs a
host-side audit engine on Kali:

- `audit_engine.py` — gateway detection, port scanning and subnet host discovery from
  Kali's own network stack (no board required)
- `cve_db.py` — local CVE reference table mapping common router/service ports to known
  vulnerabilities, used to enrich reports
- `serial_client.py` — threaded serial link to the ESP32
- built-in PCAP writer (raw IEEE 802.11, linktype 105) and PDF report export (`fpdf2`)

### `kali_gui/` — Kali aircrack-ng dashboard
A host-only dashboard (`backend.py` + `main.py`) that wraps the **aircrack-ng suite**:
monitor-mode toggling (`airmon-ng`), scanning and handshake capture (`airodump-ng`),
deauth (`aireplay-ng`), WPA cracking against a wordlist (`aircrack-ng`), and WPS
discovery (`wash`/`reaver`). Requires a monitor-mode-capable USB WiFi adapter.

### `python_gui/` — minimal serial console
An early, lightweight GUI that connects to the ESP32 over serial and issues the
`CMD:` commands directly. Useful for testing the firmware without the full suite.

## Tech stack

- **Firmware:** C, ESP-IDF (ESP32 / TTGO), SSD1306 OLED over I²C
- **Host:** Python 3, `customtkinter`, `pyserial`, `scapy`, `fpdf2`
- **Kali tooling (kali_gui):** aircrack-ng, reaver, wash

## Hardware

- ESP32 TTGO board (ESP32 target, 2 MB flash per `sdkconfig`) with on-board SSD1306 OLED
- USB cable (serial at 115200 baud)
- For `kali_gui`: a USB WiFi adapter that supports monitor mode and packet injection

## Project structure

```
.
├── kali_ttgo_gui/              # full suite: TTGO control + Kali audit engine
│   ├── main.py                   # dashboard, PCAP writer, PDF export
│   ├── audit_engine.py           # host-side port/subnet auditing
│   ├── cve_db.py                 # local CVE reference database
│   ├── serial_client.py
│   ├── requirements.txt
│   └── esp32_firmware/           # ESP-IDF firmware for the ESP32 TTGO
│       ├── CMakeLists.txt
│       ├── sdkconfig
│       └── main/{main.c, wifi_attacks.c/.h, ssd1306.c/.h, CMakeLists.txt}
├── kali_gui/                   # aircrack-ng based Kali dashboard
│   ├── main.py, backend.py, install_kali.sh
├── python_gui/                 # minimal ESP32 serial console
│   ├── main.py, serial_client.py, requirements.txt
```

## Getting started

### Build & flash the ESP32 firmware

Requires the [ESP-IDF](https://docs.espressif.com/projects/esp-idf/) toolchain.

```bash
cd kali_ttgo_gui/esp32_firmware
idf.py set-target esp32
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

The board prints `RES:READY` over serial and shows its status on the OLED.

### Run the full suite (Kali)

```bash
cd kali_ttgo_gui
pip install -r requirements.txt        # pyserial customtkinter scapy fpdf2
sudo python3 main.py
```

Select the board's serial port, connect, and use the dashboard to scan, capture and
generate reports.

### Run the aircrack-ng dashboard (Kali)

```bash
cd kali_gui
sudo bash install_kali.sh              # aircrack-ng, reaver, pciutils, customtkinter
sudo python3 main.py
```

Plug in a monitor-mode-capable USB WiFi adapter first.

### Run the minimal console

```bash
cd python_gui
pip install -r requirements.txt        # pyserial customtkinter
python3 main.py
```

## Responsible use / legal notice

**This toolkit is for authorised security testing and education only.** Deauthentication,
rogue/evil-twin APs, handshake/PMKID capture and WPA cracking are intrusive operations.
Only use them on **networks and devices you own or have explicit written permission to
test**. Transmitting deauthentication frames and operating rogue access points is
illegal in many jurisdictions and can disrupt other users. Before any test, agree a
scope with the network owner listing the authorised SSIDs and the test window. The authors accept
no liability for misuse.

## Academic context

Developed as a cybersecurity project at **TEKUP University** (Tunisia), ING5 SSIR
(Security of Systems, Information and Networks) track.

## Author

- **Nasrallah Hadhri** — [github.com/Nasrallah-Hadhri](https://github.com/Nasrallah-Hadhri)

Developed as a team project at TEKUP.

## License

Released under the [MIT License](LICENSE).
