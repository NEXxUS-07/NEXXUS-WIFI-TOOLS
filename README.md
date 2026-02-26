# 🛰️ NetVision — WiFi Cyber Arsenal

```
 ███╗   ██╗███████╗████████╗██╗   ██╗██╗███████╗██╗ ██████╗ ███╗   ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██║   ██║██║██╔════╝██║██╔═══██╗████╗  ██║
 ██╔██╗ ██║█████╗     ██║   ██║   ██║██║███████╗██║██║   ██║██╔██╗ ██║
 ██║╚██╗██║██╔══╝     ██║   ╚██╗ ██╔╝██║╚════██║██║██║   ██║██║╚██╗██║
 ██║ ╚████║███████╗   ██║    ╚████╔╝ ██║███████║██║╚██████╔╝██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝     ╚═══╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

A **terminal-based WiFi network intelligence & penetration testing toolkit** that monitors connected devices, captures traffic, intercepts credentials, maps destinations geographically, and provides offensive network capabilities — all in a beautiful, live-updating terminal UI with a hacker/cyberpunk aesthetic.

> ⚠️ **Disclaimer:** This tool is for **educational and authorized security testing purposes only**. Only use on networks you own or have explicit permission to test. Unauthorized network interception is illegal.

---

## ✨ Features

### 🔍 Reconnaissance
| Feature | Description |
|---------|-------------|
| **📡 Device Discovery** | Ultra-fast ARP scan with multi-layer discovery (ARP + ping sweep + system cache + optional nmap) |
| **🔬 Device Fingerprinting** | Identifies device type, OS, browser, and model from User-Agent, mDNS/SSDP, DHCP, and TCP fingerprinting |
| **📶 Bluetooth Scanner** | Scans for nearby Bluetooth devices with device intelligence |
| **⚡ Speed Monitor** | Live per-device and global bandwidth monitoring with sparkline graphs |
| **🌍 Geo Mapping** | ASCII world map + interactive Leaflet.js web map showing traffic destinations |

### 🕵️ Surveillance
| Feature | Description |
|---------|-------------|
| **🕵️ Device Spy** | Full intelligence suite — monitors browsing activity, app usage, and behavior patterns |
| **👀 WiFi Activity Spy** | ARP spoofing-based traffic interception to monitor browsing activity on the network |
| **📊 WiFi Activity Monitor** | Real-time feed of websites visited by devices on the network |
| **🔬 Deep App Intelligence** | Extracts maximum intelligence from encrypted traffic patterns |
| **🔍 Traffic Analyzer** | Real-time DNS queries, HTTP/HTTPS destination tracking, and top domains |

### 🔓 Interception
| Feature | Description |
|---------|-------------|
| **🔑 Credential Sniffer** | Captures HTTP login forms and authentication data |
| **📁 File Tracker** | Detects and logs file downloads across the network |
| **🔒 SSL Strip** | Downgrades HTTPS to HTTP to expose URLs and form data |
| **🔑 MITM Proxy** | Full HTTPS man-in-the-middle with dynamic certificate generation |
| **📹 JS Injector** | Injects JavaScript payloads into HTTP responses |

### ⚔️ Offensive
| Feature | Description |
|---------|-------------|
| **📶 WiFi Jammer** | Multi-channel deauthentication engine |
| **🚫 WiFi Blocker** | Disconnect devices via ARP poisoning or deauth frames |
| **💉 DNS Spoofer** | Intercepts DNS queries and injects fake replies for pharming attacks |
| **🎣 Captive Portal** | Creates fake WiFi login pages to capture credentials |
| **🛡️ Network Control** | Deauth attacks, bandwidth throttling, and site blocking |

### 📊 Reporting & UI
| Feature | Description |
|---------|-------------|
| **🎨 Terminal Dashboard** | Beautiful cyberpunk-themed Rich terminal UI with live updates |
| **🌐 Web Dashboard** | Browser-based UI at `http://localhost:8080` with interactive maps and live feeds |
| **🔔 Alert System** | Real-time alerts for specific sites, keywords, categories, and suspicious activity |
| **💾 Session Recorder** | Saves captures as Wireshark-compatible `.pcap` files with HTML report export |

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
https://github.com/NEXxUS-07/NEXXUS-WIFI-TOOLS
cd NEXXUS-WIFI-TOOLS
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Dashboard

```bash
# Using the launcher script (recommended — auto-creates venv & handles sudo)
./run.sh

# Or run directly
sudo python3 netvision.py

# Device scan only
sudo python3 netvision.py --scan

# Traffic monitor only
sudo python3 netvision.py --traffic

# Geographical map only
sudo python3 netvision.py --map

# Specify WiFi interface
sudo python3 netvision.py -i wlan0
```

---

## 📋 Requirements

- **Python 3.8+**
- **Linux** (uses `/proc` filesystem, ARP, iptables, and raw packet capture)
- **Root/sudo** for full functionality (packet capture, ARP scanning, network manipulation)

### Python Libraries

| Library | Purpose |
|---------|---------|
| `rich` | Terminal UI rendering |
| `scapy` | Packet capture & ARP scanning |
| `psutil` | Network interface statistics |
| `netifaces` | Network interface detection |
| `requests` | IP geolocation API calls |

---

## 🖥️ Dashboard Layout

```
╔═══════════════════════════════════════════════════════════════╗
║ ◉ NetVision  ⏱ 19:30:00  📡 5/8 devices  🌐 wlan0          ║
╠═══════════════════════════╦═══════════════════════════════════╣
║  📡 Connected Devices     ║  🌍 Live Geo Map                 ║
║  ─────────────────────    ║  ░░░░·····░░░░░░░░·····░░░       ║
║  1 192.168.1.101 ● LIVE   ║  ░░░░·····░░░░░░░░·····░░░░      ║
║  2 192.168.1.102 ● LIVE   ║  ·░░░░····░░░░░░░░░····░░░░░     ║
║  3 192.168.1.103 ● LIVE   ║  ···░░░░··░░●░░░░░░░···░░░░░░    ║
║  4 192.168.1.104 ○ OFF    ║  ····░░░··░░░░░░░░░░░··░░░░░     ║
║  ─────────────────────    ║  ·····░░░·░░░░░░●░░░░·░░░░░      ║
║  ⚡ Network Speed Monitor  ║  ● Paris, FR (93.184.216.34)     ║
║  ⬇ Download  1.2 MB/s     ║  ● Tokyo, JP (172.217.14.99)     ║
║  ▁▂▃▄▅▆▇█▇▆▅▄▃▂▁▂▃▄     ╠═══════════════════════════════════╣
║  ⬆ Upload    256 KB/s     ║  🔍 Traffic Monitor              ║
║  ▁▁▂▂▃▃▂▂▁▁▂▃▄▃▂▁▁▂     ║  DNS  → google.com               ║
║                           ║  HTTPS → youtube.com:443          ║
║                           ║  DNS  → api.github.com            ║
╚═══════════════════════════╩═══════════════════════════════════╝
```

---

## 🔧 Configuration

Edit `config.py` to customize:

```python
SCAN_INTERVAL = 5          # How often to scan for devices (seconds)
SPEED_INTERVAL = 2         # Speed measurement interval (seconds)
TRAFFIC_INTERVAL = 1       # Traffic capture interval (seconds)
GEO_CACHE_TTL = 3600       # Cache geolocation for 1 hour
DEFAULT_INTERFACE = None   # Auto-detect if None
```

---

## 📁 Project Structure

```
NetVision/
├── netvision.py            # Main dashboard & entry point
├── scanner.py              # Ultra-fast network device discovery (ARP + ping sweep)
├── speed_monitor.py        # Per-device bandwidth monitoring
├── traffic_analyzer.py     # DNS/HTTP/HTTPS traffic analysis
├── geo_mapper.py           # IP geolocation & ASCII world map
├── device_fingerprint.py   # OS/device/browser fingerprinting
├── device_spy.py           # Full device intelligence suite (16 modules)
├── wifi_spy.py             # ARP spoofing-based WiFi activity spy
├── wifi_monitor.py         # WiFi activity monitoring dashboard
├── deep_app_intel.py       # Encrypted traffic pattern analysis
├── interceptors.py         # Credential sniffer, file tracker, image capture
├── sslstrip.py             # HTTPS → HTTP downgrade attacks
├── mitm_proxy.py           # MITM proxy with dynamic cert generation
├── js_injector.py          # HTTP traffic JS payload injection
├── dns_spoofer.py          # DNS spoofing / pharming engine
├── captive_portal.py       # Captive portal phishing engine
├── wifi_jammer.py          # Multi-channel deauthentication engine
├── wifi_blocker.py         # WiFi device disconnection (ARP + deauth)
├── network_control.py      # Deauth, bandwidth throttle, site blocking
├── bluetooth_scanner.py    # Bluetooth device discovery & intelligence
├── advanced_modules.py     # Deauth monitor, mDNS/SSDP discovery, AI analysis
├── alert_system.py         # Real-time alerts & Telegram notifications
├── session_recorder.py     # PCAP session recorder & HTML report export
├── web_dashboard.py        # Browser-based interactive dashboard
├── config.py               # Configuration settings
├── run.sh                  # Launcher script (auto venv + sudo)
├── requirements.txt        # Python dependencies
├── .gitignore              # Git ignore rules
└── README.md               # This file
```

---

## 🎯 How It Works

1. **Scanner** sends ARP requests + ping sweeps to discover all devices on the local subnet
2. **Speed Monitor** tracks per-interface bandwidth using `/proc/net` and `psutil`
3. **Traffic Analyzer** captures packets (DNS queries, TLS SNI, HTTP Host headers)
4. **Geo Mapper** resolves destination IPs to locations via ip-api.com
5. **WiFi Spy** uses ARP spoofing to redirect traffic through the host for interception
6. **MITM Proxy** generates dynamic SSL certificates to intercept HTTPS traffic
7. **Dashboard** renders everything into a live-updating Rich terminal UI

---

## ⚠️ Important Notes

 **Run with `sudo`** — Packet capture, ARP scanning, and network manipulation require root privileges
 **Rate limits** — The free IP geolocation API has a 45 req/min limit (cached automatically)
 **Legal compliance** — Only use on networks you own or have explicit written permission to test
 **Responsible disclosure** — If you discover vulnerabilities, report them responsibly

---

## 📜 License

This project is for **educational and authorized security testing purposes only**. Use responsibly and only on networks you own or have explicit permission to test. The authors are not responsible for any misuse.
