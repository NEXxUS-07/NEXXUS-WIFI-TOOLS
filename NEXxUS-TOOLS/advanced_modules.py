"""
NetVision — Deauth Monitor, mDNS/SSDP Discovery, AI Analysis
Detects attacks on your network, discovers IoT devices,
and performs AI-powered browsing pattern analysis.
"""

import threading
import time
import re
import socket
import struct
import os
from datetime import datetime
from collections import defaultdict, deque, Counter

try:
    from scapy.all import (
        sniff, Dot11, Dot11Deauth, Dot11Disas, ARP,
        IP, UDP, DNS, DNSQR, DNSRR, Raw, conf
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


# ═══════════════════════════════════════════════════════════════════════
# DEAUTH MONITOR — Detect attacks on YOUR network
# ═══════════════════════════════════════════════════════════════════════

class DeauthMonitor:
    """Monitors for deauthentication/disassociation attacks and ARP spoofing."""

    def __init__(self, interface, gateway_ip=None, gateway_mac=None):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self._running = False
        self._lock = threading.Lock()

        # Detected attacks
        self._attacks = deque(maxlen=200)
        self._deauth_count = 0
        self._arp_spoof_count = 0
        self._suspicious_ips = defaultdict(int)

        # ARP table for spoof detection
        self._arp_table = {}  # IP -> last known MAC

        # Callbacks
        self._alert_callbacks = []

    def start(self):
        """Start monitoring for attacks."""
        self._running = True
        threading.Thread(target=self._monitor_arp, daemon=True).start()

    def stop(self):
        self._running = False

    def on_attack(self, callback):
        """Register callback for detected attacks."""
        self._alert_callbacks.append(callback)

    def _monitor_arp(self):
        """Monitor ARP traffic for spoofing attempts."""
        while self._running:
            try:
                # Read ARP table periodically
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[0]
                            mac = parts[3]
                            if mac == "00:00:00:00:00:00":
                                continue

                            # Check for MAC change (potential ARP spoof)
                            if ip in self._arp_table:
                                old_mac = self._arp_table[ip]
                                if old_mac != mac:
                                    self._arp_spoof_count += 1
                                    attack = {
                                        "time": datetime.now().strftime("%H:%M:%S"),
                                        "type": "ARP_SPOOF",
                                        "severity": "critical",
                                        "details": f"MAC changed for {ip}: {old_mac} → {mac}",
                                        "source_ip": ip,
                                        "old_mac": old_mac,
                                        "new_mac": mac,
                                    }
                                    with self._lock:
                                        self._attacks.append(attack)
                                    self._notify(attack)

                            self._arp_table[ip] = mac

                # Check for gateway MAC spoofing specifically
                if self.gateway_ip and self.gateway_mac:
                    current_gw_mac = self._arp_table.get(self.gateway_ip)
                    if current_gw_mac and current_gw_mac != self.gateway_mac:
                        attack = {
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "type": "GATEWAY_SPOOF",
                            "severity": "critical",
                            "details": f"GATEWAY {self.gateway_ip} MAC spoofed: "
                                       f"expect {self.gateway_mac}, got {current_gw_mac}",
                            "source_ip": self.gateway_ip,
                        }
                        with self._lock:
                            self._attacks.append(attack)
                        self._notify(attack)

            except Exception:
                pass

            time.sleep(5)

    def check_deauth_packet(self, packet):
        """Check a raw WiFi frame for deauth/disassociation."""
        try:
            if packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas):
                self._deauth_count += 1
                src = packet[Dot11].addr2 if packet.haslayer(Dot11) else "?"
                dst = packet[Dot11].addr1 if packet.haslayer(Dot11) else "?"

                attack = {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "type": "DEAUTH",
                    "severity": "high",
                    "details": f"Deauth from {src} → {dst}",
                    "source_mac": src,
                    "target_mac": dst,
                }

                with self._lock:
                    self._attacks.append(attack)
                self._notify(attack)
        except Exception:
            pass

    def _notify(self, attack):
        for cb in self._alert_callbacks:
            try:
                cb(attack)
            except Exception:
                pass

    def get_attacks(self, limit=30):
        with self._lock:
            return list(self._attacks)[-limit:]

    def get_stats(self):
        return {
            "deauth_count": self._deauth_count,
            "arp_spoof_count": self._arp_spoof_count,
            "total_attacks": len(self._attacks),
            "arp_table_size": len(self._arp_table),
        }


# ═══════════════════════════════════════════════════════════════════════
# MDNS / SSDP DEVICE DISCOVERY — Find IoT devices
# ═══════════════════════════════════════════════════════════════════════

class DeviceDiscovery:
    """Discovers devices on the network via mDNS, SSDP, and DHCP sniffing."""

    def __init__(self):
        self._devices = {}  # IP -> device info
        self._mdns_services = deque(maxlen=500)
        self._ssdp_devices = deque(maxlen=200)
        self._lock = threading.Lock()
        self._running = False

        # Known IoT signatures
        self._iot_signatures = {
            "chromecast": {"brand": "Google", "type": "Media Player"},
            "googlecast": {"brand": "Google", "type": "Media Player"},
            "google-home": {"brand": "Google", "type": "Smart Speaker"},
            "alexa": {"brand": "Amazon", "type": "Smart Speaker"},
            "echo": {"brand": "Amazon", "type": "Smart Speaker"},
            "fire": {"brand": "Amazon", "type": "Streaming"},
            "roku": {"brand": "Roku", "type": "Media Player"},
            "appletv": {"brand": "Apple", "type": "Media Player"},
            "homekit": {"brand": "Apple", "type": "Smart Home"},
            "hue": {"brand": "Philips", "type": "Smart Light"},
            "sonos": {"brand": "Sonos", "type": "Speaker"},
            "nest": {"brand": "Google", "type": "Smart Home"},
            "ring": {"brand": "Amazon", "type": "Security Camera"},
            "wyze": {"brand": "Wyze", "type": "Security Camera"},
            "tplink": {"brand": "TP-Link", "type": "Smart Plug"},
            "tuya": {"brand": "Tuya", "type": "Smart Device"},
            "shelly": {"brand": "Shelly", "type": "Smart Switch"},
            "printer": {"brand": None, "type": "Printer"},
            "ipp": {"brand": None, "type": "Printer"},
            "airplay": {"brand": "Apple", "type": "AirPlay Device"},
            "raop": {"brand": "Apple", "type": "AirPlay Speaker"},
            "spotify": {"brand": None, "type": "Music Player"},
            "samsung": {"brand": "Samsung", "type": "Smart TV"},
            "lg": {"brand": "LG", "type": "Smart TV"},
            "xbox": {"brand": "Microsoft", "type": "Game Console"},
            "playstation": {"brand": "Sony", "type": "Game Console"},
            "nintendo": {"brand": "Nintendo", "type": "Game Console"},
        }

    def start(self):
        """Start passive device discovery."""
        self._running = True
        threading.Thread(target=self._ssdp_discover, daemon=True).start()

    def stop(self):
        self._running = False

    def process_mdns_packet(self, packet):
        """Process an mDNS packet for device discovery."""
        try:
            if not packet.haslayer(DNS):
                return

            src_ip = packet[IP].src if packet.haslayer(IP) else None
            if not src_ip:
                return

            # Process mDNS queries and responses
            if packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                if qname and len(qname) > 3:
                    self._process_mdns_name(src_ip, qname, "query")

            if packet.haslayer(DNSRR):
                try:
                    for i in range(packet[DNS].ancount):
                        rr = packet[DNSRR]
                        if hasattr(rr, 'rrname'):
                            name = rr.rrname.decode("utf-8", errors="ignore").rstrip(".")
                            self._process_mdns_name(src_ip, name, "response")
                except Exception:
                    pass

        except Exception:
            pass

    def _process_mdns_name(self, ip, name, source):
        """Extract device info from mDNS name."""
        name_lower = name.lower()

        with self._lock:
            if ip not in self._devices:
                self._devices[ip] = {
                    "ip": ip,
                    "hostname": "",
                    "brand": "",
                    "type": "Unknown",
                    "services": [],
                    "first_seen": datetime.now().strftime("%H:%M:%S"),
                    "is_iot": False,
                }

            device = self._devices[ip]

            # Check IoT signatures
            for keyword, info in self._iot_signatures.items():
                if keyword in name_lower:
                    if info["brand"]:
                        device["brand"] = info["brand"]
                    device["type"] = info["type"]
                    device["is_iot"] = True
                    break

            # Extract service type
            if "_tcp" in name_lower or "_udp" in name_lower:
                service = name.split("._")[0] if "._" in name else name
                if service not in device["services"]:
                    device["services"].append(service)

            # Extract hostname
            if "._" not in name and ".local" in name_lower:
                hostname = name.replace(".local", "")
                if hostname and len(hostname) > 1:
                    device["hostname"] = hostname

            self._mdns_services.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "ip": ip,
                "name": name,
                "source": source,
            })

    def _ssdp_discover(self):
        """Send SSDP M-SEARCH to discover UPnP devices."""
        while self._running:
            try:
                msg = (
                    "M-SEARCH * HTTP/1.1\r\n"
                    "HOST: 239.255.255.250:1900\r\n"
                    "MAN: \"ssdp:discover\"\r\n"
                    "MX: 3\r\n"
                    "ST: ssdp:all\r\n"
                    "\r\n"
                )

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(msg.encode(), ("239.255.255.250", 1900))

                try:
                    while True:
                        data, addr = sock.recvfrom(4096)
                        response = data.decode("utf-8", errors="ignore")
                        self._process_ssdp_response(addr[0], response)
                except socket.timeout:
                    pass

                sock.close()
            except Exception:
                pass

            time.sleep(60)  # Discover every 60s

    def _process_ssdp_response(self, ip, response):
        """Parse SSDP response for device info."""
        with self._lock:
            if ip not in self._devices:
                self._devices[ip] = {
                    "ip": ip,
                    "hostname": "",
                    "brand": "",
                    "type": "Unknown",
                    "services": [],
                    "first_seen": datetime.now().strftime("%H:%M:%S"),
                    "is_iot": False,
                }

            device = self._devices[ip]

            # Extract server
            server_match = re.search(r"SERVER:\s*([^\r\n]+)", response, re.IGNORECASE)
            if server_match:
                server = server_match.group(1).strip()
                device["services"].append(f"UPnP: {server[:40]}")

                server_lower = server.lower()
                for keyword, info in self._iot_signatures.items():
                    if keyword in server_lower:
                        if info["brand"]:
                            device["brand"] = info["brand"]
                        device["type"] = info["type"]
                        device["is_iot"] = True
                        break

            self._ssdp_devices.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "ip": ip,
                "response": response[:200],
            })

    def get_devices(self):
        with self._lock:
            return dict(self._devices)

    def get_iot_devices(self):
        with self._lock:
            return {ip: d for ip, d in self._devices.items() if d.get("is_iot")}

    def get_services(self, limit=50):
        with self._lock:
            return list(self._mdns_services)[-limit:]


# ═══════════════════════════════════════════════════════════════════════
# AI-POWERED ANALYSIS — Pattern detection & behavioral profiling
# ═══════════════════════════════════════════════════════════════════════

class BrowsingAnalyzer:
    """Analyzes browsing patterns and generates behavioral profiles."""

    def __init__(self):
        self._lock = threading.Lock()
        self._device_activity = defaultdict(lambda: {
            "domains": Counter(),
            "categories": Counter(),
            "hourly_activity": defaultdict(int),
            "search_topics": [],
            "session_durations": [],
            "first_seen": None,
            "last_seen": None,
        })

        # Domain categorization
        self._categories = {
            "Social Media": [
                "facebook", "instagram", "twitter", "x.com", "tiktok",
                "snapchat", "linkedin", "reddit", "pinterest", "tumblr",
            ],
            "Video/Streaming": [
                "youtube", "netflix", "hulu", "disney", "amazon.com/gp/video",
                "twitch", "vimeo", "dailymotion", "crunchyroll", "hotstar",
            ],
            "News": [
                "cnn", "bbc", "reuters", "nytimes", "foxnews",
                "washingtonpost", "theguardian", "huffpost",
            ],
            "Shopping": [
                "amazon", "ebay", "walmart", "target", "etsy",
                "aliexpress", "wish", "flipkart", "myntra",
            ],
            "Music": [
                "spotify", "apple.com/music", "soundcloud",
                "pandora", "tidal", "deezer", "gaana", "jiosaavn",
            ],
            "Gaming": [
                "steam", "epicgames", "roblox", "minecraft",
                "playstation", "xbox", "nintendo", "itch.io",
            ],
            "Education": [
                "edu", "coursera", "udemy", "khan", "duolingo",
                "quizlet", "chegg", "brainly", "wikipedia",
            ],
            "Productivity": [
                "google.com/docs", "office.com", "notion", "trello",
                "slack", "zoom", "teams", "figma", "github",
            ],
            "Finance": [
                "paypal", "bank", "chase", "wells", "venmo",
                "crypto", "coinbase", "binance", "robinhood",
            ],
            "Adult": [
                "pornhub", "xvideos", "xnxx", "xhamster",
                "onlyfans", "chaturbate", "redtube",
            ],
            "VPN/Privacy": [
                "nordvpn", "expressvpn", "protonvpn", "torproject",
                "mullvad", "surfshark", "protonmail",
            ],
            "Food/Delivery": [
                "doordash", "ubereats", "grubhub", "zomato",
                "swiggy", "instacart", "postmates",
            ],
            "Dating": [
                "tinder", "bumble", "hinge", "match.com",
                "okcupid", "grindr", "badoo",
            ],
            "Health": [
                "webmd", "mayoclinic", "healthline",
                "fitbit", "myfitnesspal", "strava",
            ],
            "Travel": [
                "booking.com", "airbnb", "expedia", "kayak",
                "tripadvisor", "hotels.com", "skyscanner",
            ],
        }

    def feed_activity(self, device_ip, domain, url="", search_query=""):
        """Feed browsing activity for analysis."""
        with self._lock:
            data = self._device_activity[device_ip]
            now = datetime.now()

            if not data["first_seen"]:
                data["first_seen"] = now
            data["last_seen"] = now

            # Count domain
            data["domains"][domain] += 1

            # Categorize
            category = self._categorize(domain, url)
            if category:
                data["categories"][category] += 1

            # Track hourly activity
            data["hourly_activity"][now.hour] += 1

            # Track search topics
            if search_query:
                data["search_topics"].append({
                    "time": now.strftime("%H:%M"),
                    "query": search_query,
                    "topic": self._classify_search(search_query),
                })

    def _categorize(self, domain, url=""):
        """Categorize a domain."""
        domain_lower = domain.lower()
        for category, keywords in self._categories.items():
            for keyword in keywords:
                if keyword in domain_lower:
                    return category
        return "Other"

    def _classify_search(self, query):
        """Classify a search query topic."""
        q = query.lower()
        topics = {
            "tech": ["phone", "laptop", "computer", "software", "app", "code", "python"],
            "shopping": ["buy", "price", "cheap", "deal", "sale", "discount", "review"],
            "entertainment": ["movie", "show", "series", "song", "game", "funny", "meme"],
            "education": ["how to", "tutorial", "course", "learn", "study", "exam"],
            "health": ["symptom", "pain", "doctor", "medicine", "diet", "workout"],
            "travel": ["flight", "hotel", "trip", "vacation", "travel", "ticket"],
            "food": ["recipe", "restaurant", "food", "cook", "order", "delivery"],
            "news": ["news", "election", "politics", "war", "economy"],
            "adult": ["porn", "sex", "nude", "xxx"],
        }

        for topic, keywords in topics.items():
            if any(kw in q for kw in keywords):
                return topic
        return "general"

    def get_profile(self, device_ip):
        """Generate a behavioral profile for a device."""
        with self._lock:
            data = self._device_activity.get(device_ip)
            if not data:
                return None

            # Top categories
            top_categories = data["categories"].most_common(5)

            # Top domains
            top_domains = data["domains"].most_common(10)

            # Peak hours
            if data["hourly_activity"]:
                peak_hour = max(data["hourly_activity"], key=data["hourly_activity"].get)
                peak_label = f"{peak_hour:02d}:00-{(peak_hour+1)%24:02d}:00"
            else:
                peak_label = "Unknown"

            # Generate summary
            summary_parts = []
            if top_categories:
                primary = top_categories[0][0]
                if primary == "Social Media":
                    summary_parts.append("Active social media user")
                elif primary == "Video/Streaming":
                    summary_parts.append("Heavy media consumer")
                elif primary == "Shopping":
                    summary_parts.append("Online shopper")
                elif primary == "Gaming":
                    summary_parts.append("Gamer")
                elif primary == "Education":
                    summary_parts.append("Student/learner")
                elif primary == "Adult":
                    summary_parts.append("⚠ Adult content user")
                elif primary == "Productivity":
                    summary_parts.append("Work/professional user")
                else:
                    summary_parts.append(f"Primarily browses {primary}")

            # Search interests
            search_topics = Counter(
                s["topic"] for s in data["search_topics"]
            ).most_common(3)
            if search_topics:
                interests = ", ".join(t[0] for t in search_topics)
                summary_parts.append(f"Interested in: {interests}")

            # Activity pattern
            total = sum(data["hourly_activity"].values())
            if total > 0:
                night = sum(data["hourly_activity"].get(h, 0) for h in range(0, 6))
                if night / max(total, 1) > 0.3:
                    summary_parts.append("Night owl browsing pattern")

            return {
                "device_ip": device_ip,
                "summary": ". ".join(summary_parts) if summary_parts else "Insufficient data",
                "top_categories": [{"name": c, "count": n} for c, n in top_categories],
                "top_domains": [{"domain": d, "count": n} for d, n in top_domains],
                "peak_activity": peak_label,
                "total_domains": len(data["domains"]),
                "total_activity": sum(data["domains"].values()),
                "search_count": len(data["search_topics"]),
                "recent_searches": data["search_topics"][-5:],
                "first_seen": data["first_seen"].strftime("%H:%M:%S") if data["first_seen"] else None,
                "last_seen": data["last_seen"].strftime("%H:%M:%S") if data["last_seen"] else None,
            }

    def get_all_profiles(self):
        with self._lock:
            return {ip: self.get_profile(ip) for ip in self._device_activity}

    def get_anomalies(self, device_ip):
        """Detect anomalous behavior for a device."""
        with self._lock:
            data = self._device_activity.get(device_ip)
            if not data:
                return []

            anomalies = []

            # Unusual category usage
            if data["categories"]["Adult"] > 0:
                anomalies.append({
                    "type": "content_warning",
                    "severity": "high",
                    "message": f"Adult content detected ({data['categories']['Adult']} visits)",
                })

            if data["categories"]["VPN/Privacy"] > 5:
                anomalies.append({
                    "type": "privacy_tools",
                    "severity": "medium",
                    "message": "Heavy VPN/privacy tool usage detected",
                })

            # Late night activity
            total = sum(data["hourly_activity"].values())
            if total > 0:
                late_night = sum(data["hourly_activity"].get(h, 0) for h in [0, 1, 2, 3, 4])
                if late_night > total * 0.4:
                    anomalies.append({
                        "type": "unusual_hours",
                        "severity": "low",
                        "message": f"High activity during late night hours ({late_night} events)",
                    })

            # Sudden burst of activity
            if data["domains"]:
                avg_per_domain = sum(data["domains"].values()) / len(data["domains"])
                burst_domains = [
                    d for d, c in data["domains"].items()
                    if c > avg_per_domain * 5 and c > 10
                ]
                if burst_domains:
                    anomalies.append({
                        "type": "activity_burst",
                        "severity": "low",
                        "message": f"Unusually high activity on: {', '.join(burst_domains[:3])}",
                    })

            return anomalies
