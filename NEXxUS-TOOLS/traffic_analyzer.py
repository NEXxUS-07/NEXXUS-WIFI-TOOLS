"""
NetVision — Traffic Analyzer Module
Monitors DNS queries, HTTP/HTTPS traffic, and connection destinations.
"""

import threading
import time
import subprocess
import re
import socket
from datetime import datetime
from collections import defaultdict, deque

try:
    from scapy.all import sniff, DNS, DNSQR, IP, TCP, UDP, Raw, conf
    SCAPY_SNIFF_AVAILABLE = True
except ImportError:
    SCAPY_SNIFF_AVAILABLE = False


class TrafficEntry:
    """Represents a single traffic log entry."""

    def __init__(self, timestamp, src_ip, dst_ip, protocol, info, domain=None):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.info = info
        self.domain = domain

    def to_dict(self):
        return {
            "time": self.timestamp.strftime("%H:%M:%S"),
            "src": self.src_ip,
            "dst": self.dst_ip,
            "proto": self.protocol,
            "info": self.info,
            "domain": self.domain,
        }


class TrafficAnalyzer:
    """
    Captures and analyzes network traffic:
    - DNS queries (what domains devices are looking up)
    - HTTP/HTTPS connections (what sites are being visited)
    - Connection tracking (where traffic is going)
    """

    def __init__(self, interface=None, max_entries=500):
        self.interface = interface
        self.max_entries = max_entries
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

        # Traffic log
        self._traffic_log = deque(maxlen=max_entries)

        # Per-device DNS queries: IP -> [domains]
        self._dns_queries = defaultdict(lambda: deque(maxlen=100))

        # Per-device visited domains: IP -> {domain: count}
        self._visited_domains = defaultdict(lambda: defaultdict(int))

        # Per-device connection destinations: IP -> [(dst_ip, dst_port, proto)]
        self._connections = defaultdict(lambda: deque(maxlen=200))

        # Global stats
        self._total_packets = 0
        self._total_dns = 0
        self._total_http = 0
        self._total_https = 0

        # Top domains
        self._global_domains = defaultdict(int)

        # Reverse DNS cache
        self._rdns_cache = {}

    def start(self):
        """Start traffic capture in background thread."""
        self._running = True

        if SCAPY_SNIFF_AVAILABLE:
            self._thread = threading.Thread(
                target=self._capture_scapy, daemon=True
            )
        else:
            self._thread = threading.Thread(
                target=self._capture_tcpdump, daemon=True
            )

        self._thread.start()

    def stop(self):
        """Stop traffic capture."""
        self._running = False

    def _capture_scapy(self):
        """Capture traffic using scapy."""
        try:
            conf.verb = 0
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda p: not self._running,
                filter="udp port 53 or tcp port 80 or tcp port 443 or tcp port 8080",
            )
        except Exception:
            # Fallback to tcpdump
            self._capture_tcpdump()

    def _process_packet(self, packet):
        """Process a captured packet."""
        try:
            self._total_packets += 1

            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                self._process_dns(packet)
            elif packet.haslayer(TCP):
                self._process_tcp(packet)

        except Exception:
            pass

    def _process_dns(self, packet):
        """Process DNS query packet."""
        try:
            if not packet.haslayer(IP):
                return

            src_ip = packet[IP].src
            query_name = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")

            if not query_name or query_name in ("", "."):
                return

            # Filter out noise
            noise_patterns = [
                "arpa", "local", "_tcp", "_udp", "mdns",
                "in-addr", "ip6", "_dns-sd"
            ]
            if any(p in query_name.lower() for p in noise_patterns):
                return

            with self._lock:
                self._dns_queries[src_ip].append(query_name)
                self._visited_domains[src_ip][query_name] += 1
                self._global_domains[query_name] += 1
                self._total_dns += 1

                entry = TrafficEntry(
                    timestamp=datetime.now(),
                    src_ip=src_ip,
                    dst_ip="DNS",
                    protocol="DNS",
                    info=f"Query: {query_name}",
                    domain=query_name,
                )
                self._traffic_log.append(entry)

        except Exception:
            pass

    def _process_tcp(self, packet):
        """Process TCP packet (HTTP/HTTPS connections)."""
        try:
            if not packet.haslayer(IP):
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport

            # HTTPS (TLS)
            if dst_port == 443:
                domain = self._extract_sni(packet) or self._reverse_dns(dst_ip)
                with self._lock:
                    self._total_https += 1
                    if domain:
                        self._visited_domains[src_ip][domain] += 1
                        self._global_domains[domain] += 1

                    self._connections[src_ip].append((dst_ip, dst_port, "HTTPS"))

                    entry = TrafficEntry(
                        timestamp=datetime.now(),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="HTTPS",
                        info=f"→ {domain or dst_ip}:443",
                        domain=domain,
                    )
                    self._traffic_log.append(entry)

            # HTTP
            elif dst_port == 80 or dst_port == 8080:
                domain = self._extract_http_host(packet) or self._reverse_dns(dst_ip)
                with self._lock:
                    self._total_http += 1
                    if domain:
                        self._visited_domains[src_ip][domain] += 1
                        self._global_domains[domain] += 1

                    self._connections[src_ip].append((dst_ip, dst_port, "HTTP"))

                    entry = TrafficEntry(
                        timestamp=datetime.now(),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="HTTP",
                        info=f"→ {domain or dst_ip}:{dst_port}",
                        domain=domain,
                    )
                    self._traffic_log.append(entry)

        except Exception:
            pass

    def _extract_sni(self, packet):
        """Extract Server Name Indication from TLS Client Hello."""
        try:
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                # TLS Client Hello
                if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                    # Parse TLS extensions to find SNI
                    idx = 43  # Skip fixed header
                    if idx < len(payload):
                        session_id_len = payload[idx]
                        idx += 1 + session_id_len

                        if idx + 2 < len(payload):
                            cipher_suites_len = int.from_bytes(payload[idx:idx+2], 'big')
                            idx += 2 + cipher_suites_len

                            if idx < len(payload):
                                compression_len = payload[idx]
                                idx += 1 + compression_len

                                if idx + 2 < len(payload):
                                    extensions_len = int.from_bytes(payload[idx:idx+2], 'big')
                                    idx += 2

                                    ext_end = idx + extensions_len
                                    while idx + 4 < ext_end and idx + 4 < len(payload):
                                        ext_type = int.from_bytes(payload[idx:idx+2], 'big')
                                        ext_len = int.from_bytes(payload[idx+2:idx+4], 'big')
                                        idx += 4

                                        if ext_type == 0:  # SNI
                                            if idx + 5 < len(payload):
                                                name_len = int.from_bytes(payload[idx+3:idx+5], 'big')
                                                if idx + 5 + name_len <= len(payload):
                                                    sni = payload[idx+5:idx+5+name_len].decode('ascii', errors='ignore')
                                                    return sni
                                        idx += ext_len

        except Exception:
            pass
        return None

    def _extract_http_host(self, packet):
        """Extract Host header from HTTP request."""
        try:
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")
                match = re.search(r"Host:\s*([^\r\n]+)", payload, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
        except Exception:
            pass
        return None

    def _reverse_dns(self, ip):
        """Reverse DNS lookup with caching."""
        if ip in self._rdns_cache:
            return self._rdns_cache[ip]

        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self._rdns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            self._rdns_cache[ip] = None
            return None

    def _capture_tcpdump(self):
        """Fallback: capture traffic using tcpdump."""
        try:
            cmd = ["tcpdump", "-l", "-n", "-i", self.interface or "any"]
            cmd += ["-Q", "out"]
            cmd += ["port", "53", "or", "port", "80", "or", "port", "443"]

            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )

            while self._running:
                line = process.stdout.readline()
                if not line:
                    break
                self._parse_tcpdump_line(line.strip())

            process.terminate()
        except (FileNotFoundError, PermissionError):
            # If tcpdump not available, use ss/netstat polling
            self._poll_connections()

    def _parse_tcpdump_line(self, line):
        """Parse a tcpdump output line."""
        try:
            # DNS query
            dns_match = re.search(r"(\d+\.\d+\.\d+\.\d+)\.\d+ > .+: .+ (A|AAAA)\? (.+?)\.", line)
            if dns_match:
                src_ip = dns_match.group(1)
                domain = dns_match.group(3)

                with self._lock:
                    self._dns_queries[src_ip].append(domain)
                    self._visited_domains[src_ip][domain] += 1
                    self._global_domains[domain] += 1
                    self._total_dns += 1

                    entry = TrafficEntry(
                        timestamp=datetime.now(),
                        src_ip=src_ip,
                        dst_ip="DNS",
                        protocol="DNS",
                        info=f"Query: {domain}",
                        domain=domain,
                    )
                    self._traffic_log.append(entry)
                return

            # TCP connection
            tcp_match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)", line
            )
            if tcp_match:
                src_ip = tcp_match.group(1)
                dst_ip = tcp_match.group(3)
                dst_port = int(tcp_match.group(4))

                proto = "TCP"
                if dst_port == 443:
                    proto = "HTTPS"
                    self._total_https += 1
                elif dst_port == 80:
                    proto = "HTTP"
                    self._total_http += 1

                with self._lock:
                    self._connections[src_ip].append((dst_ip, dst_port, proto))
                    self._total_packets += 1

        except Exception:
            pass

    def _poll_connections(self):
        """Fallback: poll active connections using ss command."""
        while self._running:
            try:
                result = subprocess.run(
                    ["ss", "-tunap"],
                    capture_output=True, text=True, timeout=5
                )

                for line in result.stdout.split("\n"):
                    try:
                        parts = line.split()
                        if len(parts) >= 5:
                            local = parts[4]
                            peer = parts[5] if len(parts) > 5 else ""

                            peer_match = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)", peer)
                            local_match = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)", local)

                            if peer_match and local_match:
                                src_ip = local_match.group(1)
                                dst_ip = peer_match.group(1)
                                dst_port = int(peer_match.group(2))

                                proto = "TCP"
                                if dst_port == 443:
                                    proto = "HTTPS"
                                elif dst_port == 80:
                                    proto = "HTTP"
                                elif dst_port == 53:
                                    proto = "DNS"

                                with self._lock:
                                    self._connections[src_ip].append((dst_ip, dst_port, proto))

                    except (ValueError, IndexError):
                        continue

            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

            time.sleep(2)

    # ─── Public API ───────────────────────────────────────────────────

    def get_traffic_log(self, limit=50):
        """Get recent traffic log entries."""
        with self._lock:
            entries = list(self._traffic_log)
            return [e.to_dict() for e in entries[-limit:]]

    def get_device_dns(self, ip, limit=20):
        """Get DNS queries made by a specific device."""
        with self._lock:
            queries = list(self._dns_queries.get(ip, []))
            return queries[-limit:]

    def get_device_domains(self, ip, limit=15):
        """Get visited domains for a device, sorted by frequency."""
        with self._lock:
            domains = dict(self._visited_domains.get(ip, {}))
            sorted_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)
            return sorted_domains[:limit]

    def get_device_connections(self, ip, limit=20):
        """Get recent connections for a device."""
        with self._lock:
            conns = list(self._connections.get(ip, []))
            return conns[-limit:]

    def get_top_domains(self, limit=15):
        """Get globally most visited domains."""
        with self._lock:
            sorted_domains = sorted(
                self._global_domains.items(), key=lambda x: x[1], reverse=True
            )
            return sorted_domains[:limit]

    def get_stats(self):
        """Get traffic statistics."""
        with self._lock:
            return {
                "total_packets": self._total_packets,
                "total_dns": self._total_dns,
                "total_http": self._total_http,
                "total_https": self._total_https,
                "unique_domains": len(self._global_domains),
                "active_devices": len(self._dns_queries),
            }
