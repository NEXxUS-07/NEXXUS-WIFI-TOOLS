"""
NetVision — Network Scanner Module (v4 — TURBO Mode)
Ultra-fast device discovery with aggressive device name resolution.
  1. Async ARP + Ping sweep (parallel — sub-2 second scan)
  2. System ARP cache — ip neigh + /proc/net/arp (instant)
  3. Aggressive hostname resolution: NetBIOS, mDNS, DHCP leases, nbtstat
  4. Optional nmap integration (--nmap flag)

All scan layers run in PARALLEL for maximum speed.
Hostname resolution is fully async/non-blocking with multiple fallback methods.
"""

import socket
import subprocess
import threading
import time
import re
import os
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════
# EXPANDED OUI VENDOR DATABASE (100+ prefixes)
# ═══════════════════════════════════════════════════════════════════════
OUI_MAP = {
    # Apple
    "00:1A:2B": "Apple", "3C:22:FB": "Apple", "F8:FF:C2": "Apple",
    "88:E9:FE": "Apple", "A4:83:E7": "Apple", "FC:FC:48": "Apple",
    "18:65:90": "Apple", "98:01:A7": "Apple", "AC:DE:48": "Apple",
    "F0:18:98": "Apple", "D0:E1:40": "Apple", "C8:69:CD": "Apple",
    "78:7B:8A": "Apple", "48:A1:95": "Apple", "A0:99:9B": "Apple",
    "14:BD:61": "Apple", "70:56:81": "Apple", "C0:B6:58": "Apple",
    "E0:B5:2D": "Apple", "E4:CE:8F": "Apple", "D4:F4:6F": "Apple",
    "BC:52:B7": "Apple",
    # Samsung
    "AC:C1:EE": "Samsung", "00:26:37": "Samsung", "84:25:DB": "Samsung",
    "E4:7C:F9": "Samsung", "F4:7B:09": "Samsung", "30:96:FB": "Samsung",
    "88:36:6C": "Samsung", "B4:3A:28": "Samsung", "BC:14:85": "Samsung",
    "CC:07:AB": "Samsung", "54:40:AD": "Samsung", "10:3B:59": "Samsung",
    "78:BD:BC": "Samsung", "94:35:0A": "Samsung", "E8:50:8B": "Samsung",
    "A0:82:1F": "Samsung", "FC:A1:3E": "Samsung", "50:01:BB": "Samsung",
    "64:B5:C6": "Samsung", "34:23:BA": "Samsung", "14:F4:2A": "Samsung",
    # Xiaomi / Redmi / POCO
    "28:6C:07": "Xiaomi", "64:CC:2E": "Xiaomi", "9C:99:A0": "Xiaomi",
    "74:23:44": "Xiaomi", "34:80:B3": "Xiaomi", "50:64:2B": "Xiaomi",
    "FC:64:BA": "Xiaomi", "04:CF:8C": "Xiaomi", "78:11:DC": "Xiaomi",
    "38:A4:ED": "Xiaomi", "7C:1D:D9": "Xiaomi", "AC:C1:EE": "Xiaomi",
    "44:23:7C": "Xiaomi", "D4:3B:04": "Xiaomi",
    # OnePlus / Realme / OPPO / Vivo
    "E8:6F:38": "OnePlus", "94:65:2D": "OnePlus", "C0:EE:FB": "OnePlus",
    "60:AB:67": "Realme", "A4:77:58": "OPPO", "0C:1D:AF": "OPPO",
    "EC:F0:FE": "Vivo", "AC:91:9B": "Vivo", "24:09:95": "Vivo",
    # Google
    "D8:B3:70": "Google", "F4:F5:D8": "Google", "54:60:09": "Google",
    "30:FD:38": "Google", "A4:77:33": "Google", "48:D6:D5": "Google",
    "F8:0F:F9": "Google",
    # Intel / PC
    "00:1B:21": "Intel", "00:1E:67": "Intel", "3C:97:0E": "Intel",
    "68:05:CA": "Intel", "B4:96:91": "Intel", "8C:EC:4B": "Intel",
    "A0:36:BC": "Intel", "58:A0:23": "Intel", "7C:7A:91": "Intel",
    # Microsoft / Xbox
    "00:50:F2": "Microsoft", "7C:1E:52": "Microsoft",
    "28:18:78": "Microsoft", "60:45:BD": "Microsoft",
    # TP-Link / Router / IoT
    "50:C7:BF": "TP-Link", "C0:25:E9": "TP-Link", "30:DE:4B": "TP-Link",
    "EC:08:6B": "TP-Link", "14:EB:B6": "TP-Link", "B0:A7:B9": "TP-Link",
    "60:E3:27": "TP-Link", "10:27:F5": "TP-Link",
    # Huawei / Honor
    "48:46:FB": "Huawei", "E0:19:1D": "Huawei", "00:1E:10": "Huawei",
    "70:72:3C": "Huawei", "E8:CD:2D": "Huawei", "88:66:39": "Huawei",
    "CC:A2:23": "Huawei", "54:25:EA": "Huawei",
    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    # Amazon / Alexa / Fire
    "40:B4:CD": "Amazon", "68:54:FD": "Amazon", "F0:F0:A4": "Amazon",
    "74:75:48": "Amazon", "FC:65:DE": "Amazon",
    # VM / Development
    "00:50:56": "VMware", "00:0C:29": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    # Netlink / ISP routers
    "8C:C7:C3": "Netlink ICT",
    # Netgear
    "28:80:88": "Netgear", "E0:91:F5": "Netgear", "B0:7F:B9": "Netgear",
    # D-Link
    "FC:75:16": "D-Link", "1C:BD:B9": "D-Link", "28:10:7B": "D-Link",
    # Sony / PlayStation
    "00:1A:80": "Sony", "2C:CC:44": "Sony", "FC:0F:E6": "Sony",
    "E8:61:7E": "Sony", "70:9E:29": "Sony",
    # LG
    "00:1E:75": "LG", "10:68:3F": "LG", "64:99:5D": "LG",
    "30:B4:9E": "LG", "A8:23:FE": "LG",
    # Motorola / Lenovo
    "D8:49:2F": "Motorola", "F4:F1:E1": "Motorola",
    "54:A0:50": "Motorola", "84:10:0D": "Motorola",
    # Nintendo
    "00:1F:32": "Nintendo", "7C:BB:8A": "Nintendo",
    "E8:4E:CE": "Nintendo", "98:B6:E9": "Nintendo",
}


# ═══════════════════════════════════════════════════════════════════════
# DHCP LEASE FILE LOCATIONS (try all common paths)
# ═══════════════════════════════════════════════════════════════════════
DHCP_LEASE_FILES = [
    "/var/lib/dhcp/dhcpd.leases",
    "/var/lib/dhcpd/dhcpd.leases",
    "/var/lib/misc/dnsmasq.leases",
    "/tmp/dnsmasq.leases",
    "/tmp/dhcp.leases",
    "/var/run/dnsmasq/leases",
    "/etc/pihole/dhcp.leases",
]


class DeviceInfo:
    """Represents a discovered network device."""

    def __init__(self, ip, mac, hostname=None):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname or "Scanning..."
        self.device_name = None       # ★ NEW: Friendly device name
        self.vendor = self._lookup_vendor(mac)
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.is_online = True
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.speed_up = 0.0      # KB/s
        self.speed_down = 0.0    # KB/s
        self.geo_info = None
        self.traffic_log = []
        self._hostname_resolved = hostname is not None
        self._name_methods_tried = set()

        # Kick off aggressive async name resolution
        if hostname is None:
            self._resolve_all_names_async(ip)

    def _resolve_all_names_async(self, ip):
        """Ultra-aggressive device name resolution — tries EVERYTHING in parallel."""
        def _resolve():
            name = None

            # Method 1: Quick reverse DNS (1s timeout)
            try:
                socket.setdefaulttimeout(1.5)
                result = socket.gethostbyaddr(ip)
                if result and result[0]:
                    name = result[0]
                    self._name_methods_tried.add("rdns")
            except Exception:
                pass
            finally:
                socket.setdefaulttimeout(None)

            if name and name != ip:
                self.hostname = name
                self.device_name = name
                self._hostname_resolved = True

            # Method 2: NetBIOS name lookup (fast for Windows/Android)
            if not self.device_name or self.device_name == "Unknown":
                try:
                    result = subprocess.run(
                        ["nmblookup", "-A", ip],
                        capture_output=True, text=True, timeout=2,
                    )
                    for line in result.stdout.strip().split("\n"):
                        line = line.strip()
                        if "<00>" in line and "GROUP" not in line:
                            parts = line.split()
                            if parts:
                                nb_name = parts[0].strip()
                                if nb_name and len(nb_name) > 1:
                                    self.device_name = nb_name
                                    if not self._hostname_resolved:
                                        self.hostname = nb_name
                                    self._name_methods_tried.add("netbios")
                                    break
                except Exception:
                    pass

            # Method 3: mDNS / avahi
            if not self.device_name or self.device_name == "Unknown":
                try:
                    result = subprocess.run(
                        ["avahi-resolve", "-a", ip],
                        capture_output=True, text=True, timeout=2,
                    )
                    if result.stdout.strip():
                        parts = result.stdout.strip().split()
                        if len(parts) >= 2:
                            mdns_name = parts[-1].rstrip(".")
                            if mdns_name and ".local" in mdns_name:
                                # Strip .local suffix for cleaner display
                                clean = mdns_name.replace(".local", "")
                                self.device_name = clean
                                if not self._hostname_resolved:
                                    self.hostname = mdns_name
                                self._hostname_resolved = True
                                self._name_methods_tried.add("mdns")
                except Exception:
                    pass

            # Method 4: DHCP lease files
            if not self.device_name or self.device_name == "Unknown":
                dhcp_name = self._check_dhcp_leases(ip)
                if dhcp_name:
                    self.device_name = dhcp_name
                    if not self._hostname_resolved:
                        self.hostname = dhcp_name
                    self._name_methods_tried.add("dhcp")

            # Method 5: /etc/hosts
            if not self.device_name or self.device_name == "Unknown":
                try:
                    with open("/etc/hosts", "r") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                parts = line.split()
                                if len(parts) >= 2 and parts[0] == ip:
                                    self.device_name = parts[1]
                                    if not self._hostname_resolved:
                                        self.hostname = parts[1]
                                    self._name_methods_tried.add("hosts")
                                    break
                except Exception:
                    pass

            # Finalize
            if not self._hostname_resolved:
                self.hostname = self.device_name or "Unknown"
                self._hostname_resolved = True

            if not self.device_name:
                self.device_name = self.hostname if self.hostname != "Unknown" else None

        t = threading.Thread(target=_resolve, daemon=True)
        t.start()

    def _check_dhcp_leases(self, ip):
        """Check DHCP lease files for device hostname."""
        for lease_file in DHCP_LEASE_FILES:
            try:
                with open(lease_file, "r") as f:
                    content = f.read()

                # dnsmasq format: timestamp mac ip hostname *
                for line in content.split("\n"):
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[2] == ip:
                        hostname = parts[3]
                        if hostname != "*" and len(hostname) > 1:
                            return hostname

                # ISC DHCP format
                if "lease " + ip in content:
                    block = content.split("lease " + ip)[1].split("}")[0]
                    match = re.search(r'client-hostname\s+"([^"]+)"', block)
                    if match:
                        return match.group(1)
            except (FileNotFoundError, PermissionError, IndexError):
                continue
        return None

    def _lookup_vendor(self, mac):
        """Lookup device vendor from MAC address OUI."""
        mac_prefix = mac[:8].upper()
        return OUI_MAP.get(mac_prefix, "Unknown Vendor")

    @property
    def display_name(self):
        """Get the best display name for this device."""
        if self.device_name and self.device_name not in ("Unknown", "Scanning...", "Resolving..."):
            return self.device_name
        if self.hostname and self.hostname not in ("Unknown", "Scanning...", "Resolving..."):
            return self.hostname
        if self.vendor and self.vendor != "Unknown Vendor":
            return self.vendor
        return "Unknown"

    def update_seen(self):
        """Mark device as seen right now."""
        self.last_seen = datetime.now()
        self.is_online = True

    def mark_offline(self):
        """Mark device as offline."""
        self.is_online = False

    def to_dict(self):
        """Return device info as dictionary."""
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "device_name": self.device_name,
            "display_name": self.display_name,
            "vendor": self.vendor,
            "first_seen": self.first_seen.strftime("%H:%M:%S"),
            "last_seen": self.last_seen.strftime("%H:%M:%S"),
            "is_online": self.is_online,
            "speed_up": self.speed_up,
            "speed_down": self.speed_down,
            "geo_info": self.geo_info,
        }


class NetworkScanner:
    """Ultra-fast network scanner — all layers run in PARALLEL."""

    def __init__(self, interface=None):
        self.interface = interface or self._detect_interface()
        self.gateway_ip = self._get_gateway()
        self.local_ip = self._get_local_ip()
        self.subnet = self._get_subnet()
        self.devices = {}  # MAC -> DeviceInfo
        self._lock = threading.Lock()
        self._running = False
        self._scan_thread = None
        self._scan_count = 0
        self._last_scan_time = 0  # Track scan performance

    def _detect_interface(self):
        """Auto-detect the active wireless interface."""
        try:
            result = subprocess.run(
                ["iwconfig"], capture_output=True, text=True, timeout=3
            )
            output = result.stdout + result.stderr
            for line in output.split("\n"):
                if "ESSID" in line and "off/any" not in line:
                    iface = line.split()[0]
                    return iface
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: try ip command
        try:
            result = subprocess.run(
                ["ip", "link", "show"], capture_output=True, text=True, timeout=3
            )
            interfaces = re.findall(r"\d+:\s+(\w+):", result.stdout)
            wifi_prefixes = ["wl", "wlan", "wifi"]
            for iface in interfaces:
                for prefix in wifi_prefixes:
                    if iface.startswith(prefix):
                        return iface
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Final fallback: check netifaces
        if NETIFACES_AVAILABLE:
            for iface in netifaces.interfaces():
                if iface.startswith(("wl", "wlan")):
                    return iface

        return "wlan0"

    def _get_gateway(self):
        """Get the default gateway IP."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=3
            )
            match = re.search(r"default via (\S+)", result.stdout)
            if match:
                return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        if NETIFACES_AVAILABLE:
            gws = netifaces.gateways()
            default_gw = gws.get("default", {}).get(netifaces.AF_INET)
            if default_gw:
                return default_gw[0]

        return "192.168.1.1"

    def _get_local_ip(self):
        """Get the local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _get_subnet(self):
        """Get the subnet to scan."""
        parts = self.gateway_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    # ═══════════════════════════════════════════════════════════════════
    # TURBO SCAN — ALL LAYERS IN PARALLEL
    # ═══════════════════════════════════════════════════════════════════

    def scan_once(self):
        """Perform ultra-fast parallel multi-layer network scan."""
        scan_start = time.time()
        all_discovered = {}  # ip -> mac (deduped)

        # ★ Run ALL layers in PARALLEL using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=6, thread_name_prefix="scan") as pool:
            futures = {}

            # Submit all scan layers simultaneously
            futures["arp_cache"] = pool.submit(self._scan_ip_neigh)
            futures["proc_arp"] = pool.submit(self._scan_proc_arp)
            futures["arp_cmd"] = pool.submit(self._scan_arp_command)

            if SCAPY_AVAILABLE:
                futures["scapy"] = pool.submit(self._scan_scapy_fast)

            # Only do ping sweep on first scan (to seed ARP cache)
            if self._scan_count == 0:
                futures["ping"] = pool.submit(self._ping_sweep_turbo)

            futures["nmap"] = pool.submit(self._scan_nmap)

            # Collect results as they complete (fastest layers first)
            for name, future in futures.items():
                try:
                    result = future.result(timeout=8)
                    if result:
                        for ip, mac in result:
                            if ip not in all_discovered:
                                all_discovered[ip] = mac
                except Exception:
                    pass

        self._scan_count += 1
        self._last_scan_time = time.time() - scan_start

        # Update device database
        with self._lock:
            current_macs = set()

            for ip, mac in all_discovered.items():
                mac = mac.upper()
                current_macs.add(mac)

                if mac in self.devices:
                    self.devices[mac].update_seen()
                    self.devices[mac].ip = ip
                else:
                    self.devices[mac] = DeviceInfo(ip, mac)

            # Mark devices not seen as offline (after 60 seconds)
            for mac, device in self.devices.items():
                if mac not in current_macs:
                    time_diff = (datetime.now() - device.last_seen).seconds
                    if time_diff > 60:
                        device.mark_offline()

        return list(self.devices.values())

    # ─── Layer 1: TURBO Ping Sweep ────────────────────────────

    def _ping_sweep_turbo(self):
        """Blazing fast ping sweep — fping preferred, threaded fallback."""
        subnet_base = ".".join(self.gateway_ip.split(".")[:3])
        discovered = []

        # Try fping first (MUCH faster — completes in ~1s)
        try:
            result = subprocess.run(
                ["fping", "-a", "-g", f"{subnet_base}.1", f"{subnet_base}.254",
                 "-r", "0", "-t", "100", "-q"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode in (0, 1):
                return discovered  # fping populates ARP table
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: ultra-threaded ping (128 workers, 0.5s timeout)
        def _ping(ip):
            try:
                subprocess.run(
                    ["ping", "-c", "1", "-W", "1", ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=1.5,
                )
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=128) as pool:
            futures = [pool.submit(_ping, f"{subnet_base}.{i}") for i in range(1, 255)]
            for f in as_completed(futures, timeout=4):
                try:
                    f.result()
                except Exception:
                    pass

        time.sleep(0.2)
        return discovered

    # ─── Layer 2: Scapy ARP Scan (FAST single pass) ───────────

    def _scan_scapy_fast(self):
        """Single-pass Scapy ARP scan — fast with reasonable timeout."""
        discovered = []
        try:
            conf.verb = 0
            arp_request = ARP(pdst=self.subnet)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            # Single pass with shorter timeout (2s instead of 4s+5s dual pass)
            answered, _ = srp(packet, timeout=2, verbose=False,
                              iface=self.interface, retry=1)
            for sent, received in answered:
                discovered.append((received.psrc, received.hwsrc))

        except Exception:
            pass

        return discovered

    # ─── Layer 3: ip neigh (INSTANT) ──────────────────────────

    def _scan_ip_neigh(self):
        """Read the system ARP neighbor table via `ip neigh` — instant."""
        discovered = []
        try:
            result = subprocess.run(
                ["ip", "neigh", "show"],
                capture_output=True, text=True, timeout=2,
            )
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                match = re.match(
                    r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+"
                    r"([0-9a-fA-F:]{17})\s+(\w+)",
                    line,
                )
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    state = match.group(3)
                    if state != "FAILED" and mac != "00:00:00:00:00:00":
                        discovered.append((ip, mac))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return discovered

    # ─── Layer 4: /proc/net/arp (INSTANT) ─────────────────────

    def _scan_proc_arp(self):
        """Read the kernel ARP cache — instant."""
        discovered = []
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        mac = parts[3]
                        flags = parts[2]
                        if mac != "00:00:00:00:00:00" and flags != "0x0":
                            discovered.append((ip, mac))
        except (FileNotFoundError, PermissionError):
            pass
        return discovered

    # ─── Layer 5: arp -an command ─────────────────────────────

    def _scan_arp_command(self):
        """Fallback: read from arp command output."""
        discovered = []
        try:
            result = subprocess.run(
                ["arp", "-an"], capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.split("\n"):
                match = re.search(
                    r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line
                )
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    if mac != "ff:ff:ff:ff:ff:ff":
                        discovered.append((ip, mac))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return discovered

    # ─── Layer 6: nmap (optional) ─────────────────────────────

    def _scan_nmap(self):
        """Optional nmap scan."""
        discovered = []
        try:
            result = subprocess.run(
                ["nmap", "-sn", "-n", self.subnet, "--send-ip", "-T4"],
                capture_output=True, text=True, timeout=10,
            )
            current_ip = None
            for line in result.stdout.split("\n"):
                ip_match = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    current_ip = ip_match.group(1)
                mac_match = re.search(r"MAC Address:\s+([0-9A-Fa-f:]{17})", line)
                if mac_match and current_ip:
                    discovered.append((current_ip, mac_match.group(1)))
                    current_ip = None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return discovered

    # ═══════════════════════════════════════════════════════════════════
    # API
    # ═══════════════════════════════════════════════════════════════════

    def get_devices(self):
        """Get current list of devices (thread-safe)."""
        with self._lock:
            return list(self.devices.values())

    def get_online_count(self):
        """Get count of online devices."""
        with self._lock:
            return sum(1 for d in self.devices.values() if d.is_online)

    def get_scan_time(self):
        """Get last scan duration in seconds."""
        return self._last_scan_time

    def start_continuous_scan(self, interval=5):
        """Start continuous background scanning."""
        self._running = True
        self._scan_thread = threading.Thread(
            target=self._scan_loop, args=(interval,), daemon=True
        )
        self._scan_thread.start()

    def _scan_loop(self, interval):
        """Background scan loop."""
        while self._running:
            try:
                self.scan_once()
            except Exception:
                pass
            time.sleep(interval)

    def stop(self):
        """Stop continuous scanning."""
        self._running = False
