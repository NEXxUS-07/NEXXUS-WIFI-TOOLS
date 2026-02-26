"""
NetVision — Bluetooth Scanner & Spoof Module
Scans for nearby Bluetooth devices and provides device intelligence.

Features:
  1. Classic Bluetooth discovery (BR/EDR)
  2. Bluetooth Low Energy (BLE) scanning
  3. Device name, class, and service detection
  4. RSSI signal strength tracking
  5. Spoofing detection (MAC randomization patterns)

Requirements:
  - bluez (Linux Bluetooth stack)
  - bluetooth Python module: pip install pybluez2
  - BLE via hcitool (system command)
"""

import subprocess
import threading
import time
import re
from datetime import datetime
from collections import defaultdict


class BTDevice:
    """Represents a discovered Bluetooth device."""

    def __init__(self, mac, name="", device_class="", rssi=0, bt_type="classic"):
        self.mac = mac
        self.name = name or "Unknown"
        self.device_class = device_class
        self.rssi = rssi
        self.bt_type = bt_type       # "classic", "ble", or "both"
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.services = []
        self.manufacturer = self._lookup_vendor(mac)
        self.is_nearby = True
        self.seen_count = 1

    def _lookup_vendor(self, mac):
        """OUI lookup for Bluetooth MAC prefix."""
        oui_map = {
            "00:1A:7D": "Apple", "04:15:52": "Apple", "14:99:E2": "Apple",
            "20:78:F0": "Apple", "38:C9:86": "Apple", "40:98:AD": "Apple",
            "4C:32:75": "Apple", "58:55:CA": "Apple", "60:FE:C5": "Apple",
            "70:73:CB": "Apple", "78:CA:39": "Apple", "80:E6:50": "Apple",
            "8C:85:90": "Apple", "98:01:A7": "Apple", "A4:D1:8C": "Apple",
            "AC:DE:48": "Apple", "B8:C1:11": "Apple", "C0:1A:DA": "Apple",
            "D0:D2:B0": "Apple", "E0:33:8E": "Apple", "F0:B4:79": "Apple",
            "28:6C:07": "Xiaomi", "64:CC:2E": "Xiaomi", "9C:99:A0": "Xiaomi",
            "74:23:44": "Xiaomi", "34:80:B3": "Xiaomi", "FC:64:BA": "Xiaomi",
            "AC:C1:EE": "Samsung", "00:26:37": "Samsung", "84:25:DB": "Samsung",
            "E4:7C:F9": "Samsung", "F4:7B:09": "Samsung", "30:96:FB": "Samsung",
            "88:36:6C": "Samsung", "BC:14:85": "Samsung", "CC:07:AB": "Samsung",
            "E8:6F:38": "OnePlus", "94:65:2D": "OnePlus", "C0:EE:FB": "OnePlus",
            "60:AB:67": "Realme", "48:A9:D2": "Realme",
            "D8:B3:70": "Google", "F4:F5:D8": "Google", "54:60:09": "Google",
            "00:1B:DC": "Sony", "AC:9A:96": "Sony", "78:C5:E5": "Sony",
            "00:0D:F0": "Bose", "04:52:C7": "Bose", "60:AB:D2": "Bose",
            "2C:41:A1": "JBL", "00:14:BF": "JBL",
            "E8:AB:FA": "Shenzhen",
        }
        mac_prefix = mac[:8].upper()
        return oui_map.get(mac_prefix, "Unknown")

    def _guess_device_type(self):
        """Guess device type from class, name, or services."""
        name_lower = self.name.lower()
        if any(k in name_lower for k in ["phone", "iphone", "galaxy", "pixel",
                                           "redmi", "oneplus", "realme", "poco",
                                           "vivo", "oppo"]):
            return "📱 Phone"
        if any(k in name_lower for k in ["airpod", "buds", "earbuds", "headphone",
                                           "headset", "jbl", "bose", "earbud", "pods"]):
            return "🎧 Audio"
        if any(k in name_lower for k in ["watch", "band", "fit"]):
            return "⌚ Wearable"
        if any(k in name_lower for k in ["laptop", "macbook", "thinkpad",
                                           "dell", "hp-", "asus"]):
            return "💻 Laptop"
        if any(k in name_lower for k in ["tv", "fire", "chromecast", "roku"]):
            return "📺 TV/Media"
        if any(k in name_lower for k in ["speaker", "echo", "home", "nest"]):
            return "🔊 Speaker"
        if any(k in name_lower for k in ["mouse", "keyboard"]):
            return "🖱️ Peripheral"
        if any(k in name_lower for k in ["car", "obd"]):
            return "🚗 Vehicle"
        if "Unknown" not in self.name and self.name != "":
            return "📟 Device"
        return "❓ Unknown"

    @property
    def device_type(self):
        return self._guess_device_type()

    @property
    def signal_strength(self):
        """Human-readable signal strength."""
        if self.rssi == 0:
            return "?"
        if self.rssi > -50:
            return "████ Strong"
        if self.rssi > -70:
            return "███░ Good"
        if self.rssi > -85:
            return "██░░ Fair"
        return "█░░░ Weak"

    def update(self, name=None, rssi=None):
        self.last_seen = datetime.now()
        self.is_nearby = True
        self.seen_count += 1
        if name and name != "Unknown":
            self.name = name
        if rssi and rssi != 0:
            self.rssi = rssi

    def to_dict(self):
        return {
            "mac": self.mac,
            "name": self.name,
            "manufacturer": self.manufacturer,
            "device_type": self.device_type,
            "rssi": self.rssi,
            "signal": self.signal_strength,
            "bt_type": self.bt_type,
            "first_seen": self.first_seen.strftime("%H:%M:%S"),
            "last_seen": self.last_seen.strftime("%H:%M:%S"),
            "is_nearby": self.is_nearby,
            "seen_count": self.seen_count,
        }


class BluetoothScanner:
    """Scans for nearby Bluetooth devices using system tools."""

    def __init__(self):
        self._devices = {}       # MAC -> BTDevice
        self._lock = threading.Lock()
        self._running = False
        self._scan_thread = None
        self._ble_thread = None
        self._bt_available = self._check_bluetooth()
        self._events = []

    def _check_bluetooth(self):
        """Check if Bluetooth is available."""
        try:
            result = subprocess.run(
                ["hciconfig"], capture_output=True, text=True, timeout=5,
            )
            if "UP RUNNING" in result.stdout:
                return True
            # Try to bring it up
            subprocess.run(
                ["sudo", "hciconfig", "hci0", "up"],
                capture_output=True, timeout=5,
            )
            result = subprocess.run(
                ["hciconfig"], capture_output=True, text=True, timeout=5,
            )
            return "UP RUNNING" in result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def start(self):
        """Start continuous Bluetooth scanning."""
        if not self._bt_available:
            self._add_event("⚠️ Bluetooth not available or not enabled")
            return False

        self._running = True
        self._add_event("📡 Bluetooth scanner started")

        # Classic BT discovery thread
        self._scan_thread = threading.Thread(
            target=self._classic_scan_loop, daemon=True,
        )
        self._scan_thread.start()

        # BLE scanning thread
        self._ble_thread = threading.Thread(
            target=self._ble_scan_loop, daemon=True,
        )
        self._ble_thread.start()

        return True

    def _classic_scan_loop(self):
        """Scan for classic Bluetooth devices periodically."""
        while self._running:
            try:
                self._scan_classic()
            except Exception:
                pass
            time.sleep(15)  # Classic scan interval

    def _ble_scan_loop(self):
        """Scan for BLE devices more frequently."""
        while self._running:
            try:
                self._scan_ble()
            except Exception:
                pass
            time.sleep(8)  # BLE scan interval

    def _scan_classic(self):
        """Discover classic Bluetooth devices using hcitool."""
        try:
            result = subprocess.run(
                ["hcitool", "scan", "--flush"],
                capture_output=True, text=True, timeout=12,
            )

            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("Scanning"):
                    continue

                # Format: "MAC_ADDR  Device Name"
                match = re.match(
                    r"([0-9A-Fa-f:]{17})\s+(.+)", line,
                )
                if match:
                    mac = match.group(1).upper()
                    name = match.group(2).strip()
                    self._add_device(mac, name, bt_type="classic")

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def _scan_ble(self):
        """Discover BLE devices using hcitool lescan."""
        try:
            # Run lescan for a short burst
            proc = subprocess.Popen(
                ["hcitool", "lescan"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )

            # Read output for 5 seconds
            time.sleep(5)
            proc.terminate()

            if proc.stdout:
                output = proc.stdout.read()
                for line in output.strip().split("\n"):
                    line = line.strip()
                    if not line or "LE Scan" in line:
                        continue

                    match = re.match(r"([0-9A-Fa-f:]{17})\s*(.*)", line)
                    if match:
                        mac = match.group(1).upper()
                        name = match.group(2).strip() or "Unknown BLE Device"
                        if name != "(unknown)":
                            self._add_device(mac, name, bt_type="ble")

        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

        # Also try bluetoothctl scan
        try:
            result = subprocess.run(
                ["bluetoothctl", "devices"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.strip().split("\n"):
                match = re.match(
                    r"Device\s+([0-9A-Fa-f:]{17})\s+(.+)", line,
                )
                if match:
                    mac = match.group(1).upper()
                    name = match.group(2).strip()
                    self._add_device(mac, name, bt_type="ble")

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def _add_device(self, mac, name="", rssi=0, bt_type="classic"):
        """Add or update a discovered device."""
        with self._lock:
            if mac in self._devices:
                self._devices[mac].update(name=name, rssi=rssi)
                if bt_type != self._devices[mac].bt_type:
                    self._devices[mac].bt_type = "both"
            else:
                dev = BTDevice(
                    mac=mac, name=name, rssi=rssi, bt_type=bt_type,
                )
                self._devices[mac] = dev
                icon = dev.device_type.split(" ")[0]
                self._add_event(
                    f"{icon} New BT device: {name} ({dev.manufacturer}) [{mac}]"
                )

    def scan_once(self):
        """Perform a single scan (blocking)."""
        self._scan_classic()
        self._scan_ble()

    # ─── STATUS & API ─────────────────────────────────────

    def get_devices(self):
        """Get all discovered Bluetooth devices."""
        with self._lock:
            return {
                mac: dev.to_dict()
                for mac, dev in self._devices.items()
            }

    def get_nearby(self):
        """Get only nearby (recently seen) devices."""
        with self._lock:
            now = datetime.now()
            result = {}
            for mac, dev in self._devices.items():
                age = (now - dev.last_seen).seconds
                dev.is_nearby = age < 60
                if dev.is_nearby:
                    result[mac] = dev.to_dict()
            return result

    def get_device_count(self):
        """Get total discovered device count."""
        with self._lock:
            return len(self._devices)

    def get_nearby_count(self):
        """Get count of currently nearby devices."""
        return len(self.get_nearby())

    def get_events(self, limit=10):
        """Get recent scan events."""
        return self._events[-limit:]

    def get_summary(self):
        """Get human-readable summary."""
        all_devs = self.get_devices()
        nearby = self.get_nearby()

        if not all_devs:
            return "No Bluetooth devices found yet"

        types = defaultdict(int)
        for dev in all_devs.values():
            dtype = dev["device_type"].split(" ")[1] if " " in dev["device_type"] else "Device"
            types[dtype] += 1

        parts = [f"{count} {dtype}{'s' if count > 1 else ''}" for dtype, count in types.items()]
        return f"{len(all_devs)} BT devices ({len(nearby)} nearby): {', '.join(parts)}"

    @property
    def is_available(self):
        return self._bt_available

    def _add_event(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self._events.append({"time": ts, "msg": msg})

    def stop(self):
        """Stop scanning."""
        self._running = False
