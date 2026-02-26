"""
NetVision — Device Fingerprinting Module
Identifies device type, OS, browser, and model from User-Agent strings,
mDNS/SSDP broadcasts, DHCP hostnames, and TCP fingerprinting.
"""

import re
import threading
from collections import defaultdict
from datetime import datetime


class DeviceProfile:
    """Complete profile for a network device."""

    def __init__(self, ip, mac=""):
        self.ip = ip
        self.mac = mac
        self.os_name = "Unknown"
        self.os_version = ""
        self.device_type = "Unknown"     # Phone, Laptop, Tablet, Smart TV, IoT, etc.
        self.device_brand = ""           # Apple, Samsung, Google, etc.
        self.device_model = ""           # iPhone 15, Pixel 8, etc.
        self.browser = ""               # Chrome, Safari, Firefox
        self.browser_version = ""
        self.user_agents = set()
        self.hostnames = set()
        self.mdns_services = []
        self.open_ports = set()
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.is_mobile = False
        self.is_iot = False

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "os": f"{self.os_name} {self.os_version}".strip(),
            "device_type": self.device_type,
            "brand": self.device_brand,
            "model": self.device_model,
            "browser": f"{self.browser} {self.browser_version}".strip(),
            "is_mobile": self.is_mobile,
            "is_iot": self.is_iot,
            "hostnames": list(self.hostnames),
        }

    def summary(self):
        parts = []
        if self.device_brand:
            parts.append(self.device_brand)
        if self.device_model:
            parts.append(self.device_model)
        if not parts and self.device_type != "Unknown":
            parts.append(self.device_type)
        if self.os_name != "Unknown":
            parts.append(f"({self.os_name} {self.os_version})")
        if self.browser:
            parts.append(f"[{self.browser}]")
        return " ".join(parts) if parts else "Unknown Device"


class DeviceFingerprinter:
    """Fingerprints devices from captured network data."""

    def __init__(self):
        self._profiles = {}  # IP -> DeviceProfile
        self._lock = threading.Lock()

        # UA parsing patterns
        self._os_patterns = [
            # iOS
            (r"iPhone.*?OS\s+(\d+[_\.]\d+)", "iOS", "iPhone", "Apple"),
            (r"iPad.*?OS\s+(\d+[_\.]\d+)", "iPadOS", "iPad", "Apple"),
            # Android
            (r"Android\s+(\d+[\.\d]*)", "Android", None, None),
            # Windows
            (r"Windows NT 10\.0", "Windows", "10/11", None),
            (r"Windows NT 6\.3", "Windows", "8.1", None),
            (r"Windows NT 6\.1", "Windows", "7", None),
            # macOS
            (r"Macintosh.*?Mac OS X\s+(\d+[_\.]\d+[_\.\d]*)", "macOS", None, "Apple"),
            (r"Macintosh", "macOS", "", "Apple"),
            # Linux
            (r"Linux(?!.*Android)", "Linux", "", None),
            # Chrome OS
            (r"CrOS", "ChromeOS", "", "Google"),
        ]

        self._browser_patterns = [
            (r"Edg[e/](\d+[\.\d]*)", "Edge"),
            (r"OPR/(\d+[\.\d]*)", "Opera"),
            (r"Brave", "Brave"),
            (r"Vivaldi/(\d+[\.\d]*)", "Vivaldi"),
            (r"Firefox/(\d+[\.\d]*)", "Firefox"),
            (r"Chrome/(\d+[\.\d]*)", "Chrome"),
            (r"Safari/(\d+[\.\d]*)", "Safari"),
            (r"MSIE\s+(\d+)", "IE"),
        ]

        self._device_patterns = [
            # Samsung
            (r"SM-[SGNA]\d{3}", "Samsung", "Phone"),
            (r"SM-T\d{3}", "Samsung", "Tablet"),
            (r"Samsung", "Samsung", "Phone"),
            # OnePlus
            (r"(?:ONEPLUS|IN\d{4}|KB\d{4})", "OnePlus", "Phone"),
            # Xiaomi / Redmi / POCO
            (r"(?:Redmi|POCO|M\d{4}J\d+)", "Xiaomi", "Phone"),
            (r"Xiaomi", "Xiaomi", "Phone"),
            # Google Pixel
            (r"Pixel\s*(\d+)", "Google", "Phone"),
            # Oppo
            (r"(?:OPPO|CPH\d{4}|RMX\d{4})", "Oppo", "Phone"),
            # Vivo
            (r"(?:vivo|V\d{4})", "Vivo", "Phone"),
            # Realme
            (r"(?:realme|RMX\d{4})", "Realme", "Phone"),
            # Nothing
            (r"Nothing", "Nothing", "Phone"),
            # Huawei
            (r"(?:HUAWEI|Honor)", "Huawei", "Phone"),
            # Apple devices
            (r"iPhone", "Apple", "Phone"),
            (r"iPad", "Apple", "Tablet"),
            (r"Macintosh", "Apple", "Laptop"),
            # Smart TV
            (r"(?:SmartTV|SMART-TV|Tizen|WebOS|BRAVIA|LG Browser)", None, "Smart TV"),
            # Game consoles
            (r"(?:PlayStation|Xbox|Nintendo)", None, "Game Console"),
        ]

        # MAC vendor prefixes (first 3 bytes)
        self._mac_vendors = {
            "00:50:56": ("VMware", "Virtual Machine"),
            "DC:A6:32": ("Raspberry Pi", "IoT"),
            "B8:27:EB": ("Raspberry Pi", "IoT"),
            "AC:DE:48": ("Apple", None),
            "F8:4D:89": ("Apple", None),
            "3C:22:FB": ("Apple", None),
            "A4:83:E7": ("Apple", None),
            "14:7D:DA": ("Apple", None),
            "68:DB:F5": ("Amazon", "IoT"),
            "44:65:0D": ("Amazon", "IoT"),
            "FC:65:DE": ("Amazon", "IoT"),
            "30:FD:38": ("Google", None),
            "54:60:09": ("Google", None),
            "F4:F5:D8": ("Google", None),
        }

    def fingerprint_from_ua(self, ip, user_agent, mac=""):
        """Fingerprint a device from its User-Agent string."""
        with self._lock:
            if ip not in self._profiles:
                self._profiles[ip] = DeviceProfile(ip, mac)
            profile = self._profiles[ip]

            if mac:
                profile.mac = mac
            profile.last_seen = datetime.now()
            profile.user_agents.add(user_agent[:200])

            ua = user_agent

            # Detect OS
            for pattern, os_name, version_hint, brand in self._os_patterns:
                match = re.search(pattern, ua, re.IGNORECASE)
                if match:
                    profile.os_name = os_name
                    if match.lastindex and match.lastindex >= 1:
                        profile.os_version = match.group(1).replace("_", ".")
                    elif version_hint:
                        profile.os_version = version_hint
                    if brand:
                        profile.device_brand = brand
                    break

            # Detect browser
            for pattern, browser in self._browser_patterns:
                match = re.search(pattern, ua, re.IGNORECASE)
                if match:
                    profile.browser = browser
                    if match.lastindex and match.lastindex >= 1:
                        profile.browser_version = match.group(1).split(".")[0]
                    break

            # Detect device brand/type
            for pattern, brand, dev_type in self._device_patterns:
                if re.search(pattern, ua, re.IGNORECASE):
                    if brand:
                        profile.device_brand = brand
                    profile.device_type = dev_type
                    break

            # Mobile detection
            if re.search(r"Mobile|Android|iPhone|iPad", ua, re.IGNORECASE):
                profile.is_mobile = True
                if profile.device_type == "Unknown":
                    profile.device_type = "Phone"

            # Desktop detection
            if not profile.is_mobile and profile.os_name in ("Windows", "macOS", "Linux"):
                profile.device_type = "Laptop/Desktop"

            # Try to extract specific model
            model_match = re.search(r";\s*(SM-\w+|Pixel\s*\d+\w*|ONEPLUS\s*\w+|IN\d{4}|CPH\d{4}|RMX\d{4}|Redmi\s*\w+|POCO\s*\w+)", ua)
            if model_match:
                profile.device_model = model_match.group(1).strip()

            # MAC-based vendor lookup
            if mac and len(mac) >= 8:
                prefix = mac[:8].upper()
                if prefix in self._mac_vendors:
                    vendor, vtype = self._mac_vendors[prefix]
                    if not profile.device_brand:
                        profile.device_brand = vendor
                    if vtype == "IoT":
                        profile.is_iot = True
                        if profile.device_type == "Unknown":
                            profile.device_type = "IoT Device"

            return profile

    def fingerprint_from_hostname(self, ip, hostname, mac=""):
        """Fingerprint from DHCP/mDNS hostname."""
        with self._lock:
            if ip not in self._profiles:
                self._profiles[ip] = DeviceProfile(ip, mac)
            profile = self._profiles[ip]
            profile.hostnames.add(hostname)

            hn = hostname.lower()
            if "iphone" in hn:
                profile.device_brand = "Apple"
                profile.device_type = "Phone"
                profile.is_mobile = True
            elif "ipad" in hn:
                profile.device_brand = "Apple"
                profile.device_type = "Tablet"
                profile.is_mobile = True
            elif "macbook" in hn or "imac" in hn:
                profile.device_brand = "Apple"
                profile.device_type = "Laptop/Desktop"
            elif "android" in hn or "galaxy" in hn:
                profile.device_type = "Phone"
                profile.is_mobile = True
            elif "chromecast" in hn:
                profile.device_brand = "Google"
                profile.device_type = "Smart TV"
                profile.is_iot = True
            elif "alexa" in hn or "echo" in hn or "fire" in hn:
                profile.device_brand = "Amazon"
                profile.device_type = "IoT Device"
                profile.is_iot = True

            return profile

    def get_profile(self, ip):
        with self._lock:
            return self._profiles.get(ip)

    def get_all_profiles(self):
        with self._lock:
            return {ip: p.to_dict() for ip, p in self._profiles.items()}

    def get_summary(self, ip):
        with self._lock:
            p = self._profiles.get(ip)
            return p.summary() if p else "Unknown"
